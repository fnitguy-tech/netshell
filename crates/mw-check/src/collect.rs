//! State collection over SSH: every device in parallel (five at a time)
//! with a progress bar, one capture file per device, zipped per run.
//! An unreachable device gets a `<host>_FAILED.txt` marker instead of
//! aborting the run.
//!
//! Port of the Python `collect.py`. netmiko is replaced by netshell
//! behind the [`Connector`] / [`Session`] traits, so `mw demo`
//! and the tests can replay captures instead of opening SSH sessions.
//! During a maintenance window an unreachable device is itself a
//! finding, not a reason to abort evidence collection.
//!
//! Output files use `### <command> ###` section headers with a dash
//! rule under each (see [`crate::capture`]); the compare modules parse
//! that two-line marker to diff command by command.
//!
//! The run is honest about how it went. [`run_collection`] returns a
//! [`RunResult`] that knows how many devices were captured, which
//! failed and why, the one-line summary to print, and the exit code to
//! leave with.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressStyle};
use netshell::{ConnectOptions, Platform, Secret};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::capture::{self, RunCounts, SECTION_RULE, section_header};
use crate::hostkeys::{self, HostKeys};
use crate::inventory::{DeviceSpec, Job};
use crate::layout::safe_name;
use crate::redact;

/// How many devices are collected at once.
pub const MAX_WORKERS: usize = 5;

/// Seconds to wait for one command; `show ip bgp` on a full table is slow.
pub const COMMAND_READ_TIMEOUT_SECS: u64 = 180;

/// Exit codes for `mw before` and `mw after`. Three values, so a
/// wrapper script can tell "look at one device" from "nothing worked".
pub const EXIT_OK: u8 = 0; // every device fully captured
pub const EXIT_SOME_FAILED: u8 = 1; // at least one device failed, was cut short, or wasn't tried
pub const EXIT_ALL_FAILED: u8 = 2; // no device was captured at all

/// How to ask each platform for its own hostname, so output files are
/// named after the device and not its management IP:
/// `(device_type, command, line prefix)`. Unknown platforms fall back
/// to the IP.
pub const HOSTNAME_LOOKUPS: &[(&str, &str, &str)] = &[
    ("arista_eos", "show hostname", "Hostname:"),
    ("paloalto_panos", "show system info | match hostname", "hostname:"),
];

/// The `(command, prefix)` lookup for a platform, if it has one.
pub fn hostname_lookup(device_type: &str) -> Option<(&'static str, &'static str)> {
    HOSTNAME_LOOKUPS
        .iter()
        .find(|(name, _, _)| *name == device_type)
        .map(|(_, command, prefix)| (*command, *prefix))
}

/// How one device's capture went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Every command ran.
    Captured,
    /// Connected, but a command timed out and the rest were skipped.
    Incomplete,
    /// Couldn't connect, or the capture broke.
    Failed,
    /// Never tried, because another device rejected the password.
    Skipped,
}

/// One device's result: who, how it went, and where the file is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceOutcome {
    pub host: String,
    pub status: Status,
    /// The device's own hostname, or `""` when it never answered.
    pub name: String,
    /// A few plain words for the summary line: `unreachable`,
    /// `authentication failed`, `timeout on show ip bgp`.
    pub reason: String,
    /// The capture, or the `_FAILED.txt` written in its place.
    pub file_path: Option<PathBuf>,
}

impl DeviceOutcome {
    /// The hostname when known, else the address.
    pub fn label(&self) -> &str {
        if self.name.is_empty() { &self.host } else { &self.name }
    }
}

/// What one `mw before` or `mw after` run produced, and how it went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResult {
    pub folder: PathBuf,
    pub zip: PathBuf,
    /// Sorted by label.
    pub outcomes: Vec<DeviceOutcome>,
}

impl RunResult {
    fn with(&self, status: Status) -> Vec<&DeviceOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.status == status)
            .collect()
    }

    /// The totals written to the completion marker.
    pub fn counts(&self) -> RunCounts {
        RunCounts {
            devices: self.outcomes.len(),
            captured: self.with(Status::Captured).len(),
            incomplete: self.with(Status::Incomplete).len(),
            failed: self.with(Status::Failed).len(),
            not_attempted: self.with(Status::Skipped).len(),
        }
    }

    pub fn ok(&self) -> bool {
        self.exit_code() == EXIT_OK
    }

    /// 0 when every device was captured, 1 when some weren't, 2 when
    /// none were. A device cut short by a timeout still left a usable
    /// file, so a run with only those exits 1, not 2.
    pub fn exit_code(&self) -> u8 {
        let counts = self.counts();

        if counts.captured == counts.devices {
            EXIT_OK
        } else if counts.captured + counts.incomplete > 0 {
            EXIT_SOME_FAILED
        } else {
            EXIT_ALL_FAILED
        }
    }

    /// The whole run in one line.
    ///
    /// ```text
    /// 8 of 8 captured.
    /// 7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
    /// 1 of 8 captured; 1 failed: 10.0.0.5 (authentication failed); 6 not attempted
    /// 7 of 8 captured; 1 incomplete: SITE-A-SW-1 (timeout on show ip bgp)
    /// ```
    pub fn summary_line(&self) -> String {
        let mut parts = vec![format!(
            "{} of {} captured",
            self.with(Status::Captured).len(),
            self.outcomes.len()
        )];

        for (status, word) in [(Status::Failed, "failed"), (Status::Incomplete, "incomplete")] {
            let found = self.with(status);

            if !found.is_empty() {
                let listed: Vec<String> = found
                    .iter()
                    .map(|outcome| format!("{} ({})", outcome.label(), outcome.reason))
                    .collect();
                parts.push(format!("{} {word}: {}", found.len(), listed.join(", ")));
            }
        }

        let skipped = self.with(Status::Skipped).len();
        if skipped > 0 {
            parts.push(format!("{skipped} not attempted"));
        }

        let end = if parts.len() == 1 { "." } else { "" };
        format!("{}{end}", parts.join("; "))
    }
}

/// An open session on one device. The real one wraps netshell; the
/// demo replays bundled captures.
pub trait Session: Send {
    /// The device's own hostname, so capture files are named after it
    /// and not its management IP.
    fn hostname(&mut self) -> anyhow::Result<String>;
    fn send_command(&mut self, command: &str) -> anyhow::Result<String>;
    fn disconnect(self: Box<Self>) -> anyhow::Result<()>;

    /// True once a read has timed out and the device may still be
    /// sending an old answer. Nothing more is sent on such a session.
    fn is_poisoned(&self) -> bool {
        false
    }
}

/// Opens sessions. Swapped for a replaying stub by `mw demo`.
///
/// Return a [`netshell::Error`] (wrapped by `?`) for a failed connect.
/// The collector reads its variant: `AuthFailed` stops the run, and
/// `HostKeyChanged` gets the changed-key message.
pub trait Connector: Sync {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>>;
}

/// Where a run reports to. The terminal bar is one; tests use another
/// to count how far the bar moved and read what was logged.
pub trait Progress: Sync {
    /// A line above the bar.
    fn log(&self, message: &str);
    /// The device now being worked on.
    fn set_message(&self, message: &str);
    /// Move the bar by this many commands.
    fn advance(&self, amount: u64);
}

/// Ask the device for its hostname with the platform's lookup command
/// and parse the answer; `fallback` (the management IP) when the
/// platform has no lookup or the answer has no hostname line.
pub fn get_hostname<S: Session + ?Sized>(session: &mut S, device_type: &str, fallback: &str) -> anyhow::Result<String> {
    let Some((command, prefix)) = hostname_lookup(device_type) else {
        return Ok(fallback.to_string());
    };

    let output = session.send_command(command)?;

    Ok(parse_hostname(&output, prefix).unwrap_or_else(|| fallback.to_string()))
}

/// The value after the first line starting with `prefix` (`Hostname:`).
pub fn parse_hostname(output: &str, prefix: &str) -> Option<String> {
    output
        .lines()
        .find(|line| line.trim().starts_with(prefix))
        .map(|line| line.split_once(':').map_or("", |(_, rest)| rest).trim().to_string())
}

/// The real connector: netshell over SSH.
///
/// Host keys are checked against a known-hosts file unless you opt out
/// on purpose with [`HostKeys::AcceptAny`].
#[derive(Clone, Debug)]
pub struct SshConnector {
    pub host_keys: HostKeys,
    /// Also offer the old SSH algorithms (`--legacy-algorithms`).
    pub legacy_algorithms: bool,
    /// The secret for `enable` (`--enable`). netshell ignores it on
    /// platforms with no enable mode, so one secret for the whole
    /// inventory is fine.
    pub enable_secret: Option<Secret>,
    /// Stay in user mode when a login lands at `>` (`--user-mode`).
    pub allow_user_mode: bool,
}

impl SshConnector {
    /// Host keys checked against `host_keys`, modern algorithms only,
    /// no enable secret.
    pub fn new(host_keys: HostKeys) -> SshConnector {
        SshConnector {
            host_keys,
            legacy_algorithms: false,
            enable_secret: None,
            allow_user_mode: false,
        }
    }

    /// The netshell options for one device.
    ///
    /// Returns `anyhow::Result` on purpose. `netshell::Error` is over
    /// clippy's large-error limit on Windows, and the only caller wants an
    /// `anyhow::Error` anyway. The netshell error is still inside it, so
    /// callers can downcast to tell an unknown platform from the rest.
    pub fn options_for(&self, device: &DeviceSpec) -> anyhow::Result<ConnectOptions> {
        let platform = Platform::by_name(&device.device_type)?;
        let mut options = ConnectOptions::new(&device.host, &device.username, device.password.clone(), platform)
            .read_timeout(Duration::from_secs(COMMAND_READ_TIMEOUT_SECS))
            .host_key(self.host_keys.policy_for(&device.host))
            .legacy_algorithms(self.legacy_algorithms)
            .allow_user_mode(self.allow_user_mode);

        if let Some(path) = self.host_keys.path() {
            options = options.known_hosts(path);
        }

        if let Some(secret) = &self.enable_secret {
            options = options.enable_secret(secret.clone());
        }

        Ok(options)
    }
}

impl Connector for SshConnector {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        let connection = netshell::blocking::Device::connect(self.options_for(device)?)?;

        Ok(Box::new(SshSession {
            connection,
            device_type: device.device_type.clone(),
            host: device.host.clone(),
        }))
    }
}

struct SshSession {
    connection: netshell::blocking::Device,
    device_type: String,
    host: String,
}

impl Session for SshSession {
    fn hostname(&mut self) -> anyhow::Result<String> {
        let (device_type, host) = (self.device_type.clone(), self.host.clone());
        get_hostname(self, &device_type, &host)
    }

    fn send_command(&mut self, command: &str) -> anyhow::Result<String> {
        Ok(self.connection.send_command(command)?)
    }

    fn disconnect(self: Box<Self>) -> anyhow::Result<()> {
        let session = *self;
        session.connection.disconnect()?;
        Ok(())
    }

    fn is_poisoned(&self) -> bool {
        self.connection.is_poisoned()
    }
}

/// The lines before the first section header, as written to a capture:
/// hostname, management IP, when it was taken, whether secrets were
/// stripped, and a rule of 80 `=`.
pub fn capture_header(hostname: &str, ip: &str, generated: &str, redacted: bool) -> String {
    let mut header = format!("Hostname: {hostname}\nIP Address: {ip}\nGenerated: {generated}\n");
    if redacted {
        header.push_str("Secrets: redacted\n");
    }
    header.push_str(&"=".repeat(80));
    header.push('\n');
    header
}

/// One command's section, as written to a capture: two blank lines,
/// the `### command ###` header, a rule of 80 `-`, the output, newline.
pub fn capture_section(command: &str, output: &str) -> String {
    format!("\n\n{}\n{SECTION_RULE}\n{output}\n", section_header(command))
}

/// The `Generated:` timestamp, in the shape of Python's
/// `str(datetime.now())`: `2026-04-14 08:48:02.123456`.
pub fn generated_timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

/// Python's `str.capitalize()`: "precheck" -> "Precheck".
pub fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars.flat_map(char::to_lowercase)).collect(),
        None => String::new(),
    }
}

/// The terminal progress bar.
struct BarProgress(ProgressBar);

impl Progress for BarProgress {
    /// Timestamped like the Python's `console.log`. Printed even when
    /// the bar is hidden (stdout is not a terminal), which
    /// `ProgressBar::println` is not.
    fn log(&self, message: &str) {
        let stamp = chrono::Local::now().format("%H:%M:%S");
        self.0.suspend(|| println!("[{stamp}] {message}"));
    }

    fn set_message(&self, message: &str) {
        self.0.set_message(message.to_string());
    }

    fn advance(&self, amount: u64) {
        self.0.inc(amount);
    }
}

/// A lock that's still usable after another worker panicked.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The netshell error behind a failure, if that's what it is.
fn netshell_error(error: &anyhow::Error) -> Option<&netshell::Error> {
    error.chain().find_map(|cause| cause.downcast_ref::<netshell::Error>())
}

fn is_auth_failure(error: &anyhow::Error) -> bool {
    matches!(netshell_error(error), Some(netshell::Error::AuthFailed { .. }))
}

/// A read or write gave up waiting, so the device may still be sending
/// the old answer.
fn is_timeout(error: &anyhow::Error) -> bool {
    matches!(
        netshell_error(error),
        Some(
            netshell::Error::ReadTimeout { .. }
                | netshell::Error::WriteTimeout { .. }
                | netshell::Error::SessionPoisoned { .. }
        )
    )
}

/// A few plain words for the summary line; the full error goes in the file.
fn failure_reason(error: &anyhow::Error) -> &'static str {
    use netshell::Error;

    match netshell_error(error) {
        Some(Error::AuthFailed { .. }) => "authentication failed",
        Some(Error::HostKeyChanged { .. }) => "host key changed",
        Some(Error::Connect { source, .. }) if source.to_string().contains("lookup address") => "name not found",
        Some(Error::Connect { .. } | Error::ConnectTimeout { .. }) => "unreachable",
        Some(Error::EnableRequired { .. }) => "enable secret needed",
        Some(Error::EnableFailed { .. }) => "enable secret rejected",
        Some(Error::UnknownPlatform(_)) => "unknown platform",
        Some(
            Error::SetupTimeout { .. }
            | Error::NoCommonAlgorithm { .. }
            | Error::KeyboardInteractiveRefused { .. }
            | Error::HostKeyMismatch { .. }
            | Error::KnownHosts { .. }
            | Error::Session { .. }
            | Error::Ssh(_),
        ) => "SSH connection failed",
        _ => "capture failed",
    }
}

/// The error text for the `_FAILED.txt` file and the console. A changed
/// host key gets mw's own message, which names the mw flag that fixes it.
fn failure_text(error: &anyhow::Error) -> String {
    match netshell_error(error) {
        Some(netshell::Error::HostKeyChanged {
            host,
            stored,
            offered,
            file,
            line,
            ..
        }) => hostkeys::changed_key_message(host, stored, offered, file, *line),
        _ => format!("{error:#}"),
    }
}

/// Error text with the login password blanked out, in case a library
/// ever echoes it back. Very short passwords are left alone: blanking
/// every "a" would wreck the message and hide nothing.
fn hide_password(text: &str, device: &DeviceSpec) -> String {
    let password = device.password.expose();

    if password.chars().count() >= 4 {
        text.replace(password, "<hidden>")
    } else {
        text.to_string()
    }
}

/// What a connect attempt came to.
enum Connected {
    Session(Box<dyn Session>),
    /// Not tried: this device already rejected the password.
    NotAttempted(String),
    Failed(anyhow::Error),
}

/// Stops a mistyped password from being tried on every device.
///
/// Most networks check logins against one central server, and that
/// server locks an account after a few bad tries. Five devices at a
/// time, a typo would use up those tries in the first second.
///
/// So the first connections go one at a time. As soon as one device
/// accepts the password, it's known to be right and the rest connect in
/// parallel. The first device that rejects it ends the run for every
/// device that hasn't started yet: at most one bad try with an unproven
/// password. Once it's proven, connections overlap, so a rejection can
/// still be followed by the few that were already in flight.
#[derive(Default)]
struct CredentialGate {
    turn: Mutex<()>,
    proven: AtomicBool,
    rejected_by: Mutex<Option<String>>,
}

impl CredentialGate {
    fn connect(&self, device: &DeviceSpec, connector: &dyn Connector) -> Connected {
        if !self.proven.load(Ordering::SeqCst) {
            let _turn = lock(&self.turn);

            // Checked again: the password may have been proven while
            // this connection waited its turn.
            if !self.proven.load(Ordering::SeqCst) {
                let outcome = self.attempt(device, connector);

                if matches!(outcome, Connected::Session(_)) {
                    self.proven.store(true, Ordering::SeqCst);
                }

                return outcome;
            }
        }

        self.attempt(device, connector)
    }

    fn attempt(&self, device: &DeviceSpec, connector: &dyn Connector) -> Connected {
        if let Some(rejected_by) = lock(&self.rejected_by).clone() {
            return Connected::NotAttempted(rejected_by);
        }

        match connector.connect(device) {
            Ok(session) => Connected::Session(session),
            Err(error) => {
                if is_auth_failure(&error) {
                    lock(&self.rejected_by).get_or_insert_with(|| device.host.clone());
                }

                Connected::Failed(error)
            }
        }
    }
}

/// What the worker threads share for one run.
struct Run<'a> {
    folder: &'a Path,
    progress: &'a dyn Progress,
    redact_secrets: bool,
    connector: &'a dyn Connector,
    /// One gate per credential, so a rejected password only stops the
    /// devices that would have been sent the same one.
    gates: Mutex<Vec<(String, Secret, Arc<CredentialGate>)>>,
    /// Capture paths handed out so far, by lower-cased file stem.
    claims: Mutex<IndexMap<String, Vec<(String, PathBuf)>>>,
}

impl Run<'_> {
    fn log(&self, message: impl AsRef<str>) {
        self.progress.log(message.as_ref());
    }

    /// Scrub output before it is written so no password, hash, or key
    /// ever reaches disk; off by default because it hides a rotated
    /// password from the diff (see redact.rs).
    fn clean(&self, text: &str) -> String {
        if self.redact_secrets {
            redact::scrub(text)
        } else {
            text.to_string()
        }
    }

    fn connect(&self, device: &DeviceSpec) -> Connected {
        let gate = {
            let mut gates = lock(&self.gates);
            let found = gates
                .iter()
                .find(|(username, password, _)| {
                    *username == device.username && password.expose() == device.password.expose()
                })
                .map(|(_, _, gate)| Arc::clone(gate));

            found.unwrap_or_else(|| {
                let gate = Arc::new(CredentialGate::default());
                gates.push((device.username.clone(), device.password.clone(), Arc::clone(&gate)));
                gate
            })
        };

        gate.connect(device, self.connector)
    }

    /// Pick the capture file path for a device; never one already taken.
    ///
    /// The name comes from the device, so it's cleaned first. Two
    /// devices can also report the same name (two lab boxes both called
    /// "localhost"). The second one to arrive gets the host added:
    /// `localhost_192.0.2.2.txt`. [`Run::settle_names`] then renames
    /// the first to match, so neither depends on which connected first.
    fn claim_file(&self, hostname: &str, host: &str) -> PathBuf {
        let stem = safe_name(hostname, host);
        let mut claims = lock(&self.claims);

        let mut path = self.folder.join(format!("{stem}.txt"));
        let taken = claims.values().flatten().any(|(_, claimed)| *claimed == path);
        let shared = claims.get(&stem.to_lowercase()).is_some_and(|list| !list.is_empty());

        if shared || taken {
            path = self.folder.join(format!("{stem}_{}.txt", safe_name(host, "device")));
        }

        claims
            .entry(stem.to_lowercase())
            .or_default()
            .push((host.to_string(), path.clone()));

        path
    }

    /// After the last device: give every device that shared a name the
    /// same `<name>_<host>.txt` form.
    fn settle_names(&self, outcomes: &mut [DeviceOutcome]) {
        for claimed in lock(&self.claims).values() {
            if claimed.len() < 2 {
                continue;
            }

            let (host, path) = &claimed[0];
            let Some(stem) = path.file_stem().map(|stem| stem.to_string_lossy().into_owned()) else {
                continue;
            };
            let new_path = self.folder.join(format!("{stem}_{}.txt", safe_name(host, "device")));

            if path.exists() && !new_path.exists() && fs::rename(path, &new_path).is_ok() {
                for outcome in outcomes.iter_mut() {
                    if outcome.file_path.as_deref() == Some(path.as_path()) {
                        outcome.file_path = Some(new_path.clone());
                    }
                }
            }
        }
    }
}

/// Run every command and write the capture file.
///
/// `done` counts each command as its section is written, so the caller
/// knows how far the progress bar has moved even if this fails.
/// Returns the command that cut the capture short and why (`timeout`
/// or `error`), or `None` when every command ran.
///
/// If a command times out, the rest are skipped, not run. A timeout
/// means mw stopped waiting; the device didn't stop answering. The late
/// output is still on its way down the same connection, and the next
/// command would read it as its own answer. Every answer after that
/// would be filed under the wrong command. netshell refuses to send on
/// such a session for the same reason.
///
/// Reconnecting would fix that, but it also resets the session. PAN-OS
/// needs `set cli config-output-format set` to hold for the whole
/// capture, so a fresh session would print the config in another format
/// and the diff would light up from top to bottom. Skipping is the safe
/// choice. The capture says so in plain words:
///
/// ```text
/// ### show running-config ###
/// --------------------------------------------------------------------------------
/// SKIPPED after timeout on show ip bgp
/// ```
fn capture_commands(
    session: &mut dyn Session,
    job: &Job,
    hostname: &str,
    file_path: &Path,
    run: &Run,
    done: &mut usize,
) -> io::Result<Option<(String, &'static str)>> {
    let device = &job.device;
    let mut stopped: Option<(String, &'static str)> = None;
    let mut file = BufWriter::new(File::create(file_path)?);

    let generated = generated_timestamp();
    file.write_all(capture_header(hostname, &device.host, &generated, run.redact_secrets).as_bytes())?;

    for command in &job.commands {
        run.progress.set_message(hostname);

        let output = match &stopped {
            Some((stopped_on, why)) => format!("SKIPPED after {why} on {stopped_on}"),
            None => match session.send_command(command) {
                Ok(output) => output,
                Err(error) => {
                    let why = if is_timeout(&error) || session.is_poisoned() {
                        "timeout"
                    } else {
                        "error"
                    };
                    run.log(format!(
                        "{hostname}: {why} on '{command}'. Skipping the rest of its commands."
                    ));
                    stopped = Some((command.clone(), why));
                    format!("COMMAND FAILED:\n{}", hide_password(&format!("{error:#}"), device))
                }
            },
        };

        file.write_all(capture_section(command, &run.clean(&output)).as_bytes())?;

        run.progress.advance(1);
        *done += 1;
    }

    file.flush()?;

    Ok(stopped)
}

/// Capture one device and return its [`DeviceOutcome`].
///
/// Connect, capture every command into `<folder>/<hostname>.txt`, and
/// on any failure write `<folder>/<host>_FAILED.txt` instead. Only an
/// error writing that marker is returned.
fn collect_device(job: &Job, run: &Run) -> anyhow::Result<DeviceOutcome> {
    let device = &job.device;
    let host = device.host.as_str();
    let mut done = 0usize;
    let mut hostname = String::new();
    let mut file_path: Option<PathBuf> = None;
    let mut session: Option<Box<dyn Session>> = None;

    run.log(format!("Connecting to {host}..."));

    let attempt: Result<Option<(String, &'static str)>, anyhow::Error> = match run.connect(device) {
        Connected::NotAttempted(rejected_by) => {
            run.log(format!("NOT ATTEMPTED: {host}"));
            let reason = format!("{rejected_by} rejected the username or password");
            let failed_file = capture::write_failed(
                run.folder,
                host,
                capture::NOT_ATTEMPTED_FIRST_LINE,
                &format!("Not tried, because {reason}. Trying it on more devices could lock the account.\n"),
            )
            .with_context(|| format!("could not write the NOT ATTEMPTED file for {host}"))?;

            run.progress.advance(job.commands.len() as u64);

            return Ok(DeviceOutcome {
                host: host.to_string(),
                status: Status::Skipped,
                name: String::new(),
                reason,
                file_path: Some(failed_file),
            });
        }
        Connected::Failed(error) => Err(error),
        Connected::Session(opened) => {
            let opened = session.insert(opened);

            opened.hostname().and_then(|name| {
                hostname = name;
                run.log(format!("Connected to {hostname}"));

                let path = run.claim_file(&hostname, host);
                file_path = Some(path.clone());

                capture_commands(opened.as_mut(), job, &hostname, &path, run, &mut done)
                    .map_err(|error| anyhow::anyhow!("could not write {}: {error}", path.display()))
            })
        }
    };

    let outcome = match attempt {
        Ok(stopped) => DeviceOutcome {
            host: host.to_string(),
            status: if stopped.is_some() {
                Status::Incomplete
            } else {
                Status::Captured
            },
            name: hostname.clone(),
            reason: stopped
                .map(|(stopped_on, why)| format!("{why} on {stopped_on}"))
                .unwrap_or_default(),
            file_path: file_path.clone(),
        },
        Err(error) => {
            let text = hide_password(&failure_text(&error), device);

            run.log(format!("FAILED: {host}"));
            run.log(&text);

            if is_auth_failure(&error) {
                run.log(format!(
                    "{host} rejected the username or password. No more devices will be tried, \
                     so a mistyped password can't lock the account."
                ));
            }

            // A capture that broke partway isn't evidence. Left in
            // place, the compare would read the half file as the
            // device's whole state.
            if let Some(path) = &file_path
                && path.exists()
            {
                let _ = fs::remove_file(path);
            }

            let failed_file = capture::write_failed(run.folder, host, capture::FAILED_FIRST_LINE, &run.clean(&text))
                .with_context(|| format!("could not write the FAILED file for {host}"))?;

            DeviceOutcome {
                host: host.to_string(),
                status: Status::Failed,
                name: hostname.clone(),
                reason: failure_reason(&error).to_string(),
                file_path: Some(failed_file),
            }
        }
    };

    // Advance the bar for the commands this device didn't get to run.
    // Counted, so a device that fails late doesn't move the bar twice.
    run.progress.advance((job.commands.len() - done) as u64);

    if let Some(session) = session {
        // Closing can fail on its own (the device hangs up first). By
        // now the capture is on disk and complete, so it's worth a
        // warning and nothing more: not a FAILED file next to a good
        // capture.
        if let Err(error) = session.disconnect() {
            run.log(format!(
                "WARNING: {}: error while disconnecting, ignored ({error:#})",
                outcome.label()
            ));
        }
    }

    Ok(outcome)
}

/// A file's modification time as a zip entry timestamp, like Python's
/// `zipfile` records it; the zip epoch when it cannot be represented.
fn zip_mtime(path: &Path) -> zip::DateTime {
    use chrono::{Datelike, Timelike};

    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .map(chrono::DateTime::<chrono::Local>::from)
        .and_then(|time| {
            zip::DateTime::from_date_and_time(
                u16::try_from(time.year()).ok()?,
                time.month() as u8,
                time.day() as u8,
                time.hour() as u8,
                time.minute() as u8,
                time.second() as u8,
            )
            .ok()
        })
        .unwrap_or_default()
}

/// Zip every file in `folder` into `zip_path`, each at the archive
/// root under its own name (deflate).
pub fn create_zip(folder: &Path, zip_path: &Path) -> anyhow::Result<()> {
    let file = File::create(zip_path).with_context(|| format!("could not create {}", zip_path.display()))?;
    let mut archive = ZipWriter::new(BufWriter::new(file));

    let mut entries: Vec<PathBuf> = fs::read_dir(folder)
        .with_context(|| format!("could not list {}", folder.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<_>>()?;
    entries.sort();

    for path in entries.iter().filter(|path| path.is_file()) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(zip_mtime(path));
        archive.start_file(name.as_ref(), options)?;
        let mut source = File::open(path).with_context(|| format!("could not read {}", path.display()))?;
        io::copy(&mut source, &mut archive)?;
    }

    archive.finish()?.flush()?;

    Ok(())
}

/// Collect all devices for one phase ("precheck" or "postcheck") into
/// `<phase_dir>/<phase>_<run_timestamp>/` and zip it next to it, with
/// a progress bar on the terminal.
///
/// With `redact_secrets`, every command's output is passed through
/// [`redact::scrub`] before it is written, so passwords, hashes, and
/// keys never land in the capture files or the zip.
///
/// Returns a [`RunResult`]: the folder and zip that were just written,
/// each device's outcome, the summary line, and the exit code.
pub fn run_collection(
    jobs: &[Job],
    phase: &str,
    phase_dir: &Path,
    run_timestamp: &str,
    redact_secrets: bool,
    connector: &dyn Connector,
) -> anyhow::Result<RunResult> {
    let total_commands: u64 = jobs.iter().map(|job| job.commands.len() as u64).sum();

    let bar = ProgressBar::new(total_commands)
        .with_style(
            ProgressStyle::with_template("{msg:.bold.blue} {bar:40} {percent:>3}% {elapsed_precise} {eta_precise}")
                .expect("valid progress template"),
        )
        .with_message(format!("{} Progress", capitalize(phase)));
    let progress = BarProgress(bar);

    let result = run_collection_with(
        jobs,
        phase,
        phase_dir,
        run_timestamp,
        redact_secrets,
        connector,
        &progress,
    );

    progress.0.finish();

    result
}

/// [`run_collection`] reporting to `progress` instead of a terminal bar.
pub fn run_collection_with(
    jobs: &[Job],
    phase: &str,
    phase_dir: &Path,
    run_timestamp: &str,
    redact_secrets: bool,
    connector: &dyn Connector,
    progress: &dyn Progress,
) -> anyhow::Result<RunResult> {
    let folder = phase_dir.join(format!("{phase}_{run_timestamp}"));
    let zip_path = phase_dir.join(format!("{phase}_{run_timestamp}.zip"));

    fs::create_dir_all(&folder).with_context(|| format!("could not create {}", folder.display()))?;

    let run = Run {
        folder: &folder,
        progress,
        redact_secrets,
        connector,
        gates: Mutex::new(Vec::new()),
        claims: Mutex::new(IndexMap::new()),
    };
    let next_job = AtomicUsize::new(0);
    let collected: Mutex<Vec<DeviceOutcome>> = Mutex::new(Vec::new());

    thread::scope(|scope| {
        for _ in 0..MAX_WORKERS.min(jobs.len()) {
            scope.spawn(|| {
                loop {
                    let index = next_job.fetch_add(1, Ordering::SeqCst);
                    let Some(job) = jobs.get(index) else {
                        break;
                    };

                    let outcome = collect_device(job, &run).unwrap_or_else(|error| {
                        run.log(format!("Thread failed: {}: {error:#}", job.device.host));
                        DeviceOutcome {
                            host: job.device.host.clone(),
                            status: Status::Failed,
                            name: String::new(),
                            reason: "capture failed".to_string(),
                            file_path: None,
                        }
                    });

                    lock(&collected).push(outcome);
                }
            });
        }
    });

    let mut outcomes = collected.into_inner().unwrap_or_else(PoisonError::into_inner);
    run.settle_names(&mut outcomes);
    // A stable sort, so devices that share a label keep a steady order.
    outcomes.sort_by(|a, b| a.label().cmp(b.label()).then_with(|| a.host.cmp(&b.host)));

    let result = RunResult {
        folder,
        zip: zip_path,
        outcomes,
    };

    // Last, and only if we got this far: a run stopped by Ctrl-C or a
    // crash never writes the marker, so the compare can tell its folder
    // isn't a full baseline.
    capture::write_complete_marker(&result.folder, phase, result.counts())
        .with_context(|| format!("could not write the completion marker in {}", result.folder.display()))?;

    create_zip(&result.folder, &result.zip)?;

    Ok(result)
}

/// The lines [`report_run`] prints: how the run went, in the order a
/// reader needs them.
///
/// SUCCESS is the first line only when every device was fully captured.
/// Anything less gets INCOMPLETE, so neither a person nor a wrapper
/// script reads a partial capture as a clean one.
///
/// ```text
/// INCOMPLETE
/// 7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
/// Precheck ZIP created: reports/NET-123/Precheck/precheck_2026-04-14_08-48-05.zip
/// ```
pub fn report_lines(result: &RunResult, phase: &str, zip_shown: &str) -> Vec<String> {
    let mut lines = vec![
        if result.ok() { "SUCCESS" } else { "INCOMPLETE" }.to_string(),
        result.summary_line(),
    ];

    if let Some(skipped) = result.with(Status::Skipped).first() {
        lines.push(format!(
            "Stopped early: {}. Check the password, then run again.",
            skipped.reason
        ));
    }

    lines.push(format!("{} ZIP created: {zip_shown}", capitalize(phase)));

    lines
}

/// Print how the run went and return the exit code to leave with.
pub fn report_run(result: &RunResult, phase: &str, zip_shown: &str) -> u8 {
    println!();

    for line in report_lines(result, phase, zip_shown) {
        println!("{line}");
    }

    result.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_parsing() {
        assert_eq!(parse_hostname("Hostname: SW-1\n", "Hostname:").as_deref(), Some("SW-1"));
        assert_eq!(
            parse_hostname("  hostname: FW-1\nserial: 1", "hostname:").as_deref(),
            Some("FW-1")
        );
        assert_eq!(parse_hostname("nothing here", "Hostname:"), None);
        assert_eq!(hostname_lookup("cisco_ios"), None);
        assert_eq!(hostname_lookup("arista_eos"), Some(("show hostname", "Hostname:")));
    }

    #[test]
    fn header_and_section_shape() {
        let header = capture_header("SW-1", "192.0.2.1", "2026-04-14 08:48:02.123456", true);
        assert_eq!(
            header,
            format!(
                "Hostname: SW-1\nIP Address: 192.0.2.1\nGenerated: 2026-04-14 08:48:02.123456\nSecrets: redacted\n{}\n",
                "=".repeat(80)
            )
        );
        assert!(!capture_header("SW-1", "192.0.2.1", "t", false).contains("Secrets"));
        assert_eq!(
            capture_section("show version", "Arista"),
            format!("\n\n### show version ###\n{}\nArista\n", "-".repeat(80))
        );
    }

    #[test]
    fn generated_timestamp_shape() {
        let stamp = generated_timestamp();
        let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$").unwrap();
        assert!(re.is_match(&stamp), "{stamp}");
    }

    #[test]
    fn capitalizes_like_python() {
        assert_eq!(capitalize("precheck"), "Precheck");
        assert_eq!(capitalize("POSTCHECK"), "Postcheck");
        assert_eq!(capitalize(""), "");
    }
}
