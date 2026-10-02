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
//! Output files use `### <command> ###` section headers (see
//! [`crate::capture`]); the compare modules parse those headers to
//! diff command by command.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use netshell::{ConnectOptions, Platform};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::capture::section_header;
use crate::inventory::{DeviceSpec, Job};
use crate::redact;

/// How many devices are collected at once.
pub const MAX_WORKERS: usize = 5;

/// Seconds to wait for one command; `show ip bgp` on a full table is slow.
pub const COMMAND_READ_TIMEOUT_SECS: u64 = 180;

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

/// An open session on one device. The real one wraps netshell; the
/// demo replays bundled captures.
pub trait Session: Send {
    /// The device's own hostname, so capture files are named after it
    /// and not its management IP.
    fn hostname(&mut self) -> anyhow::Result<String>;
    fn send_command(&mut self, command: &str) -> anyhow::Result<String>;
    fn disconnect(self: Box<Self>) -> anyhow::Result<()>;
}

/// Opens sessions. Swapped for a replaying stub by `mw demo`.
pub trait Connector: Sync {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>>;
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
pub struct SshConnector;

impl Connector for SshConnector {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        let platform = Platform::by_name(&device.device_type)?;
        let options = ConnectOptions::new(&device.host, &device.username, &device.password, platform)
            .read_timeout(Duration::from_secs(COMMAND_READ_TIMEOUT_SECS));
        let connection = netshell::blocking::Device::connect(options)?;

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
    format!("\n\n{}\n{}\n{output}\n", section_header(command), "-".repeat(80))
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

/// A console line above the progress bar, timestamped like the
/// Python's `console.log`. Printed even when the bar is hidden
/// (stdout is not a terminal), which `ProgressBar::println` is not.
fn log(bar: &ProgressBar, message: impl AsRef<str>) {
    let stamp = chrono::Local::now().format("%H:%M:%S");
    bar.suspend(|| println!("[{stamp}] {}", message.as_ref()));
}

/// Connect, capture every command into `<folder>/<hostname>.txt`, and
/// on any failure write `<folder>/<host>_FAILED.txt` instead. Only an
/// error writing that marker is returned.
fn collect_device(
    job: &Job,
    folder: &Path,
    bar: &ProgressBar,
    redact_secrets: bool,
    connector: &dyn Connector,
) -> anyhow::Result<()> {
    let device = &job.device;

    log(bar, format!("Connecting to {}...", device.host));

    if let Err(error) = capture_device(job, folder, bar, redact_secrets, connector) {
        log(bar, format!("FAILED: {}", device.host));
        log(bar, error.to_string());

        let failed_file = folder.join(format!("{}_FAILED.txt", device.host));
        let text = format!(
            "FAILED TO CONNECT TO {}\n{}",
            device.host,
            clean(&error.to_string(), redact_secrets)
        );
        fs::write(&failed_file, text).with_context(|| format!("could not write {}", failed_file.display()))?;

        // Still advance the bar for the commands this device would have run.
        bar.inc(job.commands.len() as u64);
    }

    Ok(())
}

/// Scrub output before it is written so no password, hash or key ever
/// reaches disk; off by default because it hides a rotated password
/// from the diff (see redact.rs).
fn clean(text: &str, redact_secrets: bool) -> String {
    if redact_secrets {
        redact::scrub(text)
    } else {
        text.to_string()
    }
}

/// Everything the Python does inside its `try:` block.
fn capture_device(
    job: &Job,
    folder: &Path,
    bar: &ProgressBar,
    redact_secrets: bool,
    connector: &dyn Connector,
) -> anyhow::Result<()> {
    let device = &job.device;
    let mut session = connector.connect(device)?;

    let hostname = session.hostname()?;
    log(bar, format!("Connected to {hostname}"));

    let file_path = folder.join(format!("{hostname}.txt"));
    let write_error = |error: io::Error| anyhow!("could not write {}: {error}", file_path.display());
    let mut file = BufWriter::new(File::create(&file_path).map_err(write_error)?);

    let generated = generated_timestamp();
    file.write_all(capture_header(&hostname, &device.host, &generated, redact_secrets).as_bytes())
        .map_err(write_error)?;

    for command in &job.commands {
        bar.set_message(hostname.clone());

        let output = match session.send_command(command) {
            Ok(output) => output,
            Err(error) => format!("COMMAND FAILED:\n{error}"),
        };

        file.write_all(capture_section(command, &clean(&output, redact_secrets)).as_bytes())
            .map_err(write_error)?;

        bar.inc(1);
    }

    file.flush().map_err(write_error)?;
    drop(file);

    session.disconnect()?;

    Ok(())
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
/// `<phase_dir>/<phase>_<run_timestamp>/` and zip it next to it.
/// Returns `(folder, zip)`.
///
/// With `redact_secrets`, every command's output is passed through
/// [`redact::scrub`] before it is written, so passwords, hashes and
/// keys never land in the capture files or the zip.
pub fn run_collection(
    jobs: &[Job],
    phase: &str,
    phase_dir: &Path,
    run_timestamp: &str,
    redact_secrets: bool,
    connector: &dyn Connector,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let folder = phase_dir.join(format!("{phase}_{run_timestamp}"));
    let zip_path = phase_dir.join(format!("{phase}_{run_timestamp}.zip"));

    fs::create_dir_all(&folder).with_context(|| format!("could not create {}", folder.display()))?;

    let total_commands: u64 = jobs.iter().map(|job| job.commands.len() as u64).sum();

    let bar = ProgressBar::new(total_commands)
        .with_style(
            ProgressStyle::with_template("{msg:.bold.blue} {bar:40} {percent:>3}% {elapsed_precise} {eta_precise}")
                .expect("valid progress template"),
        )
        .with_message(format!("{} Progress", capitalize(phase)));

    let next_job = AtomicUsize::new(0);

    thread::scope(|scope| {
        for _ in 0..MAX_WORKERS.min(jobs.len()) {
            scope.spawn(|| {
                loop {
                    let index = next_job.fetch_add(1, Ordering::SeqCst);
                    let Some(job) = jobs.get(index) else {
                        break;
                    };
                    if let Err(error) = collect_device(job, &folder, &bar, redact_secrets, connector) {
                        log(&bar, format!("Thread failed: {error}"));
                    }
                }
            });
        }
    });

    bar.finish();

    create_zip(&folder, &zip_path)?;

    Ok((folder, zip_path))
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
