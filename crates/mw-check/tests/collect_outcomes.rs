//! The collector, driven by fake connections. No SSH happens here.
//!
//! Port of the Python `tests/test_collect.py`, plus the exit-code table
//! from `tests/test_cli.py`. The fakes fail with real `netshell::Error`
//! values, because that's what the collector reads to tell a rejected
//! password from an unreachable device from a timeout.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mw_check::capture::{self, COMPLETE_MARKER, capture_files, parse_sections};
use mw_check::collect::{
    Connector, DeviceOutcome, EXIT_ALL_FAILED, EXIT_OK, EXIT_SOME_FAILED, Progress, RunResult, Session, Status,
    report_lines, run_collection_with,
};
use mw_check::inventory::{DeviceSpec, Job};

const COMMANDS: [&str; 3] = ["show version", "show ip bgp", "show running-config"];
const PASSWORD: &str = "pass-under-test";
const RUN_FOLDER: &str = "precheck_2026-01-01_00-00-00";

/// How a pretend device refuses a connection.
#[derive(Clone)]
enum ConnectError {
    Unreachable,
    AuthRejected,
    HostKeyChanged,
    Other(&'static str),
}

/// One pretend device: its hostname, and how it misbehaves.
#[derive(Clone, Default)]
struct FakeDevice {
    hostname: String,
    connect_error: Option<ConnectError>,
    slow_command: Option<&'static str>,
    disconnect_error: Option<&'static str>,
    /// The first connect to this device takes this long.
    connect_delay: Duration,
    commands_sent: Arc<Mutex<Vec<String>>>,
}

impl FakeDevice {
    fn named(hostname: &str) -> FakeDevice {
        FakeDevice {
            hostname: hostname.to_string(),
            ..FakeDevice::default()
        }
    }

    fn failing(error: ConnectError) -> FakeDevice {
        FakeDevice {
            connect_error: Some(error),
            ..FakeDevice::default()
        }
    }
}

struct FakeSession {
    host: String,
    device: FakeDevice,
    /// Output the device is still sending when the collector gives up
    /// waiting. The next read on the same connection would get it.
    late_output: Option<String>,
}

impl Session for FakeSession {
    fn hostname(&mut self) -> anyhow::Result<String> {
        let host = self.host.clone();
        mw_check::collect::get_hostname(self, "arista_eos", &host)
    }

    fn send_command(&mut self, command: &str) -> anyhow::Result<String> {
        self.device.commands_sent.lock().unwrap().push(command.to_string());

        if command == "show hostname" {
            return Ok(format!("Hostname: {}", self.device.hostname));
        }

        if let Some(late) = self.late_output.take() {
            return Ok(late);
        }

        if self.device.slow_command == Some(command) {
            self.late_output = Some(format!("late output of {command}"));
            return Err(netshell::Error::ReadTimeout {
                host: self.host.clone(),
                what: format!("the prompt after `{command}`"),
                timeout: Duration::from_secs(180),
                received: String::new(),
            }
            .into());
        }

        Ok(format!("output of {command}"))
    }

    fn disconnect(self: Box<Self>) -> anyhow::Result<()> {
        match self.device.disconnect_error {
            Some(text) => anyhow::bail!("{text}"),
            None => Ok(()),
        }
    }
}

/// Stands in for the SSH connector; records every attempt.
struct FakeNetwork {
    devices: BTreeMap<String, FakeDevice>,
    attempts: Mutex<Vec<String>>,
}

impl FakeNetwork {
    fn new(devices: impl IntoIterator<Item = (String, FakeDevice)>) -> FakeNetwork {
        FakeNetwork {
            devices: devices.into_iter().collect(),
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }
}

impl Connector for FakeNetwork {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        self.attempts.lock().unwrap().push(device.host.clone());
        let fake = self.devices[&device.host].clone();
        std::thread::sleep(fake.connect_delay);

        match &fake.connect_error {
            Some(ConnectError::Unreachable) => Err(netshell::Error::ConnectTimeout {
                host: device.host.clone(),
                port: 22,
                timeout: Duration::from_secs(15),
            }
            .into()),
            Some(ConnectError::AuthRejected) => Err(netshell::Error::AuthFailed {
                user: device.username.clone(),
                host: device.host.clone(),
                tried: "password".to_string(),
            }
            .into()),
            Some(ConnectError::HostKeyChanged) => Err(netshell::Error::HostKeyChanged {
                host: device.host.clone(),
                port: 22,
                stored: "ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".to_string(),
                offered: "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s".to_string(),
                file: PathBuf::from("/home/you/.config/mw/known_hosts"),
                line: 3,
            }
            .into()),
            Some(ConnectError::Other(text)) => anyhow::bail!("{text}"),
            None => Ok(Box::new(FakeSession {
                host: device.host.clone(),
                device: fake,
                late_output: None,
            })),
        }
    }
}

/// Counts how far the bar moved and keeps what was logged.
#[derive(Default)]
struct RecordingProgress {
    log: Mutex<String>,
    advanced: AtomicU64,
}

impl RecordingProgress {
    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    fn advanced(&self) -> u64 {
        self.advanced.load(Ordering::SeqCst)
    }
}

impl Progress for RecordingProgress {
    fn log(&self, message: &str) {
        let mut log = self.log.lock().unwrap();
        log.push_str(message);
        log.push('\n');
    }

    fn set_message(&self, _message: &str) {}

    fn advance(&self, amount: u64) {
        self.advanced.fetch_add(amount, Ordering::SeqCst);
    }
}

struct Outcome {
    tmp: tempfile::TempDir,
    result: RunResult,
    network: FakeNetwork,
    progress: RecordingProgress,
    total: u64,
}

impl Outcome {
    fn folder(&self) -> PathBuf {
        self.tmp.path().join(RUN_FOLDER)
    }
}

fn jobs_for(network: &FakeNetwork) -> Vec<Job> {
    network
        .devices
        .keys()
        .map(|host| Job {
            device: DeviceSpec::new("arista_eos", host.as_str(), "admin", PASSWORD),
            commands: COMMANDS.iter().map(|command| command.to_string()).collect(),
        })
        .collect()
}

fn run(devices: impl IntoIterator<Item = (String, FakeDevice)>) -> Outcome {
    let tmp = tempfile::tempdir().unwrap();
    let network = FakeNetwork::new(devices);
    let jobs = jobs_for(&network);
    let progress = RecordingProgress::default();

    let result = run_collection_with(
        &jobs,
        "precheck",
        tmp.path(),
        "2026-01-01_00-00-00",
        false,
        &network,
        &progress,
    )
    .unwrap();

    Outcome {
        tmp,
        result,
        network,
        progress,
        total: (jobs.len() * COMMANDS.len()) as u64,
    }
}

fn hosts(count: usize) -> Vec<String> {
    (1..=count).map(|n| format!("10.0.0.{n}")).collect()
}

/// `count` healthy devices named SW-1, SW-2, ...
fn healthy(count: usize) -> BTreeMap<String, FakeDevice> {
    hosts(count)
        .into_iter()
        .enumerate()
        .map(|(index, host)| (host, FakeDevice::named(&format!("SW-{}", index + 1))))
        .collect()
}

fn printed(result: &RunResult) -> String {
    report_lines(result, "precheck", "reports/NET-1/Precheck/run.zip").join("\n")
}

fn file_names(outcomes: &[DeviceOutcome]) -> Vec<String> {
    let mut names: Vec<String> = outcomes
        .iter()
        .filter_map(|outcome| outcome.file_path.as_deref())
        .filter_map(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// --- honest exit codes and the failure summary ---------------------------

#[test]
fn all_captured_is_success_and_exit_zero() {
    let outcome = run(healthy(3));

    assert_eq!(outcome.result.summary_line(), "3 of 3 captured.");
    assert_eq!(outcome.result.exit_code(), EXIT_OK);
    assert_eq!(EXIT_OK, 0);
    assert!(printed(&outcome.result).starts_with("SUCCESS\n3 of 3 captured.\n"));
    assert_eq!(outcome.progress.advanced(), outcome.total);
    assert_eq!(outcome.total, 9);
}

#[test]
fn one_unreachable_device_is_counted_named_and_exit_one() {
    let mut devices = healthy(8);
    devices.get_mut("10.0.0.5").unwrap().connect_error = Some(ConnectError::Unreachable);
    let outcome = run(devices);

    let summary = "7 of 8 captured; 1 failed: 10.0.0.5 (unreachable)";
    assert_eq!(outcome.result.summary_line(), summary);
    assert_eq!(outcome.result.exit_code(), EXIT_SOME_FAILED);
    assert_eq!(EXIT_SOME_FAILED, 1);

    let printed = printed(&outcome.result);
    assert!(!printed.contains("SUCCESS"));
    assert_eq!(
        printed,
        format!("INCOMPLETE\n{summary}\nPrecheck ZIP created: reports/NET-1/Precheck/run.zip")
    );
    assert!(outcome.folder().join("10.0.0.5_FAILED.txt").exists());
    assert_eq!(outcome.progress.advanced(), outcome.total);
}

#[test]
fn every_device_failing_is_exit_two() {
    let devices = hosts(2)
        .into_iter()
        .map(|host| (host, FakeDevice::failing(ConnectError::Unreachable)));
    let outcome = run(devices);

    assert_eq!(outcome.result.exit_code(), EXIT_ALL_FAILED);
    assert_eq!(EXIT_ALL_FAILED, 2);
    assert_eq!(
        outcome.result.summary_line(),
        "0 of 2 captured; 2 failed: 10.0.0.1 (unreachable), 10.0.0.2 (unreachable)"
    );
}

#[test]
fn first_authentication_failure_stops_the_run() {
    let devices = hosts(8)
        .into_iter()
        .map(|host| (host, FakeDevice::failing(ConnectError::AuthRejected)));
    let outcome = run(devices);

    // A wrong password is tried on exactly one device, not all eight.
    let attempts = outcome.network.attempts();
    assert_eq!(attempts.len(), 1, "{attempts:?}");
    let rejected_by = &attempts[0];

    assert_eq!(outcome.result.exit_code(), EXIT_ALL_FAILED);
    assert_eq!(
        outcome.result.summary_line(),
        format!("0 of 8 captured; 1 failed: {rejected_by} (authentication failed); 7 not attempted")
    );
    assert!(
        outcome
            .progress
            .log()
            .contains(&format!("{rejected_by} rejected the username or password"))
    );
    assert!(printed(&outcome.result).contains(&format!(
        "Stopped early: {rejected_by} rejected the username or password. Check the password, then run again."
    )));
    assert!(!printed(&outcome.result).contains("SUCCESS"));

    // Each device that wasn't tried still leaves a record for the compare.
    let skipped = hosts(8).into_iter().find(|host| host != rejected_by).unwrap();
    let record = fs::read_to_string(outcome.folder().join(format!("{skipped}_FAILED.txt"))).unwrap();
    assert_eq!(
        record,
        format!(
            "NOT ATTEMPTED: {skipped}\nNot tried, because {rejected_by} rejected the username or password. \
             Trying it on more devices could lock the account.\n"
        )
    );
    assert_eq!(
        outcome
            .result
            .outcomes
            .iter()
            .filter(|device| device.status == Status::Skipped)
            .count(),
        7
    );
    assert_eq!(outcome.progress.advanced(), outcome.total);
}

#[test]
fn an_unreachable_first_device_does_not_count_as_a_bad_password() {
    let mut devices = healthy(4);
    devices.get_mut("10.0.0.1").unwrap().connect_error = Some(ConnectError::Unreachable);
    let outcome = run(devices);

    let mut attempts = outcome.network.attempts();
    attempts.sort();
    assert_eq!(attempts, hosts(4));
    assert_eq!(
        outcome.result.summary_line(),
        "3 of 4 captured; 1 failed: 10.0.0.1 (unreachable)"
    );
}

#[test]
fn the_first_connection_goes_alone_until_the_password_is_proven() {
    // The first device takes a while to answer. Nothing else may be
    // tried in that time: the password isn't known to be right yet.
    let mut devices = healthy(6);
    for device in devices.values_mut() {
        device.connect_delay = Duration::from_millis(150);
    }

    let tmp = tempfile::tempdir().unwrap();
    let network = FakeNetwork::new(devices);
    let jobs = jobs_for(&network);
    let progress = RecordingProgress::default();

    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            run_collection_with(
                &jobs,
                "precheck",
                tmp.path(),
                "2026-01-01_00-00-00",
                false,
                &network,
                &progress,
            )
            .unwrap()
        });

        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            network.attempts().len(),
            1,
            "only one connection before the password is proven"
        );

        let result = worker.join().unwrap();
        assert_eq!(result.summary_line(), "6 of 6 captured.");
    });

    assert_eq!(network.attempts().len(), 6);
}

#[test]
fn the_password_never_reaches_a_failed_file_or_the_log() {
    let devices = [(
        "10.0.0.1".to_string(),
        FakeDevice::failing(ConnectError::Other("login as admin/pass-under-test refused")),
    )];
    let outcome = run(devices);

    let failed = fs::read_to_string(outcome.folder().join("10.0.0.1_FAILED.txt")).unwrap();
    assert!(!failed.contains(PASSWORD));
    assert!(!outcome.progress.log().contains(PASSWORD));
    assert_eq!(failed, "FAILED TO CONNECT TO 10.0.0.1\nlogin as admin/<hidden> refused");
    assert_eq!(
        outcome.result.summary_line(),
        "0 of 1 captured; 1 failed: 10.0.0.1 (capture failed)"
    );
}

#[test]
fn a_changed_host_key_fails_that_device_with_the_fix_and_nothing_else() {
    let mut devices = healthy(3);
    devices.get_mut("10.0.0.2").unwrap().connect_error = Some(ConnectError::HostKeyChanged);
    let outcome = run(devices);

    assert_eq!(
        outcome.result.summary_line(),
        "2 of 3 captured; 1 failed: 10.0.0.2 (host key changed)"
    );
    // A changed key isn't a rejected password: the other devices were still tried.
    assert_eq!(outcome.network.attempts().len(), 3);

    let failed = fs::read_to_string(outcome.folder().join("10.0.0.2_FAILED.txt")).unwrap();
    assert!(failed.starts_with(
        "FAILED TO CONNECT TO 10.0.0.2\nThe SSH host key for 10.0.0.2 has changed, so the connection was refused \
         before any password was sent.\n"
    ));
    assert!(failed.contains("  Key on file:  ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8\n"));
    assert!(failed.contains("  Key offered:  ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s\n"));
    assert!(failed.contains("  File:         /home/you/.config/mw/known_hosts (line 3)\n"));
    assert!(failed.contains("  --accept-new-host-key 10.0.0.2\n"));
    assert!(outcome.progress.log().contains("--accept-new-host-key 10.0.0.2"));
}

// --- a slow command must not shift later answers ---------------------------

#[test]
fn commands_after_a_timeout_are_skipped_not_misfiled() {
    let mut device = FakeDevice::named("SW-1");
    device.slow_command = Some("show ip bgp");
    let commands_sent = Arc::clone(&device.commands_sent);
    let outcome = run([("10.0.0.1".to_string(), device)]);

    let sections = parse_sections(&outcome.folder().join("SW-1.txt")).unwrap();
    assert_eq!(sections["show version"][1], "output of show version");
    assert_eq!(sections["show ip bgp"][1], "COMMAND FAILED:");
    assert_eq!(
        sections["show running-config"][1],
        "SKIPPED after timeout on show ip bgp"
    );

    // The late BGP output was never read, so it can't sit under the config.
    let sent = commands_sent.lock().unwrap().clone();
    assert!(!sent.iter().any(|command| command == "show running-config"), "{sent:?}");
    assert!(
        !sections["show running-config"]
            .join("\n")
            .contains("late output of show ip bgp")
    );

    assert_eq!(
        outcome.result.summary_line(),
        "0 of 1 captured; 1 incomplete: SW-1 (timeout on show ip bgp)"
    );
    assert_eq!(outcome.result.exit_code(), EXIT_SOME_FAILED);
    assert!(printed(&outcome.result).starts_with("INCOMPLETE\n"));
    assert!(
        outcome
            .progress
            .log()
            .contains("SW-1: timeout on 'show ip bgp'. Skipping the rest of its commands.")
    );
    assert_eq!(outcome.progress.advanced(), outcome.total);
}

// --- file names --------------------------------------------------------------

#[test]
fn two_devices_with_the_same_hostname_keep_separate_files() {
    let devices = [
        ("192.0.2.1".to_string(), FakeDevice::named("localhost")),
        ("192.0.2.2".to_string(), FakeDevice::named("localhost")),
    ];
    let outcome = run(devices);
    let folder = outcome.folder();

    assert_eq!(
        capture_files(&folder).unwrap(),
        ["localhost_192.0.2.1.txt", "localhost_192.0.2.2.txt"]
    );
    for host in ["192.0.2.1", "192.0.2.2"] {
        let text = fs::read_to_string(folder.join(format!("localhost_{host}.txt"))).unwrap();
        assert!(text.contains(&format!("IP Address: {host}\n")));
    }
    assert_eq!(
        file_names(&outcome.result.outcomes),
        ["localhost_192.0.2.1.txt", "localhost_192.0.2.2.txt"]
    );
}

#[test]
fn a_hostile_or_empty_hostname_stays_inside_the_run_folder() {
    for (hostname, host, expected) in [
        ("../../x", "192.0.2.1", "_.._x.txt"),
        ("", "192.0.2.1", "192.0.2.1.txt"),
        ("", "2001:db8::1", "2001_db8__1.txt"),
        ("core sw/1", "192.0.2.1", "core_sw_1.txt"),
    ] {
        let outcome = run([(host.to_string(), FakeDevice::named(hostname))]);

        assert_eq!(capture_files(&outcome.folder()).unwrap(), [expected], "{hostname:?}");

        // Nothing was written above the run folder.
        let mut above: Vec<String> = fs::read_dir(outcome.tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        above.sort();
        assert_eq!(
            above,
            [RUN_FOLDER.to_string(), format!("{RUN_FOLDER}.zip")],
            "{hostname:?}"
        );
    }
}

#[test]
fn an_unreachable_ipv6_host_gets_a_windows_safe_failed_file() {
    let outcome = run([(
        "2001:db8::5".to_string(),
        FakeDevice::failing(ConnectError::Unreachable),
    )]);

    assert_eq!(capture_files(&outcome.folder()).unwrap(), ["2001_db8__5_FAILED.txt"]);
}

// --- completion marker ---------------------------------------------------------

#[test]
fn a_finished_run_writes_the_completion_marker() {
    let mut devices = healthy(2);
    devices.get_mut("10.0.0.2").unwrap().connect_error = Some(ConnectError::Unreachable);
    let outcome = run(devices);

    let text = fs::read_to_string(outcome.folder().join(COMPLETE_MARKER)).unwrap();
    assert!(text.contains("\"phase\": \"precheck\""), "{text}");
    assert!(text.contains("\"devices\": 2"), "{text}");
    assert!(text.contains("\"captured\": 1"), "{text}");
    assert!(text.contains("\"failed\": 1"), "{text}");

    // The compare reads the folder as a finished run: no warning.
    let (warnings, _notes) = capture::baseline_warnings(&outcome.folder(), &outcome.folder());
    assert!(warnings.is_empty(), "{warnings:?}");
}

/// A connector that dies partway, the way Ctrl-C or a crash would.
struct Crashing;

impl Connector for Crashing {
    fn connect(&self, _device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        panic!("interrupted");
    }
}

#[test]
fn an_interrupted_run_leaves_no_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let jobs = vec![Job {
        device: DeviceSpec::new("arista_eos", "10.0.0.1", "admin", PASSWORD),
        commands: vec!["show version".to_string()],
    }];
    let progress = RecordingProgress::default();

    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_collection_with(
            &jobs,
            "precheck",
            tmp.path(),
            "2026-01-01_00-00-00",
            false,
            &Crashing,
            &progress,
        )
    }));

    assert!(crashed.is_err());
    assert!(tmp.path().join(RUN_FOLDER).is_dir());
    assert!(!tmp.path().join(RUN_FOLDER).join(COMPLETE_MARKER).exists());
    assert!(!tmp.path().join(format!("{RUN_FOLDER}.zip")).exists());
}

// --- disconnect errors -----------------------------------------------------------

#[test]
fn a_disconnect_error_after_a_full_capture_is_only_a_warning() {
    let mut device = FakeDevice::named("SW-1");
    device.disconnect_error = Some("Socket is closed");
    let outcome = run([("10.0.0.1".to_string(), device)]);

    assert_eq!(capture_files(&outcome.folder()).unwrap(), ["SW-1.txt"]);
    assert_eq!(outcome.result.summary_line(), "1 of 1 captured.");
    assert!(
        outcome
            .progress
            .log()
            .contains("WARNING: SW-1: error while disconnecting, ignored (Socket is closed)")
    );
    // The bar moved once per command, not twice.
    assert_eq!(outcome.progress.advanced(), outcome.total);
    assert_eq!(outcome.total, COMMANDS.len() as u64);
}

#[test]
fn the_result_names_the_folder_and_the_zip() {
    let outcome = run([("10.0.0.1".to_string(), FakeDevice::named("SW-1"))]);

    assert!(outcome.result.folder.ends_with(RUN_FOLDER));
    assert!(outcome.result.zip.ends_with(format!("{RUN_FOLDER}.zip")));
    assert!(outcome.result.zip.is_file());
}

// --- the exit code and the last lines match the run (tests/test_cli.py) -------------

#[test]
fn the_exit_code_and_last_lines_match_the_run() {
    let cases: [(&[Status], u8, &str); 3] = [
        (&[Status::Captured, Status::Captured], 0, "2 of 2 captured."),
        (
            &[Status::Captured, Status::Failed],
            1,
            "1 of 2 captured; 1 failed: 10.0.0.2 (authentication failed)",
        ),
        (
            &[Status::Failed, Status::Failed],
            2,
            "0 of 2 captured; 2 failed: 10.0.0.1 (authentication failed), 10.0.0.2 (authentication failed)",
        ),
    ];

    for (statuses, exit_code, summary) in cases {
        let outcomes = statuses
            .iter()
            .enumerate()
            .map(|(index, status)| DeviceOutcome {
                host: format!("10.0.0.{}", index + 1),
                status: *status,
                name: String::new(),
                reason: if *status == Status::Captured {
                    String::new()
                } else {
                    "authentication failed".to_string()
                },
                file_path: None,
            })
            .collect();
        let result = RunResult {
            folder: PathBuf::from("run"),
            zip: PathBuf::from("run.zip"),
            outcomes,
        };

        for phase in ["precheck", "postcheck"] {
            let lines = report_lines(&result, phase, "run.zip");
            assert_eq!(result.exit_code(), exit_code, "{summary}");
            assert_eq!(lines[1], summary);
            assert_eq!(lines[0] == "SUCCESS", exit_code == 0, "{summary}");
            assert_eq!(lines[0] == "INCOMPLETE", exit_code != 0, "{summary}");
            assert!(lines.last().unwrap().ends_with("ZIP created: run.zip"));
        }
    }
}

#[test]
fn a_run_cut_short_by_timeouts_alone_exits_one_not_two() {
    let result = RunResult {
        folder: PathBuf::from("run"),
        zip: PathBuf::from("run.zip"),
        outcomes: vec![DeviceOutcome {
            host: "10.0.0.1".to_string(),
            status: Status::Incomplete,
            name: "SITE-A-SW-1".to_string(),
            reason: "timeout on show ip bgp".to_string(),
            file_path: None,
        }],
    };

    assert_eq!(result.exit_code(), EXIT_SOME_FAILED);
    assert_eq!(
        result.summary_line(),
        "0 of 1 captured; 1 incomplete: SITE-A-SW-1 (timeout on show ip bgp)"
    );
}
