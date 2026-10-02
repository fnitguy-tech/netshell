//! `run_collection` end to end through the demo's replaying connector:
//! the files, the header, the sections and the zip it produces.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mw_check::capture::{HEADER, parse_sections};
use mw_check::collect::{Connector, run_collection};
use mw_check::commands::demo::{DEVICES, ReplayConnector, demo_jobs_in, phase_folder, stamp};
use mw_check::inventory::{DeviceSpec, Job};
use regex::Regex;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn replay(phase: &str) -> ReplayConnector {
    ReplayConnector::for_phase(&fixtures(), phase).with_delay(Duration::ZERO)
}

/// The lines without the blank ones that end a section.
fn trimmed(lines: &[String]) -> &[String] {
    let end = lines.iter().rposition(|line| !line.is_empty()).map_or(0, |i| i + 1);
    &lines[..end]
}

fn zip_names(path: &Path) -> BTreeSet<String> {
    let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
    (0..archive.len())
        .map(|index| archive.by_index(index).unwrap().name().to_string())
        .collect()
}

#[test]
fn demo_jobs_come_from_the_precheck_captures() {
    let jobs = demo_jobs_in(&fixtures()).unwrap();

    assert_eq!(jobs.len(), DEVICES.len());
    for (job, (device_type, host, _)) in jobs.iter().zip(DEVICES) {
        assert_eq!(job.device.device_type, device_type);
        assert_eq!(job.device.host, host);
        assert_eq!(job.device.username, "demo");
        assert_eq!(job.device.password, "demo");
        assert!(!job.commands.is_empty());
        assert!(job.commands.iter().all(|command| command != HEADER));
    }
    // Both EOS switches share SITE-A-SW-1's command list, like the Python.
    assert_eq!(jobs[0].commands, jobs[1].commands);
    assert_eq!(jobs[0].commands, jobs[2].commands);
    assert!(jobs[0].commands.iter().any(|c| c == "show ip bgp summary"));
    assert!(jobs[3].commands.iter().any(|c| c == "show config running"));
}

#[test]
fn replayed_collection_reproduces_the_fixture_captures() {
    let tmp = tempfile::tempdir().unwrap();
    let jobs = demo_jobs_in(&fixtures()).unwrap();
    let generated = Regex::new(r"^Generated: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$").unwrap();

    for phase in ["precheck", "postcheck"] {
        let phase_dir = tmp.path().join(phase);
        let (folder, zip_path) = run_collection(&jobs, phase, &phase_dir, stamp(phase), false, &replay(phase)).unwrap();

        assert_eq!(folder, phase_dir.join(format!("{phase}_{}", stamp(phase))));
        assert_eq!(zip_path, phase_dir.join(format!("{phase}_{}.zip", stamp(phase))));

        // One file per device, named after the hostname, nothing else.
        let mut written: Vec<String> = fs::read_dir(&folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        written.sort();
        let mut expected: Vec<String> = DEVICES
            .iter()
            .map(|(_, _, hostname)| format!("{hostname}.txt"))
            .collect();
        expected.sort();
        assert_eq!(written, expected);

        let source_folder = phase_folder(&fixtures(), phase);

        for (_, host, hostname) in DEVICES {
            let text = fs::read_to_string(folder.join(format!("{hostname}.txt"))).unwrap();
            let lines: Vec<&str> = text.lines().collect();

            // The exact header shape.
            assert_eq!(lines[0], format!("Hostname: {hostname}"));
            assert_eq!(lines[1], format!("IP Address: {host}"));
            assert!(generated.is_match(lines[2]), "{}", lines[2]);
            assert_eq!(lines[3], "=".repeat(80));
            assert_eq!(lines[4], "");
            assert_eq!(lines[5], "");
            assert!(lines[6].starts_with("### ") && lines[6].ends_with(" ###"));
            assert_eq!(lines[7], "-".repeat(80));
            assert!(!text.contains("Secrets: redacted"));

            // One section per job command, in job order.
            let job = jobs.iter().find(|job| job.device.host == host).unwrap();
            let ours = parse_sections(&folder.join(format!("{hostname}.txt"))).unwrap();
            let mut expected_commands = vec![HEADER.to_string()];
            expected_commands.extend(job.commands.iter().cloned());
            assert_eq!(
                ours.keys().cloned().collect::<Vec<_>>(),
                expected_commands,
                "{hostname}"
            );

            // The fixture's sections round-trip: same commands in the
            // same order, same lines. Only the trailing blank lines of
            // an output differ, because the replay strips them the way
            // the Python demo's stand-in connection does. A command the
            // platform list has but this device's fixture does not
            // (SITE-A-SW-2 has no transceiver section) comes back empty.
            let theirs = parse_sections(&source_folder.join(format!("{hostname}.txt"))).unwrap();
            let in_both: Vec<&String> = ours.keys().filter(|command| theirs.contains_key(*command)).collect();
            assert_eq!(in_both, theirs.keys().collect::<Vec<_>>(), "{hostname}");
            for (command, lines) in &ours {
                if command == HEADER {
                    continue;
                }
                match theirs.get(command) {
                    Some(fixture_lines) => assert_eq!(trimmed(lines), trimmed(fixture_lines), "{hostname} {command}"),
                    None => assert_eq!(trimmed(lines), [("-".repeat(80))], "{hostname} {command}"),
                }
            }
        }

        // The zip holds the same file names, at the archive root.
        assert_eq!(zip_names(&zip_path), written.iter().cloned().collect::<BTreeSet<_>>());
    }
}

#[test]
fn unreachable_device_gets_a_failed_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let mut jobs = demo_jobs_in(&fixtures()).unwrap();
    jobs.truncate(1);
    jobs.push(Job {
        device: DeviceSpec {
            device_type: "arista_eos".to_string(),
            host: "198.51.100.99".to_string(),
            username: "demo".to_string(),
            password: "demo".to_string(),
        },
        commands: vec!["show version".to_string(), "show ip route".to_string()],
    });

    let (folder, zip_path) = run_collection(
        &jobs,
        "precheck",
        tmp.path(),
        "2026-01-01_00-00",
        true,
        &replay("precheck"),
    )
    .unwrap();

    let marker = fs::read_to_string(folder.join("198.51.100.99_FAILED.txt")).unwrap();
    assert!(marker.starts_with("FAILED TO CONNECT TO 198.51.100.99\n"), "{marker}");
    assert!(marker.contains("no demo capture for 198.51.100.99"), "{marker}");
    assert!(!folder.join("198.51.100.99.txt").exists());

    // The reachable device was still captured, with redaction noted.
    let good = fs::read_to_string(folder.join("SITE-A-SW-1.txt")).unwrap();
    assert!(good.contains("Secrets: redacted\n"));

    assert_eq!(
        zip_names(&zip_path),
        ["198.51.100.99_FAILED.txt".to_string(), "SITE-A-SW-1.txt".to_string()]
            .into_iter()
            .collect()
    );
}

/// A session that fails one command but not the connection.
struct FlakySession;

impl mw_check::collect::Session for FlakySession {
    fn hostname(&mut self) -> anyhow::Result<String> {
        Ok("FLAKY-1".to_string())
    }

    fn send_command(&mut self, command: &str) -> anyhow::Result<String> {
        if command == "show ip bgp" {
            anyhow::bail!("timed out after 180s waiting for the prompt");
        }
        Ok(format!("output of {command}"))
    }

    fn disconnect(self: Box<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}

struct FlakyConnector;

impl Connector for FlakyConnector {
    fn connect(&self, _device: &DeviceSpec) -> anyhow::Result<Box<dyn mw_check::collect::Session>> {
        Ok(Box::new(FlakySession))
    }
}

#[test]
fn failed_command_is_recorded_in_its_section() {
    let tmp = tempfile::tempdir().unwrap();
    let jobs = vec![Job {
        device: DeviceSpec {
            device_type: "cisco_ios".to_string(),
            host: "10.0.0.1".to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
        },
        commands: vec!["show version".to_string(), "show ip bgp".to_string()],
    }];

    let (folder, _zip) = run_collection(
        &jobs,
        "postcheck",
        tmp.path(),
        "2026-01-01_00-00",
        false,
        &FlakyConnector,
    )
    .unwrap();

    let sections = parse_sections(&folder.join("FLAKY-1.txt")).unwrap();
    assert_eq!(
        sections.keys().collect::<Vec<_>>(),
        [HEADER, "show version", "show ip bgp"]
    );
    assert_eq!(
        sections["show version"],
        [
            "-".repeat(80),
            "output of show version".to_string(),
            String::new(),
            String::new()
        ]
    );
    assert_eq!(
        sections["show ip bgp"],
        [
            "-".repeat(80),
            "COMMAND FAILED:".to_string(),
            "timed out after 180s waiting for the prompt".to_string()
        ]
    );
}
