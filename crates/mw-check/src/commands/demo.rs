//! `mw demo`: the whole workflow on the bundled fictional dataset.
//! No devices, no SSH: the connector replays the captures in
//! `fixtures/NET-DEMO/`, everything else is the real code path.
//!
//! Port of the Python `scripts/demo.py`. The SSH connector is swapped
//! for [`ReplayConnector`], which answers each show command from the
//! captures of a made-up uplink migration at SITE-A (see
//! `fixtures/NET-DEMO/SCENARIO.md`). Everything else is the real code:
//! the parallel collector with its progress bar, the zip packaging,
//! the quick text diff and the HTML report land in `reports/NET-DEMO/`
//! exactly as they would after a real window.
//!
//! # Where the fixtures are
//!
//! A binary has no source tree next to it, so [`fixtures_dir`] looks,
//! in order, at `$MW_FIXTURES`, then at `fixtures/` in the
//! current directory, then at the `fixtures/` directory of the crate
//! that was compiled (`CARGO_MANIFEST_DIR`), which is what tests and
//! `cargo run` use.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};

use crate::capture::{self, HEADER, Sections};
use crate::collect::{self, Connector, Session, capitalize, run_collection};
use crate::inventory::{DeviceSpec, Job};
use crate::{layout, report, textcompare};

pub const TICKET: &str = "NET-DEMO";

/// Capture timestamps from the fictional window; reused so the replayed
/// run lands in folders with the same names as the source captures.
pub const STAMPS: [(&str, &str); 2] = [("precheck", "2026-04-14_08-48"), ("postcheck", "2026-04-14_10-42")];

/// Pretend each show command takes this long, so the progress bar is visible.
pub const COMMAND_DELAY: Duration = Duration::from_millis(120);

/// Which capture belongs to which "management IP" and platform:
/// `(device_type, host, hostname)`.
pub const DEVICES: [(&str, &str, &str); 4] = [
    ("arista_eos", "192.0.2.1", "SITE-A-SW-1"),
    ("arista_eos", "192.0.2.2", "SITE-A-SW-2"),
    ("arista_eos", "192.0.2.11", "SITE-B-SW-1"),
    ("paloalto_panos", "10.10.200.254", "SITE-A-FW-1"),
];

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Where to write reports/ (default: $MW_HOME or the current directory)
    #[arg(short = 'H', long, value_name = "DIR")]
    pub home: Option<std::path::PathBuf>,
}

/// The capture timestamp of a phase.
pub fn stamp(phase: &str) -> &'static str {
    STAMPS
        .iter()
        .find(|(name, _)| *name == phase)
        .map(|(_, stamp)| *stamp)
        .unwrap_or_else(|| panic!("no demo stamp for phase {phase:?}"))
}

/// The demo dataset, compiled into the binary so `mw demo` works from
/// a downloaded executable with no source tree around it.
const EMBEDDED_FIXTURES: &[(&str, &str)] = &[
    (
        "NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-A-FW-1.txt",
        include_str!("../../fixtures/NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-A-FW-1.txt"),
    ),
    (
        "NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-A-SW-1.txt",
        include_str!("../../fixtures/NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-A-SW-1.txt"),
    ),
    (
        "NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-A-SW-2.txt",
        include_str!("../../fixtures/NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-A-SW-2.txt"),
    ),
    (
        "NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-B-SW-1.txt",
        include_str!("../../fixtures/NET-DEMO/Precheck/precheck_2026-04-14_08-48/SITE-B-SW-1.txt"),
    ),
    (
        "NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-A-FW-1.txt",
        include_str!("../../fixtures/NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-A-FW-1.txt"),
    ),
    (
        "NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-A-SW-1.txt",
        include_str!("../../fixtures/NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-A-SW-1.txt"),
    ),
    (
        "NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-A-SW-2.txt",
        include_str!("../../fixtures/NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-A-SW-2.txt"),
    ),
    (
        "NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-B-SW-1.txt",
        include_str!("../../fixtures/NET-DEMO/Postcheck/postcheck_2026-04-14_10-42/SITE-B-SW-1.txt"),
    ),
    (
        "NET-DEMO/SCENARIO.md",
        include_str!("../../fixtures/NET-DEMO/SCENARIO.md"),
    ),
    (
        "devices.example.yml",
        include_str!("../../fixtures/devices.example.yml"),
    ),
];

/// The folder holding `NET-DEMO/`. When it's a copy unpacked from the
/// binary, the temp folder is removed when this is dropped.
pub struct Fixtures {
    path: PathBuf,
    _unpacked: Option<tempfile::TempDir>,
}

impl Fixtures {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Write the embedded dataset into a fresh private temp folder.
///
/// The folder gets a random name and is readable only by you
/// (`tempfile::TempDir`). The old fixed name under the shared temp
/// directory could be created ahead of time by another user on the
/// same machine, and the demo would then have replayed their files.
fn unpack_embedded_fixtures() -> anyhow::Result<Fixtures> {
    let dir = tempfile::Builder::new()
        .prefix("mw-demo-")
        .tempdir()
        .context("could not create a temp folder for the demo captures")?;

    for (relative, contents) in EMBEDDED_FIXTURES {
        let path = dir.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
        }
        fs::write(&path, contents).with_context(|| format!("could not write {}", path.display()))?;
    }

    Ok(Fixtures {
        path: dir.path().to_path_buf(),
        _unpacked: Some(dir),
    })
}

/// The directory holding `NET-DEMO/`: `$MW_FIXTURES`, else `./fixtures`
/// when it has the demo, else the crate's own `fixtures/` when this is
/// a source checkout, else the copy compiled into the binary, unpacked
/// into a private temp folder.
pub fn fixtures_dir() -> anyhow::Result<Fixtures> {
    let on_disk = |path: PathBuf| Fixtures { path, _unpacked: None };

    if let Some(dir) = std::env::var_os("MW_FIXTURES").filter(|dir| !dir.is_empty()) {
        return Ok(on_disk(PathBuf::from(dir)));
    }

    let local = PathBuf::from("fixtures");
    if local.join(TICKET).is_dir() {
        return Ok(on_disk(local));
    }

    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    if source.join(TICKET).is_dir() {
        return Ok(on_disk(source));
    }

    unpack_embedded_fixtures()
}

/// The source capture folder of one phase:
/// `<fixtures>/NET-DEMO/Precheck/precheck_2026-04-14_08-48`.
pub fn phase_folder(fixtures: &Path, phase: &str) -> PathBuf {
    fixtures
        .join(TICKET)
        .join(capitalize(phase))
        .join(format!("{phase}_{}", stamp(phase)))
}

/// Stands in for an SSH connection; replays one device's capture.
struct ReplaySession {
    sections: Sections,
    hostname: String,
    device_type: String,
    host: String,
    delay: Duration,
}

impl Session for ReplaySession {
    fn hostname(&mut self) -> anyhow::Result<String> {
        let (device_type, host) = (self.device_type.clone(), self.host.clone());
        collect::get_hostname(self, &device_type, &host)
    }

    fn send_command(&mut self, command: &str) -> anyhow::Result<String> {
        std::thread::sleep(self.delay);

        if command == "show hostname" || command == "show system info | match hostname" {
            return Ok(format!("Hostname: {0}\nhostname: {0}", self.hostname));
        }

        // Real captures store the command output under a "### cmd ###"
        // header, preceded by a dashed rule; return just the output.
        let rule = "-".repeat(80);
        let output = self
            .sections
            .get(command)
            .map(|lines| {
                lines
                    .iter()
                    .filter(|line| !line.starts_with(&rule))
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        Ok(output.trim_end_matches('\n').to_string())
    }

    fn disconnect(self: Box<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Opens [`ReplaySession`]s from the captures of one phase folder.
pub struct ReplayConnector {
    folder: PathBuf,
    delay: Duration,
}

impl ReplayConnector {
    /// Replay the `<hostname>.txt` captures in `folder`, pausing
    /// [`COMMAND_DELAY`] per command.
    pub fn new(folder: impl Into<PathBuf>) -> ReplayConnector {
        ReplayConnector {
            folder: folder.into(),
            delay: COMMAND_DELAY,
        }
    }

    /// The connector for one phase of the bundled scenario.
    pub fn for_phase(fixtures: &Path, phase: &str) -> ReplayConnector {
        ReplayConnector::new(phase_folder(fixtures, phase))
    }

    /// How long each command pretends to take (tests pass zero).
    pub fn with_delay(mut self, delay: Duration) -> ReplayConnector {
        self.delay = delay;
        self
    }
}

impl Connector for ReplayConnector {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        let hostname = DEVICES
            .iter()
            .find(|(_, ip, _)| *ip == device.host)
            .map(|(_, _, hostname)| *hostname)
            .ok_or_else(|| anyhow!("no demo capture for {}", device.host))?;

        let path = self.folder.join(format!("{hostname}.txt"));
        let sections = capture::parse_sections(&path).with_context(|| format!("could not read {}", path.display()))?;

        Ok(Box::new(ReplaySession {
            sections,
            hostname: hostname.to_string(),
            device_type: device.device_type.clone(),
            host: device.host.clone(),
            delay: self.delay,
        }))
    }
}

/// Same shape `inventory::build_jobs()` produces, without credentials,
/// from the bundled fixtures (see [`fixtures_dir`]).
pub fn demo_jobs() -> anyhow::Result<Vec<Job>> {
    demo_jobs_in(fixtures_dir()?.path())
}

/// [`demo_jobs`] from an explicit fixtures directory. Each platform's
/// command list is the section list of its first device's precheck
/// capture.
pub fn demo_jobs_in(fixtures: &Path) -> anyhow::Result<Vec<Job>> {
    let precheck = phase_folder(fixtures, "precheck");
    let mut commands_by_type: Vec<(&str, Vec<String>)> = Vec::new();

    for (device_type, _ip, hostname) in DEVICES {
        if commands_by_type.iter().any(|(name, _)| *name == device_type) {
            continue;
        }
        let path = precheck.join(format!("{hostname}.txt"));
        let sections = capture::parse_sections(&path).with_context(|| format!("could not read {}", path.display()))?;
        let commands = sections.keys().filter(|key| *key != HEADER).cloned().collect();
        commands_by_type.push((device_type, commands));
    }

    Ok(DEVICES
        .iter()
        .map(|(device_type, ip, _hostname)| Job {
            device: DeviceSpec::new(*device_type, *ip, "demo", "demo"),
            commands: commands_by_type
                .iter()
                .find(|(name, _)| name == device_type)
                .map(|(_, commands)| commands.clone())
                .unwrap_or_default(),
        })
        .collect())
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // --home stands in for $MW_HOME on this run.
    let root = args.home.clone().unwrap_or_else(layout::root);
    run_in(&root, fixtures_dir()?.path(), COMMAND_DELAY)
}

/// The demo under an explicit root: `reports/NET-DEMO/` is written
/// inside `root` and every path is shown relative to it. Nothing here
/// reads the environment or the current directory.
pub fn run_in(root: &Path, fixtures: &Path, delay: Duration) -> anyhow::Result<()> {
    let dirs = layout::ticket_dirs_in(root, TICKET)?;
    let shown = |path: &Path| dirs.display(path);

    let jobs = demo_jobs_in(fixtures)?;

    println!(
        "{TICKET}: fictional SITE-A uplink migration, {} devices replayed from fixtures/ (no SSH)",
        jobs.len()
    );
    println!();

    for (phase, phase_dir) in [("precheck", &dirs.precheck), ("postcheck", &dirs.postcheck)] {
        fs::create_dir_all(phase_dir).with_context(|| format!("could not create {}", phase_dir.display()))?;
        // No SSH happens here, so there are no host keys to check, and
        // the demo never touches your known-hosts file.
        let connector = ReplayConnector::for_phase(fixtures, phase).with_delay(delay);
        let result = run_collection(&jobs, phase, phase_dir, stamp(phase), false, &connector)?;
        println!("{} ZIP created: {}", capitalize(phase), shown(&result.zip));
        println!();
    }

    let run_timestamp = layout::timestamp();
    textcompare::write_compare_report(TICKET, &dirs, &run_timestamp)?;

    report::build_html_report(TICKET, &dirs, &run_timestamp, None, None)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_fixtures_unpack_to_a_usable_dataset() {
        let fixtures = unpack_embedded_fixtures().unwrap();
        assert!(fixtures.path().join("devices.example.yml").is_file());
        let jobs = demo_jobs_in(fixtures.path()).unwrap();
        assert_eq!(jobs.len(), DEVICES.len());

        // Each unpack gets its own folder, so nobody can plant one first.
        let again = unpack_embedded_fixtures().unwrap();
        assert_ne!(again.path(), fixtures.path());

        // The folder goes away with the handle.
        let path = fixtures.path().to_path_buf();
        drop(fixtures);
        assert!(!path.exists());
    }

    #[test]
    fn the_demo_writes_under_the_root_it_is_given() {
        let home = tempfile::tempdir().unwrap();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");

        run_in(home.path(), &fixtures, Duration::ZERO).unwrap();

        let base = home.path().join("reports").join(TICKET);
        assert!(
            base.join("Precheck/precheck_2026-04-14_08-48/SITE-A-SW-1.txt")
                .is_file()
        );
        assert!(base.join("Postcheck/postcheck_2026-04-14_10-42.zip").is_file());
        let reports: Vec<String> = fs::read_dir(base.join("Compare"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(reports.len(), 2, "{reports:?}");

        // Paths in the report are relative to the root, not the machine.
        let html = reports.iter().find(|name| name.ends_with(".html")).unwrap();
        let page = fs::read_to_string(base.join("Compare").join(html)).unwrap();
        assert!(page.contains("Precheck: reports/NET-DEMO/Precheck/precheck_2026-04-14_08-48"));
    }
}
