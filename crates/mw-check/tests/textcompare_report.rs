//! The text compare report: the run-folder lookup and console lines of
//! `write_compare_report` (ported from the Python tool's
//! `tests/test_textcompare.py`), and the bundled NET-DEMO fixture, whose
//! `expected/compare.txt` is the report the Python tool writes for the
//! same captures.

use std::fs;
use std::path::{Path, PathBuf};

use mw_check::layout::ticket_dirs_in;
use mw_check::textcompare::{compare_folders, parse_sections, write_compare_report};

fn fixture(part: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("NET-DEMO")
        .join(part)
}

const CAPTURE: &str = "Hostname: switch1\n### show vlan brief ###\n--------------------------------------------------------------------------------\n10  users  active\n";

#[test]
fn parse_sections_and_compare_report() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = ticket_dirs_in(tmp.path(), "NET-1").unwrap();
    let pre_run = dirs.precheck.join("precheck_2026-01-01_00-00");
    let post_run = dirs.postcheck.join("postcheck_2026-01-01_02-00");
    fs::create_dir_all(&pre_run).unwrap();
    fs::create_dir_all(&post_run).unwrap();

    fs::write(pre_run.join("switch1.txt"), CAPTURE).unwrap();
    fs::write(post_run.join("switch1.txt"), format!("{CAPTURE}20  voice  active\n")).unwrap();

    let sections = parse_sections(&pre_run.join("switch1.txt")).unwrap();
    // The dash rule is part of the marker; it stays as the section's first line.
    assert_eq!(
        sections["show vlan brief"],
        vec!["-".repeat(80), "10  users  active".to_string()]
    );

    let report_path = write_compare_report("NET-1", &dirs, "2026-01-01_02-05").unwrap();

    let report_path = report_path.expect("both run folders exist");
    assert_eq!(report_path, dirs.compare.join("compare_2026-01-01_02-05.txt"));
    let content = fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("Ticket:           NET-1\n"));
    assert!(content.contains("Device/File: switch1.txt"));
    assert!(content.contains("Command: show vlan brief"));
    assert!(content.contains("Differences detected.\n\n+ 20  voice  active\n"));
    assert!(!content.contains("No meaningful changes detected."));
}

#[test]
fn compare_report_uses_the_latest_run_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = ticket_dirs_in(tmp.path(), "NET-2").unwrap();
    for run in ["precheck_2026-01-01_00-00", "precheck_2026-01-02_00-00"] {
        let folder = dirs.precheck.join(run);
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("switch1.txt"), CAPTURE.replace("users", run)).unwrap();
    }
    let post_run = dirs.postcheck.join("postcheck_2026-01-02_02-00");
    fs::create_dir_all(&post_run).unwrap();
    fs::write(post_run.join("switch1.txt"), CAPTURE).unwrap();

    let report_path = write_compare_report("NET-2", &dirs, "2026-01-02_02-05")
        .unwrap()
        .unwrap();
    let content = fs::read_to_string(report_path).unwrap();
    assert!(content.contains("- 10  precheck_2026-01-02_00-00  active\n+ 10  users  active\n"));
    assert!(!content.contains("precheck_2026-01-01_00-00  active"));
}

#[test]
fn compare_report_skips_without_precheck() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = ticket_dirs_in(tmp.path(), "NET-1").unwrap();

    assert_eq!(write_compare_report("NET-1", &dirs, "2026-01-01_00-00").unwrap(), None);

    // A precheck without a postcheck is skipped the same way.
    fs::create_dir_all(dirs.precheck.join("precheck_2026-01-01_00-00")).unwrap();
    assert_eq!(write_compare_report("NET-1", &dirs, "2026-01-01_00-00").unwrap(), None);
    assert!(
        !dirs.compare.exists(),
        "nothing is written when a run folder is missing"
    );
}

#[test]
fn unchanged_device_reports_no_meaningful_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let pre = tmp.path().join("pre");
    let post = tmp.path().join("post");
    fs::create_dir_all(&pre).unwrap();
    fs::create_dir_all(&post).unwrap();
    let capture = "Hostname: sw\nGenerated: 2026-01-01 00:00:00\n\n### show version ###\n--------------------------------------------------------------------------------\nUptime: 1 day\nArista\n";
    fs::write(pre.join("sw.txt"), capture).unwrap();
    fs::write(
        post.join("sw.txt"),
        capture.replace("1 day", "2 days").replace("00:00:00", "02:00:00"),
    )
    .unwrap();

    let report = compare_folders(tmp.path(), "NET-3", &pre, &post).unwrap();
    assert!(report.ends_with("Device/File: sw.txt\n================================================================================\n\nNo meaningful changes detected.\n"));
    assert!(!report.contains("Command:"));
}

/// The bundled demo, byte for byte. The Python demo copies the
/// captures under `reports/`; here they sit under the crate's
/// `fixtures/`, so the fixtures folder is passed as the root with the
/// same folder names below it. Nothing depends on the working directory
/// or the environment.
#[test]
fn fixture_report_matches_the_python_tool() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let pre = fixture("Precheck/precheck_2026-04-14_08-48");
    let post = fixture("Postcheck/postcheck_2026-04-14_10-42");
    let got = compare_folders(&root, "NET-DEMO", &pre, &post)
        .unwrap()
        .replace("Folder:  NET-DEMO/", "Folder:  reports/NET-DEMO/")
        .replace("Folder: NET-DEMO/", "Folder: reports/NET-DEMO/");
    let expected = fs::read_to_string(fixture("expected/compare.txt"))
        .unwrap()
        .replace("\r\n", "\n");

    assert!(expected.contains("Precheck Folder:  reports/NET-DEMO/Precheck/precheck_2026-04-14_08-48\n"));
    assert_eq!(got, expected);
}
