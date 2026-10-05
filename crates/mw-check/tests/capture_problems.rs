//! Capture folders: section headers, failed and missing devices, and
//! the checks on whether a pair of folders can be trusted.
//!
//! Port of the Python `tests/test_captures.py`. What the two commands
//! print is checked through the same functions that build those lines.

use std::fs;
use std::path::{Path, PathBuf};

use mw_check::analysis::{Impact, analyze};
use mw_check::capture::{
    self, FAILED_FIRST_LINE, NEWER_BASELINE_WARNING, NOT_ATTEMPTED_FIRST_LINE, RunCounts, SECTION_RULE,
};
use mw_check::layout::{TicketDirs, ticket_dirs_in};
use mw_check::report::build_html_report;
use mw_check::textcompare::{self, action_required_line, console_lines, write_compare_report};

const BGP_ROW: &str = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Estab 100 98";

fn capture_text(hostname: &str, address: &str, config_lines: &[&str]) -> String {
    format!(
        "Hostname: {hostname}\nIP Address: {address}\nGenerated: 2026-01-01 00:00:00\n{}\n\
         \n\n### show ip bgp summary ###\n{SECTION_RULE}\n{BGP_ROW}\n\
         \n\n### show running-config ###\n{SECTION_RULE}\n{}\n",
        "=".repeat(80),
        config_lines.join("\n")
    )
}

fn device(hostname: &str, address: &str) -> String {
    capture_text(hostname, address, &["hostname x"])
}

struct Folders {
    _tmp: tempfile::TempDir,
    pre: PathBuf,
    post: PathBuf,
    dirs: TicketDirs,
}

fn folders(pre: &str, post: &str, complete: bool) -> Folders {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = ticket_dirs_in(tmp.path(), "NET-1").unwrap();
    let pre_run = dirs.precheck.join(pre);
    let post_run = dirs.postcheck.join(post);
    fs::create_dir_all(&pre_run).unwrap();
    fs::create_dir_all(&post_run).unwrap();

    if complete {
        let counts = RunCounts {
            devices: 1,
            ..RunCounts::default()
        };
        capture::write_complete_marker(&pre_run, "precheck", counts).unwrap();
        capture::write_complete_marker(&post_run, "postcheck", counts).unwrap();
    }

    Folders {
        _tmp: tmp,
        pre: pre_run,
        post: post_run,
        dirs,
    }
}

fn default_folders() -> Folders {
    folders("precheck_2026-01-01_00-00", "postcheck_2026-01-01_02-00", true)
}

/// Both reports, as written to disk: `(text, html)`.
fn build_both(dirs: &TicketDirs) -> (String, String) {
    let text_path = write_compare_report("NET-1", dirs, "2026-01-01_02-05-00")
        .unwrap()
        .unwrap();
    let html_path = build_html_report("NET-1", dirs, "2026-01-01_02-05-00", None, None)
        .unwrap()
        .unwrap();

    (
        fs::read_to_string(text_path).unwrap(),
        fs::read_to_string(html_path).unwrap(),
    )
}

/// What both commands print for a pair of folders.
fn console(pre: &Path, post: &Path) -> String {
    let (warnings, notes) = capture::baseline_warnings(pre, post);
    let (_common, problems) = capture::device_problems(pre, post).unwrap();
    let mut lines = console_lines(&warnings, &notes);

    if !problems.is_empty() {
        let names: Vec<&str> = problems.iter().map(|problem| problem.name.as_str()).collect();
        lines.push(action_required_line(&names));
    }

    lines.join("\n")
}

fn index_of(haystack: &str, needle: &str) -> usize {
    haystack.find(needle).unwrap_or_else(|| panic!("{needle:?} not found"))
}

// --- section headers ----------------------------------------------------

#[test]
fn a_banner_line_inside_a_config_does_not_start_a_section() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("SW-1.txt");
    let config = [
        "hostname SW-1",
        "banner login",
        "### AUTHORIZED USE ONLY ###",
        "EOF",
        "router bgp 65001",
    ];
    fs::write(&path, capture_text("SW-1", "10.0.0.1", &config)).unwrap();

    for sections in [
        capture::parse_sections(&path).unwrap(),
        textcompare::parse_sections(&path).unwrap(),
    ] {
        assert_eq!(
            sections.keys().collect::<Vec<_>>(),
            ["HEADER", "show ip bgp summary", "show running-config"]
        );
        let config = &sections["show running-config"];
        assert_eq!(config[0], SECTION_RULE);
        assert!(config.iter().any(|line| line == "### AUTHORIZED USE ONLY ###"));
        assert!(config.iter().any(|line| line == "router bgp 65001"));
    }
}

// --- failed and missing devices -----------------------------------------

#[test]
fn a_device_unreachable_after_the_change_is_loud_in_both_reports() {
    let run = default_folders();
    fs::write(run.pre.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();
    fs::write(run.pre.join("SW-2.txt"), device("SW-2", "10.0.0.6")).unwrap();
    fs::write(run.post.join("SW-2.txt"), device("SW-2", "10.0.0.6")).unwrap();
    capture::write_failed(
        &run.post,
        "10.0.0.5",
        FAILED_FIRST_LINE,
        "TCP connection to device failed.\n\nDevice settings: arista_eos 10.0.0.5:22\n",
    )
    .unwrap();

    let analysis = analyze(&run.pre, &run.post, None).unwrap();
    let (text, page) = build_both(&run.dirs);

    // Without the fix: SW-2 is unchanged, SW-1 vanishes, verdict "Stable".
    assert_eq!(analysis.window_totals.get(Impact::ActionRequired), 1);
    assert_eq!(analysis.common_files, ["SW-2.txt"]);
    assert_eq!(analysis.device_reports[0].file_name, "SW-1.txt");

    assert!(page.contains("<div class=\"value health-action-required\">Action Required</div>"));
    assert!(page.contains("<div class=\"label\">Devices Checked</div><div class=\"value\">2</div>"));
    assert!(page.contains("Devices Not Verified"));
    assert!(page.contains("Device unreachable after the change"));
    assert!(page.contains("TCP connection to device failed."));
    assert!(page.contains("Device settings: arista_eos 10.0.0.5:22"));
    assert!(page.contains("1 device(s) couldn&#x27;t be verified"));
    // At the top: before the summary cards.
    assert!(index_of(&page, "id=\"device-problems\"") < index_of(&page, "<div class=\"cards\">"));

    assert!(text.contains("ACTION REQUIRED: 1 device(s) could not be verified"));
    assert!(text.contains("! SW-1 (10.0.0.5): Device unreachable after the change"));
    assert!(text.contains("    | TCP connection to device failed."));
    assert!(index_of(&text, "ACTION REQUIRED") < index_of(&text, "Device/File: SW-2.txt"));

    assert!(console(&run.pre, &run.post).contains("ACTION REQUIRED: 1 device(s) could not be verified: SW-1"));
}

#[test]
fn every_kind_of_missing_or_failed_device_is_reported() {
    let run = default_folders();
    fs::write(run.pre.join("GONE.txt"), device("GONE", "10.0.0.1")).unwrap();
    fs::write(run.post.join("NEW.txt"), device("NEW", "10.0.0.2")).unwrap();
    fs::write(run.post.join("LATE.txt"), device("LATE", "10.0.0.3")).unwrap();
    capture::write_failed(&run.pre, "10.0.0.3", FAILED_FIRST_LINE, "timed out\n").unwrap();
    capture::write_failed(&run.pre, "10.0.0.4", FAILED_FIRST_LINE, "timed out\n").unwrap();
    capture::write_failed(&run.post, "10.0.0.4", FAILED_FIRST_LINE, "timed out again\n").unwrap();
    capture::write_failed(&run.post, "10.0.0.9", NOT_ATTEMPTED_FIRST_LINE, "Not tried.\n").unwrap();

    let (common, problems) = capture::device_problems(&run.pre, &run.post).unwrap();
    let mut titles: Vec<(&str, &str)> = problems
        .iter()
        .map(|problem| (problem.name.as_str(), problem.title.as_str()))
        .collect();
    titles.sort();

    assert!(common.is_empty());
    assert_eq!(
        titles,
        [
            ("10.0.0.4", "Device unreachable before and after the change"),
            ("10.0.0.9", "Device not attempted after the change"),
            ("GONE", "Device missing after the change"),
            ("LATE", "Device unreachable before the change"),
            ("NEW", "Device only in the after capture"),
        ]
    );

    let analysis = analyze(&run.pre, &run.post, None).unwrap();
    assert_eq!(analysis.window_totals.get(Impact::ActionRequired), 5);
    assert_eq!(analysis.devices_with_findings, 5);
    assert!(
        analysis
            .device_problems
            .iter()
            .all(|finding| finding.impact == Impact::ActionRequired)
    );
}

#[test]
fn with_no_problem_devices_nothing_is_added() {
    let run = default_folders();
    fs::write(run.pre.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();
    fs::write(run.post.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();

    let (text, page) = build_both(&run.dirs);
    let printed = console(&run.pre, &run.post);

    assert!(!page.contains("Devices Not Verified"));
    assert!(!format!("{text}{printed}").contains("ACTION REQUIRED"));
    assert!(!format!("{text}{printed}").contains("WARNING"));
    assert!(!page.contains("Warning</h2>"));
    assert!(page.contains("<div class=\"value health-stable\">Stable</div>"));
}

// --- baseline sanity ----------------------------------------------------

#[test]
fn a_before_capture_newer_than_the_after_capture_is_called_out() {
    let run = folders("precheck_2026-01-01_10-40-00", "postcheck_2026-01-01_08-50-00", true);
    fs::write(run.pre.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();
    fs::write(run.post.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();

    let (text, page) = build_both(&run.dirs);
    let warning = NEWER_BASELINE_WARNING;
    assert_eq!(
        warning,
        "The before capture is newer than the after capture. Did you run before again by mistake?"
    );

    assert!(text.contains(&format!("WARNING: {warning}")));
    assert!(index_of(&text, "WARNING") < index_of(&text, "File Summary"));
    assert!(page.contains(&format!("<h2>Warning</h2><p>{warning}</p>")));
    assert!(index_of(&page, "<h2>Warning</h2>") < index_of(&page, "<div class=\"cards\">"));
    assert!(console(&run.pre, &run.post).contains(&format!("WARNING: {warning}")));
}

#[test]
fn a_run_without_its_marker_is_an_interrupted_baseline() {
    let run = folders("precheck_2026-01-01_00-00-07", "postcheck_2026-01-01_02-00", false);
    capture::write_complete_marker(&run.post, "postcheck", RunCounts::default()).unwrap();
    fs::write(run.pre.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();
    fs::write(run.post.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();

    let (text, page) = build_both(&run.dirs);

    assert!(page.contains("The before capture (precheck_2026-01-01_00-00-07) didn&#x27;t finish."));
    assert!(text.contains("The before capture (precheck_2026-01-01_00-00-07) didn't finish."));
    assert!(console(&run.pre, &run.post).contains("didn't finish"));

    // The marker is not a device.
    assert!(page.contains("<div class=\"label\">Devices Checked</div><div class=\"value\">1</div>"));
    assert!(text.contains("Common files: 1"));
}

#[test]
fn an_older_folder_without_a_marker_still_compares_with_only_a_note() {
    // Minute-resolution names are what older versions (and the bundled
    // demo captures) use; they never had markers.
    let run = folders("precheck_2026-01-01_00-00", "postcheck_2026-01-01_02-00", false);
    fs::write(run.pre.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();
    fs::write(run.post.join("SW-1.txt"), device("SW-1", "10.0.0.5")).unwrap();

    let (text, page) = build_both(&run.dirs);
    let printed = console(&run.pre, &run.post);

    assert!(!text.contains("WARNING") && !page.contains("Warning</h2>"));
    assert!(printed.contains("Note: The before capture (precheck_2026-01-01_00-00) has no completion marker."));
    assert!(printed.contains("Note: The after capture (postcheck_2026-01-01_02-00) has no completion marker."));
    assert!(run.dirs.compare.join("compare_2026-01-01_02-05-00.html").exists());
}

#[test]
fn the_completion_marker_is_the_json_python_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let counts = RunCounts {
        devices: 8,
        captured: 7,
        incomplete: 0,
        failed: 1,
        not_attempted: 0,
    };
    capture::write_complete_marker(tmp.path(), "precheck", counts).unwrap();

    let text = fs::read_to_string(tmp.path().join(capture::COMPLETE_MARKER)).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "{");
    assert_eq!(lines[1], "  \"phase\": \"precheck\",");
    assert!(lines[2].starts_with("  \"finished\": \"20"), "{}", lines[2]);
    assert_eq!(
        &lines[3..],
        [
            "  \"devices\": 8,",
            "  \"captured\": 7,",
            "  \"incomplete\": 0,",
            "  \"failed\": 1,",
            "  \"not_attempted\": 0",
            "}"
        ]
    );
    assert!(text.ends_with("}\n"));
}
