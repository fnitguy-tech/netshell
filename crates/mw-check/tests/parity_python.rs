//! Byte-for-byte parity with the Python tool on the paths the bundled
//! demo doesn't reach: failed, missing, and new devices, a stale or
//! interrupted baseline, and the diff size cap.
//!
//! The expected files were written by prepost-check under Python 3.12
//! (see `fixtures/parity/README.md`). Every path is built from the
//! crate folder, so nothing depends on the working directory or the
//! environment.

use std::fs;
use std::path::{Path, PathBuf};

use mw_check::analysis::analyze;
use mw_check::capture;
use mw_check::difflib::{FANCY_REPLACE_MAX_PAIRS, ndiff};
use mw_check::report::render_html_at;
use mw_check::textcompare::{action_required_line, compare_folders, console_lines};

fn parity() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join("parity")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        // Windows checkouts may carry CRLF; the comparison is on content.
        .replace("\r\n", "\n")
}

fn assert_same(got: &str, expected: &str, what: &str) {
    if got == expected {
        return;
    }

    let first = got.lines().zip(expected.lines()).position(|(a, b)| a != b);
    panic!(
        "{what} differs from the Python output; first differing line: {:?} (lengths {} and {})",
        first.map(|index| (index + 1, got.lines().nth(index), expected.lines().nth(index))),
        got.len(),
        expected.len()
    );
}

/// Both reports for one ticket under `fixtures/parity/reports/`, and
/// the console lines, against what Python wrote for the same folders.
fn check_ticket(ticket: &str, pre_name: &str, post_name: &str) {
    let root = parity();
    let base = root.join("reports").join(ticket);
    let pre = base.join("Precheck").join(pre_name);
    let post = base.join("Postcheck").join(post_name);
    let compare = base.join("Compare");

    let expected_text = read(&compare.join("compare_2026-04-14_10-45-00.txt"));
    let text = compare_folders(&root, ticket, &pre, &post).unwrap();
    assert_same(&text, &expected_text, &format!("{ticket} text report"));

    let expected_html = read(&compare.join("compare_2026-04-14_10-45-00.html"));
    // The footer carries the generation time; take it from the fixture.
    let generated = expected_html
        .lines()
        .find_map(|line| line.trim().strip_prefix("Generated "))
        .and_then(|rest| rest.split(" | ").next())
        .expect("fixture footer");
    let analysis = analyze(&pre, &post, None).unwrap();
    let html = render_html_at(&root, ticket, &pre, &post, &analysis, None, generated);
    assert_same(&html, &expected_html, &format!("{ticket} HTML report"));

    // What `mw after` prints, then what `mw report` prints.
    let (warnings, notes) = capture::baseline_warnings(&pre, &post);
    let (_common, problems) = capture::device_problems(&pre, &post).unwrap();
    let names: Vec<&str> = problems.iter().map(|problem| problem.name.as_str()).collect();
    let subjects: Vec<&str> = analysis
        .device_problems
        .iter()
        .map(|finding| finding.subject[0].as_str())
        .collect();

    let mut printed = console_lines(&warnings, &notes);
    printed.push(action_required_line(&names));
    printed.push(format!(
        "Compare report created: reports/{ticket}/Compare/compare_2026-04-14_10-45-00.txt"
    ));
    printed.extend(console_lines(&analysis.warnings, &notes));
    printed.push(action_required_line(&subjects));
    printed.push("HTML comparison report created.".to_string());
    printed.push(format!(
        "Created: reports/{ticket}/Compare/compare_2026-04-14_10-45-00.html"
    ));
    assert_same(
        &format!("{}\n", printed.join("\n")),
        &read(&compare.join("console.txt")),
        &format!("{ticket} console output"),
    );
}

#[test]
fn a_failed_a_missing_and_a_new_device_match_the_python_reports() {
    check_ticket(
        "NET-FAIL",
        "precheck_2026-04-14_08-48-05",
        "postcheck_2026-04-14_10-42-10",
    );

    // The scenario is what it claims to be.
    let html = read(&parity().join("reports/NET-FAIL/Compare/compare_2026-04-14_10-45-00.html"));
    assert!(html.contains("<div class=\"value health-action-required\">Action Required</div>"));
    assert!(html.contains("Devices Not Verified"));
    assert!(html.contains("Device unreachable after the change"));
    assert!(html.contains("Device missing after the change"));
    assert!(html.contains("Device only in the after capture"));
    assert!(html.contains("<div class=\"label\">Devices Checked</div><div class=\"value\">4</div>"));
}

#[test]
fn a_stale_interrupted_baseline_matches_the_python_reports() {
    check_ticket(
        "NET-STALE",
        "precheck_2026-04-14_10-40-00",
        "postcheck_2026-04-14_08-50-00",
    );

    let text = read(&parity().join("reports/NET-STALE/Compare/compare_2026-04-14_10-45-00.txt"));
    assert!(text.contains("WARNING: The before capture is newer than the after capture."));
    assert!(text.contains("didn't finish"));
    assert!(text.contains("! V6 (2001:db8::5): Device unreachable after the change"));
    assert!(text.contains("! 10.0.0.9: Device not attempted after the change"));
}

fn lines(path: &Path) -> Vec<String> {
    read(path).lines().map(str::to_string).collect()
}

#[test]
fn replaced_blocks_at_and_over_the_cap_match_python() {
    let folder = parity().join("ndiff_cap");

    // (case, old lines, new lines, is it over the cap)
    for (case, old, new, over) in [
        ("at", 200, 200, false),
        ("over", 200, 201, true),
        ("longer_old", 300, 200, true),
    ] {
        assert_eq!(old * new > FANCY_REPLACE_MAX_PAIRS, over, "{case}");

        let a = lines(&folder.join(format!("{case}_a.txt")));
        let b = lines(&folder.join(format!("{case}_b.txt")));
        assert_eq!((a.len(), b.len()), (old + 2, new + 2), "{case}");

        let got = ndiff(&a, &b);
        let expected = lines(&folder.join(format!("{case}_expected.txt")));
        assert_eq!(got.len(), expected.len(), "{case}");
        for (number, (ours, theirs)) in got.iter().zip(&expected).enumerate() {
            assert_eq!(ours, theirs, "{case}: line {}", number + 1);
        }
    }
}
