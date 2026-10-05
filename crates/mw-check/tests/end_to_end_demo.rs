//! The whole analysis on the bundled fixtures, rendered and compared
//! against the HTML the Python tool produced from the same captures.
//!
//! Hermetic: the root that paths are shown relative to is passed in, so
//! the result doesn't depend on the working directory or on `MW_HOME`,
//! and the test can run in parallel with any other.

use std::path::Path;

use mw_check::analysis::analyze;
use mw_check::report::render_html_at;

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/NET-DEMO"))
}

#[test]
fn demo_analysis_renders_the_python_report() {
    let pre = fixtures().join("Precheck/precheck_2026-04-14_08-48");
    let post = fixtures().join("Postcheck/postcheck_2026-04-14_10-42");
    let analysis = analyze(&pre, &post, None).unwrap();

    // Windows checkouts may carry CRLF; the comparison is on content.
    let expected = std::fs::read_to_string(fixtures().join("expected/compare.html"))
        .unwrap()
        .replace("\r\n", "\n");
    // The footer carries the generation time; take it from the fixture.
    let generated = expected
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("Generated ")
                .map(|rest| rest.split(" | ").next().unwrap_or("").trim().to_string())
        })
        .unwrap_or_default();
    // The Python demo copies the captures under reports/; here they are
    // read from the fixtures directory. With fixtures/ as the root, only
    // the "reports/" prefix of the two folder labels differs.
    let root = fixtures().parent().unwrap();
    let html = render_html_at(root, "NET-DEMO", &pre, &post, &analysis, None, &generated)
        .replace("check: NET-DEMO/", "check: reports/NET-DEMO/");
    assert!(analysis.device_problems.is_empty() && analysis.warnings.is_empty());

    if html != expected {
        let first_diff = html.lines().zip(expected.lines()).position(|(a, b)| a != b);
        panic!(
            "report differs from the Python fixture; first differing line: {:?}",
            first_diff.map(|i| (i + 1, html.lines().nth(i), expected.lines().nth(i)))
        );
    }
}
