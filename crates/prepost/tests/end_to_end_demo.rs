//! The whole analysis on the bundled fixtures, rendered and compared
//! against the HTML the Python tool produced from the same captures.

use std::path::Path;

use prepost::analysis::analyze;
use prepost::expectations::load_expectations;
use prepost::report::render_html_at;

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/NET-DEMO"))
}

#[test]
fn demo_analysis_renders_the_python_report() {
    let pre = fixtures().join("Precheck/precheck_2026-04-14_08-48");
    let post = fixtures().join("Postcheck/postcheck_2026-04-14_10-42");
    let expectations = load_expectations(&fixtures().join("expectations.yml"), Some("NET-DEMO")).unwrap();
    let analysis = analyze(&pre, &post, None, Some(&expectations)).unwrap();

    let expected = std::fs::read_to_string(fixtures().join("expected/compare.html")).unwrap();
    // The footer carries the generation time; take it from the fixture.
    let generated = expected
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("Generated ")
                .map(|rest| rest.split(" | ").next().unwrap_or("").trim().to_string())
        })
        .unwrap_or_default();
    let html = render_html_at(
        "NET-DEMO",
        &pre,
        &post,
        &analysis,
        Some("docs/demo/NET-DEMO/expectations.yml"),
        &generated,
    )
    // The Python demo copies the captures under reports/; here they
    // are read from the fixtures directory. Only the path labels differ.
    .replace("fixtures/NET-DEMO/", "reports/NET-DEMO/");

    if html != expected {
        let out = std::env::temp_dir().join("prepost-demo-actual.html");
        std::fs::write(&out, &html).unwrap();
        let first_diff = html.lines().zip(expected.lines()).position(|(a, b)| a != b);
        panic!(
            "report differs from the Python fixture (actual written to {}); first differing line: {:?}",
            out.display(),
            first_diff.map(|i| (i + 1, html.lines().nth(i), expected.lines().nth(i)))
        );
    }
}
