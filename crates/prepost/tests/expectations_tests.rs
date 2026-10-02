//! Expected BGP prefix deltas. Port of the Python
//! `tests/test_expectations.py` (minus the end-to-end report checks).
//!
//! Every prefix-count change used to carry the same "this may be
//! expected when ..." hedge, and a caveat on everything is a caveat on
//! nothing. With an expectations file in play a matching delta is
//! Stable ("as planned"), a delta that differs from or has no
//! expectation is Attention, and an expected change that did not
//! happen is Attention too. Without a file, the old behaviour (Changed
//! + hedge) is kept.

use std::path::{Path, PathBuf};

use prepost::analysis::bgp::{PREFIX_DELTA_HEDGE, bgp_neighbor_findings};
use prepost::analysis::{Finding, Impact};
use prepost::analysis::{TITLE_AS_PLANNED, TITLE_DIFFERS, TITLE_NOT_MET, TITLE_UNEXPLAINED};
use prepost::capture::Sections;
use prepost::expectations::{Expectation, ExpectationsError, Expected, describe, for_device, load_expectations};

fn example_expectations() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/NET-DEMO/expectations.yml")
}

fn sections_for(count: u32, name: &str, ip: &str) -> Sections {
    let mut sections = Sections::new();
    sections.insert(
        "show ip bgp summary".to_string(),
        vec![format!(
            "  {name}  {ip}  4 64497  213  201  0  0  5d02h  Estab  {count}  {count}"
        )],
    );
    sections
}

fn sections(count: u32) -> Sections {
    sections_for(count, "ISP-B", "198.51.100.9")
}

fn entry(peer: &str, expected: Expected) -> Expectation {
    Expectation {
        device: "SITE-A-SW-1".to_string(),
        peer: peer.to_string(),
        expected,
        note: String::new(),
    }
}

fn titles_and_impacts(findings: &[Finding]) -> Vec<(&str, Impact)> {
    findings.iter().map(|f| (f.title.as_str(), f.impact)).collect()
}

fn write(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("expectations.yml");
    std::fs::write(&path, body).unwrap();
    path
}

fn load_err(path: &Path, ticket: Option<&str>) -> String {
    match load_expectations(path, ticket) {
        Ok(entries) => panic!("expected an error, got {entries:?}"),
        Err(ExpectationsError(message)) => message,
    }
}

#[test]
fn load_expectations_example_file() {
    let entries = load_expectations(&example_expectations(), Some("NET-DEMO")).unwrap();

    assert_eq!(
        entries,
        [Expectation {
            device: "SITE-A-SW-2".to_string(),
            peer: "10.0.0.1".to_string(),
            expected: Expected::Delta(3),
            note: "SITE-A-SW-1 re-advertises the three ISP-B transit prefixes over iBGP".to_string(),
        }]
    );
}

#[test]
fn load_expectations_accepts_quoted_delta_and_absolute_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        &dir,
        "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: '+3'\n  - device: sw-1\n    peer: 10.0.0.1\n    expected_prefixes: 815\n",
    );

    let entries = load_expectations(&path, None).unwrap();

    assert_eq!(entries[0].expected, Expected::Delta(3));
    assert_eq!(entries[1].expected, Expected::Prefixes(815));
    assert_eq!(entries[1].note, "");
}

#[test]
fn load_expectations_accepts_negative_and_zero_deltas_and_trims_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        &dir,
        "expectations:\n  - device: ' sw-1 '\n    peer: ' ISP-B '\n    expected_delta: -200\n    note: ' trimmed '\n  - device: sw-1\n    peer: ISP-A\n    expected_delta: \"0\"\n    note: 7\n",
    );

    let entries = load_expectations(&path, None).unwrap();

    assert_eq!(entries[0].device, "sw-1");
    assert_eq!(entries[0].peer, "ISP-B");
    assert_eq!(entries[0].expected, Expected::Delta(-200));
    assert_eq!(entries[0].note, "trimmed");
    assert_eq!(entries[1].expected, Expected::Delta(0));
    assert_eq!(entries[1].note, "7");
}

#[test]
fn malformed_expectations_rejected() {
    let cases = [
        ("expectations: nope\n", "expected a top-level 'expectations' list."),
        ("ticket: NET-1\n", "expected a top-level 'expectations' list."),
        ("- device: sw-1\n", "expected a top-level 'expectations' list."),
        (
            "expectations:\n  - just a string\n",
            "expectations[0] must be a mapping.",
        ),
        (
            "expectations:\n  - peer: ISP-B\n    expected_delta: 3\n",
            "expectations[0] is missing 'device'.",
        ),
        (
            "expectations:\n  - device: sw-1\n    expected_delta: 3\n",
            "expectations[0] is missing 'peer'.",
        ),
        (
            "expectations:\n  - device: ''\n    peer: ISP-B\n    expected_delta: 3\n",
            "expectations[0] is missing 'device'.",
        ),
        (
            "expectations:\n  - device: 7\n    peer: ISP-B\n    expected_delta: 3\n",
            "expectations[0] is missing 'device'.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n",
            "expectations[0] needs exactly one of 'expected_delta' or 'expected_prefixes'.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: 3\n    expected_prefixes: 5\n",
            "expectations[0] needs exactly one of 'expected_delta' or 'expected_prefixes'.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: three\n",
            "expectations[0]: 'expected_delta' must be an integer.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_prefixes: true\n",
            "expectations[0]: 'expected_prefixes' must be an integer.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: 3.5\n",
            "expectations[0]: 'expected_delta' must be an integer.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: [3]\n",
            "expectations[0]: 'expected_delta' must be an integer.",
        ),
        (
            "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta:\n",
            "expectations[0]: 'expected_delta' must be an integer.",
        ),
        (
            "expectations:\n  - device: ok\n    peer: ISP-B\n    expected_delta: 3\n  - device: sw-1\n    peer: ISP-A\n",
            "expectations[1] needs exactly one of 'expected_delta' or 'expected_prefixes'.",
        ),
    ];

    for (body, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, body);
        let message = load_err(&path, None);
        assert_eq!(message, format!("{}: {expected}", path.display()), "body: {body:?}");
    }
}

#[test]
fn wrong_ticket_and_missing_file_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(&dir, "ticket: NET-1\nexpectations: []\n");

    assert_eq!(
        load_err(&path, Some("NET-2")),
        format!(
            "{}: file is for ticket NET-1, this report is for NET-2.",
            path.display()
        )
    );
    assert_eq!(load_expectations(&path, Some("net-1")).unwrap(), []);
    // No ticket to check against, or none in the file: accepted.
    assert_eq!(load_expectations(&path, None).unwrap(), []);
    assert_eq!(load_expectations(&path, Some("")).unwrap(), []);
    let untagged = write(&dir, "expectations: []\n");
    assert_eq!(load_expectations(&untagged, Some("NET-2")).unwrap(), []);

    let missing = dir.path().join("missing.yml");
    let message = load_err(&missing, None);
    assert!(message.starts_with(&format!("Expectations file not found: {}\n", missing.display())));
    assert!(message.contains("for the format."));
}

#[test]
fn for_device_is_case_insensitive() {
    let entries = [entry("x", Expected::Delta(1))];

    assert_eq!(for_device(&entries, "site-a-sw-1"), [&entries[0]]);
    assert!(for_device(&entries, "SITE-A-SW-2").is_empty());
}

#[test]
fn describe_reads_like_english() {
    assert_eq!(describe(&entry("x", Expected::Delta(3))), "a change of +3");
    assert_eq!(describe(&entry("x", Expected::Delta(-200))), "a change of -200");
    assert_eq!(describe(&entry("x", Expected::Delta(0))), "a change of +0");
    assert_eq!(describe(&entry("x", Expected::Prefixes(815))), "815 prefixes received");
}

#[test]
fn no_file_keeps_the_hedge() {
    let findings = bgp_neighbor_findings(&sections(815), &sections(812), &[], None);

    assert_eq!(
        titles_and_impacts(&findings),
        [("BGP Prefix Count Changed", Impact::Changed)]
    );
    assert!(findings[0].summary.contains(PREFIX_DELTA_HEDGE));
    assert_eq!(
        findings[0].summary,
        format!("Prefix count changed by -3. {PREFIX_DELTA_HEDGE}")
    );
    assert_eq!(findings[0].category, "BGP prefixes");
}

#[test]
fn matching_delta_is_stable_as_planned() {
    let expectations = [entry("ISP-B", Expected::Delta(3))];
    let findings = bgp_neighbor_findings(&sections(812), &sections(815), &[], Some(&expectations));

    assert_eq!(titles_and_impacts(&findings), [(TITLE_AS_PLANNED, Impact::Stable)]);
    assert!(findings[0].summary.contains("+3"));
    assert!(!findings[0].summary.contains(PREFIX_DELTA_HEDGE));
    assert_eq!(
        findings[0].summary,
        "Prefix count changed by +3, matching the expectation of a change of +3."
    );
}

#[test]
fn matching_absolute_count_by_ip_is_stable_with_note() {
    let mut expectation = entry("198.51.100.9", Expected::Prefixes(815));
    expectation.note = "full table minus bogons".to_string();

    let findings = bgp_neighbor_findings(&sections(812), &sections(815), &[], Some(&[expectation]));

    assert_eq!(findings[0].title, TITLE_AS_PLANNED);
    assert!(findings[0].summary.contains("Note: full table minus bogons"));
    assert!(
        findings[0]
            .summary
            .contains("matching the expectation of 815 prefixes received.")
    );
}

#[test]
fn delta_that_differs_from_plan_is_attention() {
    let expectations = [entry("ISP-B", Expected::Delta(3))];
    let findings = bgp_neighbor_findings(&sections(812), &sections(814), &[], Some(&expectations));

    assert_eq!(titles_and_impacts(&findings), [(TITLE_DIFFERS, Impact::Attention)]);
    assert!(
        findings[0]
            .summary
            .contains("changed by +2; the expectation was a change of +3")
    );
}

#[test]
fn delta_with_no_entry_is_unexplained_attention() {
    // A file exists but covers a different peer: this delta is unexplained.
    let expectations = [entry("ISP-A", Expected::Delta(3))];
    let findings = bgp_neighbor_findings(&sections(812), &sections(815), &[], Some(&expectations));

    assert_eq!(titles_and_impacts(&findings), [(TITLE_UNEXPLAINED, Impact::Attention)]);
    assert!(!findings[0].summary.contains(PREFIX_DELTA_HEDGE));
    assert_eq!(
        findings[0].summary,
        "Prefix count changed by +3 and no entry in the expectations file covers this peer."
    );

    // An empty list (file present, nothing for this device) is the same.
    let findings = bgp_neighbor_findings(&sections(812), &sections(815), &[], Some(&[]));
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(findings[0].title, TITLE_UNEXPLAINED);
}

#[test]
fn expected_change_that_did_not_happen_is_attention() {
    let expectations = [entry("ISP-B", Expected::Delta(3))];
    let findings = bgp_neighbor_findings(&sections(812), &sections(812), &[], Some(&expectations));

    assert_eq!(titles_and_impacts(&findings), [(TITLE_NOT_MET, Impact::Attention)]);
    assert_eq!(
        findings[0].summary,
        "The expectation was a change of +3, but the prefix count did not change (812 received in both captures)."
    );

    // An expectation of "no change" or of the count it already has is met.
    let none = [entry("ISP-B", Expected::Delta(0))];
    assert!(bgp_neighbor_findings(&sections(812), &sections(812), &[], Some(&none)).is_empty());
    let same = [entry("ISP-B", Expected::Prefixes(812))];
    assert!(bgp_neighbor_findings(&sections(812), &sections(812), &[], Some(&same)).is_empty());

    // Nothing moved and no entry names this peer: nothing to say.
    let other = [entry("ISP-A", Expected::Delta(3))];
    assert!(bgp_neighbor_findings(&sections(812), &sections(812), &[], Some(&other)).is_empty());
    assert!(bgp_neighbor_findings(&sections(812), &sections(812), &[], Some(&[])).is_empty());
}

#[test]
fn state_change_outranks_the_expectation() {
    let mut idle = Sections::new();
    idle.insert(
        "show ip bgp summary".to_string(),
        vec!["  ISP-B  198.51.100.9  4 64497  213  201  0  0  00:01:12  Idle(Admin)".to_string()],
    );
    let expectations = [entry("ISP-B", Expected::Delta(3))];

    let findings = bgp_neighbor_findings(&sections(812), &idle, &[], Some(&expectations));

    assert_eq!(
        findings.iter().map(|f| f.title.as_str()).collect::<Vec<_>>(),
        ["BGP Peer Administratively Disabled"]
    );
}

#[test]
fn reset_outranks_the_expectation() {
    let mut reset = sections(815);
    reset["show ip bgp summary"][0] = reset["show ip bgp summary"][0].replace("5d02h", "00:00:10");
    let expectations = [entry("ISP-B", Expected::Delta(3))];

    let findings = bgp_neighbor_findings(&sections(812), &reset, &[], Some(&expectations));

    assert_eq!(
        findings.iter().map(|f| f.title.as_str()).collect::<Vec<_>>(),
        ["BGP Session Reset"]
    );
}
