//! The bundled demo, rebuilt by hand into the analysis the Python tool
//! produced for it, must render byte for byte into the Python tool's
//! report (`fixtures/NET-DEMO/expected/compare.html`), footer
//! timestamp aside. The interpreted findings and config changes are
//! transcribed from that page; the raw diff lines (bulk evidence) are
//! read back out of it.

use std::collections::BTreeMap;
use std::path::Path;

use mw_check::analysis::{
    Analysis, Classification, ClassificationCounts, DeviceReport, DiffKind, DiffLine, Field, Finding, Impact,
    ImpactCounts,
};
use mw_check::report::render_html_at;

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/NET-DEMO/expected/compare.html"
));

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}

/// The fixture's card for one device.
fn fixture_device(device_id: &str) -> &'static str {
    let marker = format!("<div id=\"device-{device_id}\" class=\"device\">");
    let start = FIXTURE
        .find(&marker)
        .unwrap_or_else(|| panic!("no device {device_id:?}"));
    let card = &FIXTURE[start + marker.len()..];
    let end = card.find("class=\"device\">").unwrap_or(card.len());
    &card[..end]
}

/// The diff lines of one collapsible raw-diff section of a device's
/// card in the fixture.
fn fixture_diff(device_id: &str, label: &str) -> Vec<DiffLine> {
    let card = fixture_device(device_id);
    let marker = format!("<summary>{label}</summary>");
    let start = card
        .find(&marker)
        .unwrap_or_else(|| panic!("no section {label:?} on {device_id:?}"));
    let block = &card[start..];
    let end = block.find("</details>").unwrap();
    let prefixes = [
        ("<div class=\"added\">+ ", DiffKind::Added),
        ("<div class=\"removed\">- ", DiffKind::Removed),
        ("<div class=\"context\">  ", DiffKind::Context),
    ];
    let mut lines = Vec::new();
    for line in block[..end].lines() {
        for (prefix, kind) in prefixes {
            if let Some(rest) = line.strip_prefix(prefix) {
                let text = rest.strip_suffix("</div>").unwrap();
                lines.push(DiffLine {
                    kind,
                    text: unescape(text),
                });
            }
        }
    }
    assert!(!lines.is_empty(), "section {label:?} has no diff lines");
    lines
}

fn diffs(device_id: &str, sections: &[(&str, &str)]) -> BTreeMap<String, Vec<DiffLine>> {
    sections
        .iter()
        .map(|(command, label)| (command.to_string(), fixture_diff(device_id, label)))
        .collect()
}

fn bgp_finding(
    impact: Impact,
    title: &str,
    peer: (&str, &str, &str),
    fields: [(&str, &str); 4],
    summary: &str,
    evidence: &str,
) -> Finding {
    let mut finding = Finding::new(Classification::Protocol, "BGP", impact, title);
    finding.subject = vec![peer.0.to_string(), peer.1.to_string(), format!("AS{}", peer.2)];
    let labels = ["State", "Prefixes Received", "Prefixes Accepted", "Up/Down"];
    finding.fields = labels
        .iter()
        .zip(fields.iter())
        .map(|(label, (before, after))| Field::new(*label, *before, *after))
        .collect();
    finding.summary = summary.to_string();
    finding.evidence = evidence.to_string();
    finding
}

fn report(
    hostname: &str,
    findings: Vec<Finding>,
    config_changes: Vec<DiffLine>,
    diffs: BTreeMap<String, Vec<DiffLine>>,
    counts: (usize, usize, usize),
) -> DeviceReport {
    let (findings_count, attention_count, impact_score) = counts;
    let stable_count = findings.iter().filter(|f| f.impact == Impact::Stable).count();
    DeviceReport {
        file_name: format!("{hostname}.txt"),
        hostname: hostname.to_string(),
        device_id: hostname.to_lowercase(),
        findings,
        config_changes,
        diffs,
        raw_categories: ClassificationCounts::default(),
        findings_count,
        attention_count,
        action_count: 0,
        changed_count: 0,
        stable_count,
        impact_score,
    }
}

fn demo_analysis() -> Analysis {
    let site_a_sw_1 = report(
        "SITE-A-SW-1",
        vec![
            bgp_finding(
                Impact::Stable,
                "BGP Peer Added",
                ("ISP-B", "198.51.100.9", "64497"),
                [
                    ("Not Present", "Estab"),
                    ("0", "815"),
                    ("0", "815"),
                    ("Not Present", "00:52:40"),
                ],
                "This peer isn't in the precheck and shows up in the postcheck. It's new since the window started.",
                "show ip bgp summary",
            ),
            bgp_finding(
                Impact::Attention,
                "BGP Peer Shut Down",
                ("ISP-A", "198.51.100.1", "64496"),
                [
                    ("Estab", "Idle(Admin)"),
                    ("812", "0"),
                    ("812", "0"),
                    ("21d04h", "00:01:12"),
                ],
                "Someone shut this peer down during the window. It's idle on purpose, not broken.",
                "show ip bgp summary + related BGP shutdown/no shutdown config",
            ),
        ],
        vec![
            DiffLine::context("interface Ethernet49/1"),
            DiffLine::added("   shutdown"),
            DiffLine::context("interface Ethernet50/1"),
            DiffLine::removed("   shutdown"),
            DiffLine::context("router bgp 64500"),
            DiffLine::added("   neighbor 198.51.100.1 shutdown"),
            DiffLine::added("   neighbor 198.51.100.9 remote-as 64497"),
            DiffLine::added("   neighbor 198.51.100.9 description ISP-B"),
            DiffLine::added("   neighbor 198.51.100.9 route-map ISP-IN in"),
        ],
        diffs(
            "site-a-sw-1",
            &[
                ("show interfaces status", "show interfaces status"),
                ("show ip bgp summary", "show ip bgp summary"),
                ("show ip interface brief", "show ip interface brief"),
                ("show ip route", "show ip route - Large routing evidence"),
                ("show running-config", "show running-config"),
                ("show vlan brief", "show vlan brief"),
            ],
        ),
        (8, 1, 22),
    );

    let site_a_sw_2 = report(
        "SITE-A-SW-2",
        vec![bgp_finding(
            Impact::Changed,
            "BGP Prefix Count Changed",
            ("SITE-A-SW-1", "10.0.0.1", "64500"),
            [("Estab", "Estab"), ("812", "815"), ("812", "815"), ("34d11h", "34d11h")],
            "Prefix count changed by +3. That's normal if this window touched routing policy, communities, failover, or advertised routes.",
            "show ip bgp summary",
        )],
        vec![],
        diffs(
            "site-a-sw-2",
            &[
                ("show ip bgp summary", "show ip bgp summary"),
                ("show running-config", "show running-config"),
                ("show vlan brief", "show vlan brief"),
            ],
        ),
        (1, 0, 2),
    );

    let site_a_fw_1 = report(
        "SITE-A-FW-1",
        vec![],
        vec![],
        // No "show routing route" section: the demo's PAN-OS routes are
        // identical apart from the age column, which is normalized away, so
        // there is no evidence block to render.
        diffs("site-a-fw-1", &[("show config running", "show config running")]),
        (0, 0, 0),
    );

    let site_b_sw_1 = report("SITE-B-SW-1", vec![], vec![], BTreeMap::new(), (0, 0, 0));

    let mut by_classification = ClassificationCounts::default();
    for (classification, count) in [
        (Classification::Configuration, 9),
        (Classification::Protocol, 4),
        (Classification::Routing, 2),
        (Classification::Interface, 1),
        (Classification::Layer2, 2),
        (Classification::EvidenceOnly, 1),
    ] {
        by_classification.add(classification, count);
    }

    let mut impact_totals = ImpactCounts::default();
    impact_totals.add(Impact::Stable, 1);
    impact_totals.add(Impact::Changed, 7);
    impact_totals.add(Impact::Attention, 1);

    // The demo has no pair-symmetry findings, so the window carries all of it.
    let window_totals = impact_totals.clone();

    Analysis {
        common_files: ["SITE-A-FW-1", "SITE-A-SW-1", "SITE-A-SW-2", "SITE-B-SW-1"]
            .iter()
            .map(|h| format!("{h}.txt"))
            .collect(),
        device_reports: vec![site_a_sw_1, site_a_sw_2, site_a_fw_1, site_b_sw_1],
        pairs: vec![("SITE-A-SW-1".to_string(), "SITE-A-SW-2".to_string())],
        pair_findings: Vec::new(),
        total_findings_by_classification: by_classification,
        impact_totals,
        window_totals,
        symmetry_totals: ImpactCounts::default(),
        devices_with_findings: 2,
    }
}

/// The diff lines of one raw-diff section are read back out of the
/// fixture, so make sure that reader sees what a human sees.
#[test]
fn fixture_reader_keeps_signs_and_whitespace() {
    let lines = fixture_diff("site-a-sw-1", "show vlan brief");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].kind, DiffKind::Added);
    assert_eq!(lines[0].text, "240   ISP-B-TRANSIT                    active    Et50/1");

    let lines = fixture_diff("site-a-sw-1", "show ip route - Large routing evidence");
    assert_eq!(lines.len(), 6);
    assert_eq!(lines[0].kind, DiffKind::Removed);
    assert_eq!(
        lines[0].text,
        " B E      0.0.0.0/0 [20/0] via 198.51.100.1, Ethernet49/1"
    );
}

#[test]
fn demo_report_is_byte_identical_to_the_python_report() {
    let generated = FIXTURE
        .lines()
        .find_map(|line| line.trim().strip_prefix("Generated "))
        .and_then(|rest| rest.split(" | ").next())
        .expect("fixture footer");
    assert_eq!(generated.len(), "2026-10-02 16:47:40".len());

    let page = render_html_at(
        "NET-DEMO",
        Path::new("reports/NET-DEMO/Precheck/precheck_2026-04-14_08-48"),
        Path::new("reports/NET-DEMO/Postcheck/postcheck_2026-04-14_10-42"),
        &demo_analysis(),
        None,
        generated,
    );

    if page != FIXTURE {
        let expected: Vec<&str> = FIXTURE.lines().collect();
        let actual: Vec<&str> = page.lines().collect();
        for (number, (want, got)) in expected.iter().zip(actual.iter()).enumerate() {
            assert_eq!(want, got, "first difference at line {}", number + 1);
        }
        panic!(
            "same prefix, different length: fixture {} lines, rendered {} lines",
            expected.len(),
            actual.len()
        );
    }
}
