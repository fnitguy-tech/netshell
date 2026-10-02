//! Rendering tests for the HTML report, on analyses built by hand (the
//! renderer takes plain structs, so no captures are needed). The last
//! group ports the rendering assertions of the Python test-suite.

use std::collections::BTreeMap;
use std::path::Path;

use mw_check::analysis::{
    Analysis, Classification, ClassificationCounts, DeviceReport, DiffKind, DiffLine, Field, Finding, Impact,
    ImpactCounts,
};
use mw_check::capture::safe_id;
use mw_check::layout::ticket_dirs_under;
use mw_check::report::{
    CHART_JS_SCRIPT_TAG, build_html_report, escape, render_diff_line, render_finding, render_html, render_html_at,
};

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/NET-DEMO/expected/compare.html"
));

const PRE: &str = "reports/NET-1/Precheck/precheck_2026-01-01_00-00";
const POST: &str = "reports/NET-1/Postcheck/postcheck_2026-01-01_02-00";

#[allow(clippy::too_many_arguments)]
fn finding(
    classification: Classification,
    category: &str,
    impact: Impact,
    title: &str,
    subject: &[&str],
    fields: &[(&str, &str, &str)],
    summary: &str,
    evidence: &str,
) -> Finding {
    let mut finding = Finding::new(classification, category, impact, title);
    finding.subject = subject.iter().map(|s| s.to_string()).collect();
    finding.fields = fields.iter().map(|(l, b, a)| Field::new(*l, *b, *a)).collect();
    finding.summary = summary.to_string();
    finding.evidence = evidence.to_string();
    finding
}

/// The shape `htmlreport.bgp_finding()` produces.
fn bgp_finding(
    impact: Impact,
    title: &str,
    peer: (&str, &str, &str),
    fields: [(&str, &str); 4],
    summary: &str,
) -> Finding {
    let labels = ["State", "Prefixes Received", "Prefixes Accepted", "Up/Down"];
    let fields: Vec<(&str, &str, &str)> = labels
        .iter()
        .zip(fields.iter())
        .map(|(label, (before, after))| (*label, *before, *after))
        .collect();
    let as_number = format!("AS{}", peer.2);
    finding(
        Classification::Protocol,
        "BGP",
        impact,
        title,
        &[peer.0, peer.1, &as_number],
        &fields,
        summary,
        "show ip bgp summary",
    )
}

/// The shape `htmlreport.pair_finding()` produces.
fn pair_finding(
    title: &str,
    pair: (&str, &str),
    subject: &[&str],
    fields: &[(&str, &str, &str)],
    summary: &str,
) -> Finding {
    let label = format!("{} vs {}", pair.0, pair.1);
    let mut spans = vec![label.as_str()];
    spans.extend_from_slice(subject);
    let mut finding = finding(
        Classification::Routing,
        "Pair symmetry",
        Impact::Attention,
        title,
        &spans,
        fields,
        summary,
        "show ip prefix-list",
    );
    finding.arrow = "vs".to_string();
    finding.devices = vec![pair.0.to_string(), pair.1.to_string()];
    finding
}

/// One device report with the counts and score `analyze()` would give it.
fn device(
    hostname: &str,
    findings: Vec<Finding>,
    config_changes: Vec<DiffLine>,
    diffs: BTreeMap<String, Vec<DiffLine>>,
) -> DeviceReport {
    let count = |impact| findings.iter().filter(|f| f.impact == impact).count();
    let attention_count = count(Impact::Attention);
    let action_count = count(Impact::ActionRequired);
    let changed_count = count(Impact::Changed);
    let stable_count = count(Impact::Stable);
    let config_change_count = config_changes.iter().filter(|l| l.kind != DiffKind::Context).count();

    DeviceReport {
        file_name: format!("{hostname}.txt"),
        hostname: hostname.to_string(),
        device_id: safe_id(hostname),
        findings_count: findings.len() + config_change_count,
        impact_score: action_count * 10
            + attention_count * 5
            + changed_count * 2
            + config_change_count * 2
            + stable_count,
        findings,
        config_changes,
        diffs,
        raw_categories: ClassificationCounts::default(),
        attention_count,
        action_count,
        changed_count,
        stable_count,
    }
}

/// Roll devices up the way `analyze()` does: pair findings count once,
/// config changes count as Changed / Configuration, devices sorted by
/// severity.
fn analysis(mut devices: Vec<DeviceReport>) -> Analysis {
    let mut impact_totals = ImpactCounts::default();
    let mut window_totals = ImpactCounts::default();
    let mut symmetry_totals = ImpactCounts::default();
    let mut by_classification = ClassificationCounts::default();
    let mut devices_with_findings = 0;

    for report in &devices {
        if report.findings_count > 0 {
            devices_with_findings += 1;
        }
        for finding in &report.findings {
            if !finding.devices.is_empty() && finding.devices[0] != report.hostname {
                continue;
            }
            by_classification.add(finding.classification, 1);
            impact_totals.add(finding.impact, 1);

            if finding.category == mw_check::analysis::pairs::CATEGORY {
                symmetry_totals.add(finding.impact, 1);
            } else {
                window_totals.add(finding.impact, 1);
            }
        }
        let config_change_count = report
            .config_changes
            .iter()
            .filter(|l| l.kind != DiffKind::Context)
            .count();
        if config_change_count > 0 {
            by_classification.add(Classification::Configuration, config_change_count);
            impact_totals.add(Impact::Changed, config_change_count);
            window_totals.add(Impact::Changed, config_change_count);
        }
    }

    devices.sort_by(|a, b| {
        let key = |r: &DeviceReport| (r.action_count, r.attention_count, r.findings_count, r.impact_score);
        key(b).cmp(&key(a))
    });

    let mut common_files: Vec<String> = devices.iter().map(|d| d.file_name.clone()).collect();
    common_files.sort();

    Analysis {
        common_files,
        device_reports: devices,
        pairs: Vec::new(),
        pair_findings: Vec::new(),
        total_findings_by_classification: by_classification,
        impact_totals,
        window_totals,
        symmetry_totals,
        devices_with_findings,
    }
}

fn render(ticket: &str, analysis: &Analysis) -> String {
    render_html(ticket, Path::new(PRE), Path::new(POST), analysis, None)
}

fn index_of(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} not found in page"))
}

fn assert_in_order(page: &str, needles: &[&str]) {
    let positions: Vec<usize> = needles.iter().map(|n| index_of(page, n)).collect();
    for pair in positions.windows(2) {
        assert!(pair[0] < pair[1], "section order broken: {needles:?} at {positions:?}");
    }
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = index_of(text, start);
    let to = from + index_of(&text[from..], end) + end.len();
    &text[from..to]
}

#[test]
fn escape_matches_python_html_escape() {
    assert_eq!(
        escape("<a href=\"x\">Tom & Jerry's</a>"),
        "&lt;a href=&quot;x&quot;&gt;Tom &amp; Jerry&#x27;s&lt;/a&gt;"
    );
    assert_eq!(escape("plain → text"), "plain → text");
}

#[test]
fn diff_lines_carry_sign_and_class() {
    assert_eq!(
        render_diff_line(DiffKind::Added, "   neighbor 10.0.0.1 shutdown"),
        "<div class=\"added\">+    neighbor 10.0.0.1 shutdown</div>"
    );
    assert_eq!(
        render_diff_line(DiffKind::Removed, "seq 10 permit 10.0.0.0/8"),
        "<div class=\"removed\">- seq 10 permit 10.0.0.0/8</div>"
    );
    assert_eq!(
        render_diff_line(DiffKind::Context, "router bgp 64500"),
        "<div class=\"context\">  router bgp 64500</div>"
    );
    assert_eq!(
        render_diff_line(DiffKind::Added, "description <ISP> & \"up\""),
        "<div class=\"added\">+ description &lt;ISP&gt; &amp; &quot;up&quot;</div>"
    );
}

#[test]
fn finding_renders_exactly_like_the_python_report() {
    let added = bgp_finding(
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
    );
    let rendered = render_finding(&added);
    assert!(
        FIXTURE.contains(&rendered),
        "rendered finding is not a fragment of the fixture:\n{rendered}"
    );

    let mut disabled = bgp_finding(
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
    );
    disabled.evidence = "show ip bgp summary + related BGP shutdown/no shutdown config".to_string();
    let rendered = render_finding(&disabled);
    assert!(
        FIXTURE.contains(&rendered),
        "rendered finding is not a fragment of the fixture:\n{rendered}"
    );
    assert!(rendered.starts_with("\n    <div class=\"finding attention\">"));
    assert!(rendered.contains("<span class=\"badge badge-attention\">Attention</span>"));
}

#[test]
fn finding_badges_and_classes_per_impact() {
    let cases = [
        (Impact::Stable, "finding stable", "badge-stable", "Stable"),
        (Impact::Changed, "finding changed", "badge-changed", "Changed"),
        (Impact::Attention, "finding attention", "badge-attention", "Attention"),
        (
            Impact::ActionRequired,
            "finding action-required",
            "badge-action",
            "Action Required",
        ),
    ];
    for (impact, css, badge, label) in cases {
        let rendered = render_finding(&Finding::new(Classification::Protocol, "BGP", impact, "T"));
        assert!(rendered.contains(&format!("<div class=\"{css}\">")), "{rendered}");
        assert!(
            rendered.contains(&format!("<span class=\"badge {badge}\">{label}</span>")),
            "{rendered}"
        );
    }
}

#[test]
fn finding_detail_and_pair_arrow() {
    let mut pair = pair_finding(
        "Pair Route-Maps Differ",
        ("SITE-A-SW-1", "SITE-A-SW-2"),
        &["ISP-IN"],
        &[("Clauses", "3", "2")],
        "Route-map ISP-IN differs between the two members.",
    );
    pair.detail = vec![
        DiffLine::removed("   set local-preference 200"),
        DiffLine::added("   set local-preference 100"),
    ];
    let rendered = render_finding(&pair);
    assert!(rendered.contains("<span class=\"peer-name\">SITE-A-SW-1 vs SITE-A-SW-2</span>"));
    assert!(rendered.contains("<span class=\"peer-ip\">ISP-IN</span>"));
    assert!(rendered.contains("<span>3</span><span class=\"arrow\">vs</span><span>2</span>"));
    assert!(rendered.contains(
        "<div class=\"diff-box finding-detail\"><div class=\"removed\">-    set local-preference 200</div><div class=\"added\">+    set local-preference 100</div></div>"
    ));

    let plain = render_finding(&Finding::new(Classification::Protocol, "BGP", Impact::Stable, "T"));
    assert!(!plain.contains("finding-detail"));
    assert!(plain.contains("<div class=\"finding-grid\">\n        </div>"));
}

#[test]
fn stable_network_verdict() {
    let analysis = analysis(vec![device("SITE-B-SW-1", vec![], vec![], BTreeMap::new())]);
    let page = render("NET-1", &analysis);

    assert!(page.contains("<div class=\"value health-stable\">Stable</div>"));
    assert!(page.contains("<p>Nothing changed between the precheck and the postcheck beyond expected churn.</p>"));
    assert!(page.contains("<li>Nothing worth reporting.</li>"));
    assert!(!page.contains("item(s)."));
    assert!(page.contains("<p class=\"empty\">Nothing needs your attention.</p>"));
    assert!(page.contains(
        "<p class=\"empty\">No redundant pairs to compare: no two captured hostnames differ only by a trailing number, and the inventory lists no pairs.</p>"
    ));
    assert!(page.contains("<div class=\"label\">Devices Checked</div><div class=\"value\">1</div>"));
    assert!(page.contains("<div class=\"label\">Devices With Findings</div><div class=\"value\">0</div>"));
    assert!(page.contains("<div class=\"label\">Changed</div><div class=\"value\">0</div>"));
    assert!(page.contains("<div class=\"label\">Attention</div><div class=\"value health-attention\">0</div>"));
    assert!(page.contains("Findings: 0 | Impact Score: 0 | Evidence Sections: 0"));
    assert!(page.contains(
        "<p class=\"empty\">No meaningful BGP neighbor, prefix, prefix-list, or interface address changes detected.</p>"
    ));
    assert!(page.contains("<p class=\"empty\">No BGP-related config changes detected.</p>"));
    assert!(page.contains("<p class=\"empty\">No raw differences detected.</p>"));
    assert!(!page.contains("Expectations:"));
    assert!(page.contains("<div class=\"meta-pill\">Ticket: NET-1</div>"));
    assert!(page.contains(&format!("<div class=\"meta-pill\">Precheck: {PRE}</div>")));
    assert!(page.contains(&format!("<div class=\"meta-pill\">Postcheck: {POST}</div>")));
    assert!(page.contains("<title>NET-1 Maintenance Report</title>"));
}

#[test]
fn changed_verdict_from_config_changes_alone() {
    let config = vec![
        DiffLine::context("router bgp 64500"),
        DiffLine::added("   neighbor 198.51.100.9 remote-as 64497"),
        DiffLine::added("   neighbor 198.51.100.9 description ISP-B"),
    ];
    let analysis = analysis(vec![device("SW-1", vec![], config, BTreeMap::new())]);
    let page = render("NET-1", &analysis);

    assert!(page.contains("<div class=\"value health-changed\">Changed</div>"));
    assert!(page.contains("<p>Something changed, but nothing needs your attention.</p>"));
    assert!(page.contains("<li>2 configuration item(s).</li>"));
    assert!(page.contains("<div class=\"label\">Changed</div><div class=\"value\">2</div>"));
    assert!(page.contains("Findings: 2 | Impact Score: 4 | Evidence Sections: 0"));
}

#[test]
fn attention_and_action_required_verdict() {
    let action = finding(
        Classification::Protocol,
        "BGP",
        Impact::ActionRequired,
        "BGP Peer Down",
        &["ISP-A", "198.51.100.1", "AS64496"],
        &[("State", "Estab", "Active")],
        "The session is no longer established.",
        "show ip bgp summary",
    );
    let attention = finding(
        Classification::Routing,
        "Prefix list",
        Impact::Attention,
        "Prefix-List Entry Removed",
        &["ISP-OUT", "seq 20"],
        &[("Rule", "permit 198.51.100.243/32", "Removed")],
        "An entry was removed.",
        "show ip prefix-list",
    );
    let quiet = device("SW-3", vec![], vec![], BTreeMap::new());
    let analysis = analysis(vec![
        quiet,
        device("SW-2", vec![attention], vec![], BTreeMap::new()),
        device("SW-1", vec![action], vec![], BTreeMap::new()),
    ]);
    let page = render("NET-1", &analysis);

    assert!(page.contains("<div class=\"value health-action-required\">Action Required</div>"));
    assert!(page.contains("<p>Something here may need fixing. Click Action Required to jump to it.</p>"));
    assert!(page.contains("<li>1 protocol item(s).</li>"));
    assert!(page.contains("<li>1 routing item(s).</li>"));
    assert!(page.contains("<div class=\"label\">Devices With Findings</div><div class=\"value\">2</div>"));
    assert!(page.contains("<div class=\"label\">Attention</div><div class=\"value health-attention\">1</div>"));
    assert!(page.contains("<span class=\"badge badge-action\">Action Required</span>"));
    assert!(page.contains("<span class=\"badge badge-attention\">Attention</span>"));
    assert!(page.contains("<div class=\"finding action-required\">"));
    assert!(page.contains("<div class=\"finding attention\">"));

    // The attention list and the device cards follow the analysis order:
    // the action-required device first, the quiet one last and off the list.
    let attention_card = section(&page, "<div id=\"attention-items\"", "<div id=\"pair-symmetry\"");
    assert!(attention_card.contains(
        "<a class=\"attention-link\" href=\"#device-sw-1\">\n            <strong>SW-1.txt</strong><br>\n            <span class=\"muted\">Attention: 0 | Action Required: 1 | Impact Score: 10</span>"
    ));
    assert!(attention_card.contains("Attention: 1 | Action Required: 0 | Impact Score: 5"));
    assert!(!attention_card.contains("SW-3"));
    assert_in_order(attention_card, &["#device-sw-1", "#device-sw-2"]);
    assert_in_order(
        &page,
        &[
            "<div id=\"device-sw-1\" class=\"device\">",
            "<div id=\"device-sw-2\" class=\"device\">",
            "<div id=\"device-sw-3\" class=\"device\">",
        ],
    );
    assert!(page.contains("const deviceLabels = [\"SW-1\", \"SW-2\", \"SW-3\"];"));
    assert!(page.contains("const deviceImpact = [10, 5, 0];"));
    assert!(page.contains("const healthValues = [0, 0, 1, 1];"));
}

#[test]
fn attention_without_action_is_attention() {
    let attention = Finding::new(Classification::Protocol, "BGP", Impact::Attention, "BGP Session Reset");
    let analysis = analysis(vec![device("SW-1", vec![attention], vec![], BTreeMap::new())]);
    let page = render("NET-1", &analysis);
    assert!(page.contains("<div class=\"value health-attention\">Attention</div>"));
    assert!(page.contains("<p>Something changed that you should look at. Click Attention to jump to it.</p>"));
}

#[test]
fn pair_symmetry_section() {
    let divergence = pair_finding(
        "Pair Prefix-Lists Differ",
        ("SITE-A-SW-1", "SITE-A-SW-2"),
        &["ISP-OUT"],
        &[("seq 20", "permit 198.51.100.243/32", "permit 198.51.100.0/24")],
        "Prefix-list ISP-OUT differs between the two members at 1 sequence(s).",
    );
    let mut analysis = analysis(vec![
        device("SITE-A-SW-1", vec![divergence.clone()], vec![], BTreeMap::new()),
        device("SITE-A-SW-2", vec![divergence.clone()], vec![], BTreeMap::new()),
        device("SITE-B-SW-1", vec![], vec![], BTreeMap::new()),
    ]);
    analysis.pairs = vec![("SITE-A-SW-1".to_string(), "SITE-A-SW-2".to_string())];
    analysis.pair_findings = vec![divergence];
    let page = render("NET-4", &analysis);

    assert!(page.contains(
        "<p class=\"muted\">1 pair(s) compared from the postcheck captures: SITE-A-SW-1 / SITE-A-SW-2. Same-named prefix-lists and route-maps, and PAN-OS HA state, are checked entry for entry.</p>"
    ));
    assert!(!page.contains("Both members of every pair agree."));
    // Once in the pair section, once on each member.
    assert_eq!(page.matches("Pair Prefix-Lists Differ").count(), 3);
    assert!(page.contains("SITE-A-SW-1 vs SITE-A-SW-2"));
    assert!(page.contains("<span class=\"arrow\">vs</span>"));
    // Counted once network-wide, attributed to both members - and on the
    // Pair Symmetry card, not Attention, because it is not a change this
    // window made. The verdict stays Stable.
    assert!(page.contains("<div class=\"label\">Attention</div><div class=\"value health-attention\">0</div>"));
    assert!(page.contains("<div class=\"label\">Pair Symmetry</div><div class=\"value\">1</div>"));
    assert!(page.contains("<div class=\"value health-stable\">Stable</div>"));
    assert!(page.contains("1 pair-symmetry finding(s) say how the two members"));
    assert!(page.contains("href=\"#device-site-a-sw-1\""));
    assert!(page.contains("href=\"#device-site-a-sw-2\""));
    assert!(!page.contains("href=\"#device-site-b-sw-1\""));
    assert_in_order(
        &page,
        &[
            "id=\"attention-items\"",
            "id=\"pair-symmetry\"",
            "Pair Prefix-Lists Differ",
            "id=\"healthChart\"",
            "id=\"device-findings\"",
        ],
    );

    analysis.pair_findings.clear();
    analysis.pairs.push(("CORE-EAST".to_string(), "CORE-WEST".to_string()));
    let page = render("NET-4", &analysis);
    assert!(
        page.contains(
            "2 pair(s) compared from the postcheck captures: SITE-A-SW-1 / SITE-A-SW-2, CORE-EAST / CORE-WEST."
        )
    );
    assert!(page.contains("<p class=\"empty\">Both members of every pair agree.</p>"));
}

#[test]
fn config_changes_render_context_lines_muted() {
    let config = vec![
        DiffLine::context("interface Ethernet49/1"),
        DiffLine::added("   shutdown"),
        DiffLine::context("router bgp 64500"),
        DiffLine::removed("   neighbor 198.51.100.1 shutdown"),
    ];
    let analysis = analysis(vec![device("SW-1", vec![], config, BTreeMap::new())]);
    let page = render("NET-1", &analysis);

    let config_section = section(&page, "<h3>Configuration / Policy Changes</h3>", "<h3>Evidence Only");
    assert!(config_section.contains(
        "<div class=\"context\">  interface Ethernet49/1</div>\n<div class=\"added\">+    shutdown</div>\n<div class=\"context\">  router bgp 64500</div>\n<div class=\"removed\">-    neighbor 198.51.100.1 shutdown</div>"
    ));
    assert!(!config_section.contains("No BGP-related config changes detected."));
    // Context lines are not counted as findings.
    assert!(page.contains("Findings: 2 | Impact Score: 4"));
}

#[test]
fn raw_diffs_are_collapsible_and_labelled() {
    let mut diffs = BTreeMap::new();
    diffs.insert(
        "show ip bgp".to_string(),
        vec![
            DiffLine::removed(" *>  203.0.113.0/24  198.51.100.1"),
            DiffLine::added(" *>  203.0.113.0/24  198.51.100.9"),
        ],
    );
    diffs.insert(
        "show interfaces status".to_string(),
        vec![DiffLine::added(
            "Et49/1     ISP-A uplink       disabled     routed   full   10G",
        )],
    );
    diffs.insert(
        "show routing route".to_string(),
        vec![DiffLine::context("flags: A:active")],
    );
    let analysis = analysis(vec![device("SW-1", vec![], vec![], diffs)]);
    let page = render("NET-1", &analysis);

    assert!(page.contains("Findings: 0 | Impact Score: 0 | Evidence Sections: 3"));
    assert_eq!(page.matches("<details>").count(), 3);
    assert_eq!(page.matches("</details>").count(), 3);
    assert!(page.contains(
        "\n            <details>\n                <summary>show interfaces status</summary>\n                <div class=\"diff-box\">\n\n<div class=\"added\">+ Et49/1     ISP-A uplink       disabled     routed   full   10G</div>\n\n                </div>\n            </details>\n"
    ));
    assert!(page.contains("<summary>show ip bgp - Large routing evidence</summary>"));
    assert!(page.contains("<summary>show routing route - Large routing evidence</summary>"));
    assert!(page.contains("<div class=\"context\">  flags: A:active</div>"));
    assert!(page.contains("<div class=\"removed\">-  *&gt;  203.0.113.0/24  198.51.100.1</div>"));
    assert_in_order(
        &page,
        &[
            "<summary>show interfaces status</summary>",
            "<summary>show ip bgp - Large routing evidence</summary>",
            "<summary>show routing route - Large routing evidence</summary>",
        ],
    );
    assert!(!page.contains("No raw differences detected."));
}

#[test]
fn hostile_strings_are_escaped_everywhere() {
    let hostile = finding(
        Classification::Protocol,
        "BGP",
        Impact::Attention,
        "<script>alert(1)</script>",
        &["<b>peer</b>", "\"ip\""],
        &[("<label>", "a & b", "'c'")],
        "summary <img src=x onerror=alert(1)>",
        "show <evidence>",
    );
    let mut diffs = BTreeMap::new();
    diffs.insert("show <cmd>".to_string(), vec![DiffLine::added("<div>raw</div>")]);
    let config = vec![DiffLine::added("neighbor <x> description \"quoted\"")];
    let mut analysis = analysis(vec![device("SW-1", vec![hostile], config, diffs)]);
    analysis.pairs = vec![("<A>".to_string(), "<B>".to_string())];

    let page = render_html("NET-<1>", Path::new("pre/<x>"), Path::new("post/<y>"), &analysis, None);

    assert!(!page.contains("<script>alert"));
    assert!(!page.contains("<img "));
    assert!(page.contains("<span class=\"finding-heading\">&lt;script&gt;alert(1)&lt;/script&gt;</span>"));
    assert!(page.contains("<span class=\"peer-name\">&lt;b&gt;peer&lt;/b&gt;</span>"));
    assert!(page.contains("<span class=\"peer-ip\">&quot;ip&quot;</span>"));
    assert!(page.contains("<div class=\"mini-label\">&lt;label&gt;</div>"));
    assert!(page.contains("<span>a &amp; b</span><span class=\"arrow\">→</span><span>&#x27;c&#x27;</span>"));
    assert!(page.contains("<div class=\"explanation\">summary &lt;img src=x onerror=alert(1)&gt;</div>"));
    assert!(page.contains("<div class=\"evidence\">Evidence: show &lt;evidence&gt;</div>"));
    assert!(page.contains("<summary>show &lt;cmd&gt;</summary>"));
    assert!(page.contains("<div class=\"added\">+ &lt;div&gt;raw&lt;/div&gt;</div>"));
    assert!(page.contains("<div class=\"added\">+ neighbor &lt;x&gt; description &quot;quoted&quot;</div>"));
    assert!(page.contains("<title>NET-&lt;1&gt; Maintenance Report</title>"));
    assert!(page.contains("<div class=\"meta-pill\">Ticket: NET-&lt;1&gt;</div>"));
    assert!(page.contains("<div class=\"meta-pill\">Precheck: pre/&lt;x&gt;</div>"));
    assert!(page.contains("<div class=\"meta-pill\">Postcheck: post/&lt;y&gt;</div>"));
    assert!(page.contains("&lt;A&gt; / &lt;B&gt;."));
}

#[test]
fn chart_data_is_embedded_like_python_json() {
    let mut analysis = analysis(vec![
        device("Zürich-1", vec![], vec![], BTreeMap::new()),
        device("SW-\"2\"", vec![], vec![], BTreeMap::new()),
    ]);
    analysis.total_findings_by_classification.add(Classification::Layer2, 2);
    analysis
        .total_findings_by_classification
        .add(Classification::EvidenceOnly, 1);
    analysis.impact_totals.add(Impact::Changed, 6);
    analysis.window_totals.add(Impact::Changed, 6);
    let page = render("NET-1", &analysis);

    assert!(page.contains("const healthLabels = [\"Stable\", \"Changed\", \"Attention\", \"Action Required\"];"));
    assert!(page.contains("const healthValues = [0, 6, 0, 0];"));
    assert!(page.contains(
        "const categoryLabels = [\"Configuration\", \"Protocol\", \"Routing\", \"Interface\", \"Layer 2\", \"Firewall\", \"System\", \"Evidence only\"];"
    ));
    assert!(page.contains("const categoryValues = [0, 0, 0, 0, 2, 0, 0, 1];"));
    assert!(page.contains("const deviceLabels = [\"Z\\u00fcrich-1\", \"SW-\\\"2\\\"\"];"));
    assert!(page.contains("const deviceImpact = [0, 0];"));
    assert_eq!(page.matches("<canvas").count(), 3);
    assert!(page.contains("<li>2 layer 2 item(s).</li>"));
    assert!(page.contains("<li>1 evidence only item(s).</li>"));
}

#[test]
fn sections_come_in_the_python_order() {
    let analysis = analysis(vec![device("SW-1", vec![], vec![], BTreeMap::new())]);
    let page = render("NET-1", &analysis);
    assert_in_order(
        &page,
        &[
            "<!DOCTYPE html>",
            "<title>",
            CHART_JS_SCRIPT_TAG,
            "<style>",
            "</style>",
            "<div class=\"header\">",
            "<div class=\"header-meta\">",
            "<div class=\"cards\">",
            "<div class=\"outcome-card\">",
            "<h2>Maintenance Outcome Summary</h2>",
            "<div id=\"attention-items\" class=\"attention-card\">",
            "<h2>Items Needing Attention</h2>",
            "<div id=\"pair-symmetry\" class=\"pair-card\">",
            "<h2>Pair Symmetry</h2>",
            "<div class=\"charts\">",
            "<canvas id=\"healthChart\">",
            "<canvas id=\"categoryChart\">",
            "<canvas id=\"deviceImpactChart\">",
            "<div id=\"device-findings\" class=\"section-title\">",
            "<h2>Device Findings</h2>",
            "<div id=\"device-sw-1\" class=\"device\">",
            "<h3>Protocol / Routing Interpretation</h3>",
            "<h3>Configuration / Policy Changes</h3>",
            "<h3>Evidence Only - Collapsible Raw Diffs</h3>",
            "<div class=\"footer\">",
            "| Maintenance Report",
            "<script>\nconst healthLabels",
            "Chart.defaults.color",
            "</script>\n\n</body>\n</html>\n",
        ],
    );
    assert!(page.starts_with("\n<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"));
    assert!(page.ends_with("</body>\n</html>\n"));
}

#[test]
fn static_skeleton_is_identical_to_the_fixture() {
    let analysis = analysis(vec![device("SW-1", vec![], vec![], BTreeMap::new())]);
    let page = render_html_at(
        "NET-DEMO",
        Path::new(PRE),
        Path::new(POST),
        &analysis,
        None,
        "2026-01-01 00:00:00",
    );

    // Head through the Chart.js tag, the whole stylesheet, the start of the body.
    let head_end = "<div class=\"header-meta\">";
    assert_eq!(
        section(&page, "\n<!DOCTYPE html>", head_end),
        section(FIXTURE, "\n<!DOCTYPE html>", head_end)
    );

    let style = section(&page, "<style>", "</style>");
    assert_eq!(style, section(FIXTURE, "<style>", "</style>"));
    assert!(style.lines().count() > 400);

    let cdn_tag = FIXTURE
        .lines()
        .find(|line| line.contains("cdn.jsdelivr.net"))
        .expect("fixture has the CDN tag");
    assert_eq!(cdn_tag, CHART_JS_SCRIPT_TAG);
    assert_eq!(page.matches(CHART_JS_SCRIPT_TAG).count(), 1);
    assert_eq!(page.lines().nth(6), Some(CHART_JS_SCRIPT_TAG));
    assert_eq!(page.matches("<script").count(), 2);

    // The charts block and the "Device Findings" title.
    let charts_start = "\n    <div class=\"charts\">";
    let charts_end = "<h2>Device Findings</h2>\n    </div>\n";
    assert_eq!(
        section(&page, charts_start, charts_end),
        section(FIXTURE, charts_start, charts_end)
    );

    // Everything after the chart data is static.
    let script_tail = "Chart.defaults.color";
    assert_eq!(
        &page[index_of(&page, script_tail)..],
        &FIXTURE[index_of(FIXTURE, script_tail)..]
    );
}

#[test]
fn chart_canvases_and_footer() {
    let analysis = analysis(vec![device("SW-1", vec![], vec![], BTreeMap::new())]);
    let page = render_html_at(
        "NET-1",
        Path::new(PRE),
        Path::new(POST),
        &analysis,
        None,
        "2026-04-14 10:45:00",
    );
    assert!(
        page.contains("\n<div class=\"footer\">\n    Generated 2026-04-14 10:45:00 | Maintenance Report\n</div>\n")
    );

    let live = render("NET-1", &analysis);
    let footer = section(&live, "<div class=\"footer\">", "</div>");
    let stamp = footer
        .trim_start_matches("<div class=\"footer\">")
        .trim()
        .trim_start_matches("Generated ")
        .split(" | ")
        .next()
        .unwrap();
    assert_eq!(stamp.len(), "2026-04-14 10:45:00".len(), "{stamp}");
    assert_eq!(&stamp[4..5], "-");
    assert_eq!(&stamp[10..11], " ");
}

// Ported from tests/test_htmlreport.py, test_prefix_lists.py,
// test_bgp_uptime.py and test_interfaces.py:
// the same assertions on the rendered page, from the findings the
// Python analysis produced for those captures.

#[test]
fn python_build_html_report_end_to_end_assertions() {
    let disabled = bgp_finding(
        Impact::Attention,
        "BGP Peer Shut Down",
        ("SPINE1", "203.0.113.1", "65001"),
        [("Estab", "Idle(Admin)"), ("100", "0"), ("98", "0"), ("5d02h", "5d02h")],
        "Someone shut this peer down during the window. It's idle on purpose, not broken.",
    );
    let config = vec![
        DiffLine::context("router bgp 65001"),
        DiffLine::added("   neighbor 203.0.113.1 shutdown"),
    ];
    let mut diffs = BTreeMap::new();
    diffs.insert(
        "show ip bgp summary".to_string(),
        vec![
            DiffLine::removed("SPINE1 203.0.113.1 AS65001 Estab 100 98"),
            DiffLine::added("SPINE1 203.0.113.1 AS65001 Idle(Admin)"),
        ],
    );
    let analysis = analysis(vec![device("switch1", vec![disabled], config, diffs)]);
    let page = render("NET-1", &analysis);

    assert!(page.contains("NET-1"));
    assert!(page.contains("switch1.txt"));
    assert!(page.contains("BGP Peer Shut Down"));
    assert!(page.contains("neighbor 203.0.113.1 shutdown"));
    assert_eq!(page.matches("<canvas").count(), 3);
}

#[test]
fn python_prefix_list_report_assertions() {
    let withdrawn = finding(
        Classification::Routing,
        "Prefix list",
        Impact::Attention,
        "Prefix-List Entry Removed",
        &["ISP-OUT", "seq 20"],
        &[("Rule", "permit 198.51.100.243/32", "Removed")],
        "A permit entry was removed from the list.",
        "show ip prefix-list",
    );
    let analysis = analysis(vec![device("SITE-A-SW-1", vec![withdrawn], vec![], BTreeMap::new())]);
    assert_eq!(analysis.impact_totals.get(Impact::Attention), 1);
    assert!(analysis.total_findings_by_classification.get(Classification::Routing) >= 1);
    assert_eq!(analysis.device_reports[0].attention_count, 1);
    assert!(analysis.device_reports[0].impact_score >= 5);

    let page = render("NET-2", &analysis);
    assert!(page.contains("Prefix-List Entry Removed"));
    assert!(page.contains("health-attention\">Attention"));
    assert!(page.contains("permit 198.51.100.243/32"));
    assert!(page.contains("<canvas"));
}

#[test]
fn python_bgp_uptime_report_assertions() {
    let reset = bgp_finding(
        Impact::Attention,
        "BGP Session Reset",
        ("ISP-A", "198.51.100.1", "64496"),
        [
            ("Estab", "Estab"),
            ("812", "812"),
            ("812", "812"),
            ("5d02h", "00:12:33"),
        ],
        "The session uptime went backwards: the peer re-established during the window.",
    );
    let analysis = analysis(vec![device("SITE-A-SW-1", vec![reset], vec![], BTreeMap::new())]);
    let page = render("NET-3", &analysis);
    assert!(page.contains("BGP Session Reset"));
    assert!(page.contains("health-attention\">Attention"));
    assert!(page.contains("Up/Down"));
    assert!(page.contains("<span>5d02h</span><span class=\"arrow\">→</span><span>00:12:33</span>"));
}

#[test]
fn python_interface_report_assertions() {
    let down = finding(
        Classification::Interface,
        "Interface",
        Impact::Attention,
        "New Address, Interface Still Down",
        &["Ethernet50/1"],
        &[("Address", "none", "198.51.100.10/30"), ("Status", "n/a", "down")],
        "The interface gained an address during the window but is down.",
        "show ip interface brief",
    );
    let analysis = analysis(vec![device("SITE-A-SW-1", vec![down], vec![], BTreeMap::new())]);
    let page = render("NET-6", &analysis);
    assert!(page.contains("New Address, Interface Still Down"));
    assert!(page.contains("health-attention\">Attention"));
    assert!(page.contains("198.51.100.10/30"));
}

#[test]
fn build_html_report_reports_missing_run_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let dirs = ticket_dirs_under(tmp.path(), "NET-1");

    let result = build_html_report("NET-1", &dirs, "2026-01-01_02-05", None, None).unwrap();
    assert_eq!(result, None);
    assert!(!dirs.compare.exists());

    std::fs::create_dir_all(dirs.precheck.join("precheck_2026-01-01_00-00")).unwrap();
    let result = build_html_report("NET-1", &dirs, "2026-01-01_02-05", None, None).unwrap();
    assert_eq!(result, None);
    assert!(!dirs.compare.exists());

    std::fs::create_dir_all(dirs.postcheck.join("notes")).unwrap();
    std::fs::write(dirs.postcheck.join("postcheck_2026-01-01_02-00.zip"), b"").unwrap();
    let result = build_html_report("NET-1", &dirs, "2026-01-01_02-05", None, None).unwrap();
    assert_eq!(result, None, "neither a zip nor an unprefixed folder is a run");
}
