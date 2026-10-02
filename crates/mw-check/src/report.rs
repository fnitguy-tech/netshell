//! The interpreted HTML report: one self-contained file with the
//! health verdict, outcome summary, attention items, pair symmetry,
//! charts (Chart.js from a CDN is the only external asset), per-device
//! findings and every raw diff behind a collapsible section.
//!
//! Port of the Python `htmlreport.render_html()` and friends. The page
//! is assembled the same way the Python does it (the same fragments,
//! joined with newlines), so a report built here and one built by the
//! Python tool from the same captures are the same bytes apart from
//! the footer timestamp.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::analysis::{self, Analysis, Classification, DeviceReport, DiffKind, Finding, Impact};
use crate::expectations::Expectation;
use crate::layout::{TicketDirs, display_path, find_latest_folder};

/// The Chart.js CDN tag: the report's only external asset.
pub const CHART_JS_SCRIPT_TAG: &str = r#"<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>"#;

/// Commands whose raw diff gets the "Large routing evidence" label.
const LARGE_ROUTING_COMMANDS: &[&str] = &["show ip bgp", "show ip route", "show routing route"];

/// `html.escape(value, quote=True)`: `& < > " '` become entities.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// One diff line: `<div class="added">+ text</div>` and friends.
pub fn render_diff_line(kind: DiffKind, text: &str) -> String {
    let (css, sign) = match kind {
        DiffKind::Added => ("added", "+"),
        DiffKind::Removed => ("removed", "-"),
        DiffKind::Context => ("context", " "),
    };
    format!("<div class=\"{css}\">{sign} {}</div>", escape(text))
}

/// Badge class for an impact level.
pub fn badge_class(impact: Impact) -> &'static str {
    match impact {
        Impact::Stable => "badge-stable",
        Impact::Changed => "badge-changed",
        Impact::Attention => "badge-attention",
        Impact::ActionRequired => "badge-action",
    }
}

/// Render one finding of any kind: badge, title, subject spans, the
/// before/after grid built from its fields, summary, evidence and any
/// raw detail lines.
pub fn render_finding(finding: &Finding) -> String {
    let impact = finding.impact;
    let arrow = escape(&finding.arrow);

    let mut subject_html = String::new();
    for (index, span) in finding.subject.iter().enumerate() {
        let css = if index == 0 { "peer-name" } else { "peer-ip" };
        let _ = write!(
            subject_html,
            "<span class=\"{css}\">{}</span>\n            ",
            escape(span)
        );
    }

    let mut fields_html = String::new();
    for field in &finding.fields {
        let _ = write!(
            fields_html,
            "\n            <div>\n                <div class=\"mini-label\">{label}</div>\n                <div class=\"state-flow\"><span>{before}</span><span class=\"arrow\">{arrow}</span><span>{after}</span></div>\n            </div>",
            label = escape(&field.label),
            before = escape(&field.before),
            after = escape(&field.after),
        );
    }

    let mut detail_html = String::new();
    if !finding.detail.is_empty() {
        detail_html.push_str("<div class=\"diff-box finding-detail\">");
        for line in &finding.detail {
            detail_html.push_str(&render_diff_line(line.kind, &line.text));
        }
        detail_html.push_str("</div>");
    }

    format!(
        "
    <div class=\"finding {impact_css}\">
        <div class=\"finding-title\">
            <span class=\"badge {badge}\">{impact_label}</span>
            <span class=\"finding-heading\">{title}</span>
            {subject_html}
        </div>

        <div class=\"finding-grid\">{fields_html}
        </div>

        <div class=\"explanation\">{summary}</div>
        <div class=\"evidence\">Evidence: {evidence}</div>
        {detail_html}
    </div>
    ",
        impact_css = impact.css(),
        badge = badge_class(impact),
        impact_label = escape(impact.label()),
        title = escape(&finding.title),
        summary = escape(&finding.summary),
        evidence = escape(&finding.evidence),
    )
}

/// The network-wide verdict: the worst impact level with any finding from
/// this window.
///
/// Graded on `window_totals`, not `impact_totals`. A pair-symmetry finding is
/// a standing condition the window did not create - it was as true in the
/// precheck - so it gets its own count and its own sentence instead of turning
/// a clean verification red.
pub fn overall_health(analysis: &Analysis) -> Impact {
    let totals = &analysis.window_totals;
    if totals.get(Impact::ActionRequired) > 0 {
        Impact::ActionRequired
    } else if totals.get(Impact::Attention) > 0 {
        Impact::Attention
    } else if totals.get(Impact::Changed) > 0 {
        Impact::Changed
    } else {
        Impact::Stable
    }
}

/// The assessment sentence shown under the verdict.
pub fn assessment_text(health: Impact) -> &'static str {
    match health {
        Impact::Stable => "Nothing changed between the precheck and the postcheck beyond expected churn.",
        Impact::Changed => "Meaningful changes were detected, but no immediate attention markers were identified.",
        Impact::Attention => {
            "Operational changes were detected that should be reviewed. Click the Attention card to jump to items requiring review."
        }
        Impact::ActionRequired => {
            "One or more findings may require action. Click Action Required to jump to the highest-priority items."
        }
    }
}

/// The "Detected Categories" bullet list.
pub fn summary_items(analysis: &Analysis) -> Vec<String> {
    let mut items: Vec<String> = analysis
        .total_findings_by_classification
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(classification, count)| {
            format!(
                "{count} {} finding/evidence item(s) detected.",
                classification.label().to_lowercase()
            )
        })
        .collect();

    if items.is_empty() {
        items.push("No meaningful findings detected.".to_string());
    }

    if analysis.expectations_in_play {
        let totals = &analysis.expectation_totals;
        items.push(format!(
            "BGP prefix deltas against the expectations file: {} as planned, {} different from plan, {} unexplained, {} expected change(s) that did not happen.",
            totals.as_planned, totals.differs, totals.unexplained, totals.not_met
        ));
    }

    items
}

/// `json.dumps(str)` with its default `ensure_ascii=True`.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

/// `json.dumps(list)` with its default `", "` separator.
fn json_list<I: IntoIterator<Item = String>>(items: I) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(", "))
}

fn json_strings<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    json_list(items.into_iter().map(json_string))
}

fn json_numbers(items: impl IntoIterator<Item = usize>) -> String {
    json_list(items.into_iter().map(|n| n.to_string()))
}

/// The label a raw diff section is collapsed under.
pub fn raw_diff_label(command: &str) -> String {
    if LARGE_ROUTING_COMMANDS.contains(&command) {
        format!("{command} - Large routing evidence")
    } else {
        command.to_string()
    }
}

/// Render the analysis into a single HTML page.
pub fn render_html(
    ticket: &str,
    precheck_folder: &Path,
    postcheck_folder: &Path,
    analysis: &Analysis,
    expectations_label: Option<&str>,
) -> String {
    let generated = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    render_html_at(
        ticket,
        precheck_folder,
        postcheck_folder,
        analysis,
        expectations_label,
        &generated,
    )
}

/// [`render_html`] with the footer's "Generated" timestamp supplied,
/// so a rendering can be compared byte for byte.
pub fn render_html_at(
    ticket: &str,
    precheck_folder: &Path,
    postcheck_folder: &Path,
    analysis: &Analysis,
    expectations_label: Option<&str>,
    generated: &str,
) -> String {
    let device_reports = &analysis.device_reports;
    let impact_totals = &analysis.impact_totals;

    let health = overall_health(analysis);
    let symmetry_count: usize = analysis.symmetry_totals.iter().map(|(_, n)| n).sum();
    let mut assessment = assessment_text(health).to_string();

    if symmetry_count > 0 {
        assessment.push_str(&format!(
            " Separately, {symmetry_count} pair-symmetry finding(s) describe how the two members of a redundant \
             pair differ from each other right now. They are not changes from this window - they were as true in \
             the precheck - and they are listed under Pair Symmetry."
        ));
    }
    let items = summary_items(analysis);

    let attention_devices: Vec<&DeviceReport> = device_reports
        .iter()
        .filter(|report| report.attention_count > 0 || report.action_count > 0)
        .collect();

    let chart_classification_labels = json_strings(Classification::ALL.iter().map(|c| c.label()));
    let chart_classification_values = json_numbers(analysis.total_findings_by_classification.iter().map(|(_, n)| n));
    let chart_impact_labels = json_strings(Impact::ALL.iter().map(|i| i.label()));
    let chart_impact_values = json_numbers(impact_totals.iter().map(|(_, n)| n));
    let device_labels: Vec<String> = device_reports
        .iter()
        .map(|report| report.file_name.replace(".txt", ""))
        .collect();
    let chart_device_labels = json_strings(device_labels.iter().map(String::as_str));
    let chart_device_impact = json_numbers(device_reports.iter().map(|report| report.impact_score));

    let expectations_pill = if analysis.expectations_in_play {
        format!(
            "<div class=\"meta-pill\">Expectations: {}</div>",
            escape(expectations_label.unwrap_or("provided"))
        )
    } else {
        String::new()
    };

    let mut parts: Vec<String> = Vec::new();

    parts.push(format!(
        "
<!DOCTYPE html>
<html>
<head>
<meta charset=\"utf-8\">
<title>{title} Maintenance Report</title>
{CHART_JS_SCRIPT_TAG}
<style>
{STYLE_SHEET}</style>
</head>
<body>
<div class=\"header\">
    <div class=\"brand\">
        <div class=\"logo\">M</div>
        <div>
            <h1>Maintenance Report</h1>
            <div class=\"subtitle\">Automated pre/post comparison, interpreted findings, visual summary, and raw evidence package</div>
        </div>
    </div>

    <div class=\"header-meta\">
        <div class=\"meta-pill\">Ticket: {ticket}</div>
        <div class=\"meta-pill\">Precheck: {precheck}</div>
        <div class=\"meta-pill\">Postcheck: {postcheck}</div>
        {expectations_pill}
    </div>
</div>

<div class=\"container\">
    <div class=\"cards\">
        <a class=\"card clickable\" href=\"#device-findings\"><div class=\"label\">Network Health</div><div class=\"value health-{health_css}\">{health_label}</div></a>
        <a class=\"card clickable\" href=\"#device-findings\"><div class=\"label\">Devices Checked</div><div class=\"value\">{devices_checked}</div></a>
        <a class=\"card clickable\" href=\"#device-findings\"><div class=\"label\">Devices With Findings</div><div class=\"value\">{devices_with_findings}</div></a>
        <a class=\"card clickable\" href=\"#device-findings\"><div class=\"label\">Changed</div><div class=\"value\">{changed}</div></a>
        <a class=\"card clickable\" href=\"#attention-items\"><div class=\"label\">Attention</div><div class=\"value health-attention\">{attention}</div></a>
        <a class=\"card clickable\" href=\"#attention-items\"><div class=\"label\">Pair Symmetry</div><div class=\"value\">{symmetry}</div></a>
    </div>

    <div class=\"outcome-card\">
        <h2>Maintenance Outcome Summary</h2>
        <div class=\"outcome-grid\">
            <div class=\"outcome-pill\">
                <strong>Assessment</strong>
                <p>{assessment}</p>
            </div>
            <div class=\"outcome-pill\">
                <strong>Detected Categories</strong>
                <ul class=\"outcome-list\">
",
        title = escape(ticket),
        ticket = escape(ticket),
        precheck = escape(&display_path(precheck_folder)),
        postcheck = escape(&display_path(postcheck_folder)),
        health_css = health.css(),
        health_label = escape(health.label()),
        devices_checked = analysis.common_files.len(),
        devices_with_findings = analysis.devices_with_findings,
        changed = analysis.window_totals.get(Impact::Changed),
        attention = analysis.window_totals.get(Impact::Attention),
        symmetry = symmetry_count,
        assessment = escape(&assessment),
    ));

    for item in &items {
        parts.push(format!("<li>{}</li>", escape(item)));
    }

    parts.push(
        "
                </ul>
            </div>
        </div>
    </div>
"
        .to_string(),
    );

    parts.push(
        "
    <div id=\"attention-items\" class=\"attention-card\">
        <h2>Items Needing Attention</h2>
"
        .to_string(),
    );

    if attention_devices.is_empty() {
        parts.push("<p class=\"empty\">No attention-level findings detected.</p>".to_string());
    } else {
        parts.push("<div class=\"attention-list\">".to_string());
        for report in &attention_devices {
            parts.push(format!(
                "
        <a class=\"attention-link\" href=\"#device-{device_id}\">
            <strong>{file_name}</strong><br>
            <span class=\"muted\">Attention: {attention} | Action Required: {action} | Impact Score: {score}</span>
        </a>
        ",
                device_id = escape(&report.device_id),
                file_name = escape(&report.file_name),
                attention = report.attention_count,
                action = report.action_count,
                score = report.impact_score,
            ));
        }
        parts.push("</div>".to_string());
    }

    parts.push(
        "
    </div>

    <div id=\"pair-symmetry\" class=\"pair-card\">
        <h2>Pair Symmetry</h2>
"
        .to_string(),
    );

    if analysis.pairs.is_empty() {
        parts.push(
            "<p class=\"empty\">No redundant pairs to compare: no two captured hostnames differ only by a trailing number, and the inventory lists no pairs.</p>"
                .to_string(),
        );
    } else {
        let pair_labels = analysis
            .pairs
            .iter()
            .map(|(a, b)| format!("{a} / {b}"))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!(
            "<p class=\"muted\">{} pair(s) compared from the postcheck captures: {}. Same-named prefix-lists and route-maps, and PAN-OS HA state, are checked entry for entry.</p>",
            analysis.pairs.len(),
            escape(&pair_labels)
        ));

        if analysis.pair_findings.is_empty() {
            parts.push("<p class=\"empty\">Both members of every pair agree.</p>".to_string());
        } else {
            for finding in &analysis.pair_findings {
                parts.push(render_finding(finding));
            }
        }
    }

    parts.push(
        "
    </div>

    <div class=\"charts\">
        <div class=\"chart-card\">
            <h3>Operational Health</h3>
            <div class=\"chart-note\">Stable, changed, attention, and action-required classifications.</div>
            <div class=\"chart-wrap\"><canvas id=\"healthChart\"></canvas></div>
        </div>
        <div class=\"chart-card\">
            <h3>Findings by Category</h3>
            <div class=\"chart-note\">Generic categories that remain useful across maintenance types.</div>
            <div class=\"chart-wrap\"><canvas id=\"categoryChart\"></canvas></div>
        </div>
        <div class=\"chart-card\">
            <h3>Device Impact</h3>
            <div class=\"chart-note\">Ranks devices by interpreted operational impact, not raw diff volume.</div>
            <div class=\"chart-wrap\"><canvas id=\"deviceImpactChart\"></canvas></div>
        </div>
    </div>

    <div id=\"device-findings\" class=\"section-title\">
        <div class=\"section-dot\"></div>
        <h2>Device Findings</h2>
    </div>
"
        .to_string(),
    );

    for report in device_reports {
        parts.push(format!(
            "
    <div id=\"device-{device_id}\" class=\"device\">
        <div class=\"device-header\">
            <div class=\"device-name\">{file_name}</div>
            <div class=\"device-summary\">Findings: {findings_count} | Impact Score: {score} | Evidence Sections: {sections}</div>
        </div>

        <div class=\"section\">
            <h3>Protocol / Routing Interpretation</h3>
    ",
            device_id = escape(&report.device_id),
            file_name = escape(&report.file_name),
            findings_count = report.findings_count,
            score = report.impact_score,
            sections = report.diffs.len(),
        ));

        if report.findings.is_empty() {
            parts.push(
                "<p class=\"empty\">No meaningful BGP neighbor, prefix, prefix-list or interface address changes detected.</p>"
                    .to_string(),
            );
        } else {
            for finding in &report.findings {
                parts.push(render_finding(finding));
            }
        }

        parts.push(
            "
        </div>

        <div class=\"section\">
            <h3>Configuration / Policy Changes</h3>
            <div class=\"diff-box\">
    "
            .to_string(),
        );

        if report.config_changes.is_empty() {
            parts.push("<p class=\"empty\">No BGP-related config changes detected.</p>".to_string());
        } else {
            for line in &report.config_changes {
                parts.push(render_diff_line(line.kind, &line.text));
            }
        }

        parts.push(
            "
            </div>
        </div>

        <div class=\"section\">
            <h3>Evidence Only - Collapsible Raw Diffs</h3>
    "
            .to_string(),
        );

        if report.diffs.is_empty() {
            parts.push("<p class=\"empty\">No raw differences detected.</p>".to_string());
        } else {
            for (command, diff_lines) in &report.diffs {
                parts.push(format!(
                    "
            <details>
                <summary>{}</summary>
                <div class=\"diff-box\">
",
                    escape(&raw_diff_label(command))
                ));
                for line in diff_lines {
                    parts.push(render_diff_line(line.kind, &line.text));
                }
                parts.push(
                    "
                </div>
            </details>
"
                    .to_string(),
                );
            }
        }

        parts.push(
            "
        </div>
    </div>
    "
            .to_string(),
        );
    }

    parts.push(format!(
        "
</div>

<div class=\"footer\">
    Generated {generated} | Maintenance Report
</div>

<script>
const healthLabels = {chart_impact_labels};
const healthValues = {chart_impact_values};

const categoryLabels = {chart_classification_labels};
const categoryValues = {chart_classification_values};

const deviceLabels = {chart_device_labels};
const deviceImpact = {chart_device_impact};

{CHART_SCRIPT}</script>

</body>
</html>
",
        generated = escape(generated),
    ));

    parts.join("\n")
}

/// Analyze the latest precheck/postcheck pair and write
/// `Compare/compare_<run_timestamp>.html`, printing the summary.
/// Returns the report path, or `None` when a run folder is missing.
pub fn build_html_report(
    ticket: &str,
    dirs: &TicketDirs,
    run_timestamp: &str,
    pairs: Option<&[(String, String)]>,
    expectations: Option<&[Expectation]>,
    expectations_label: Option<&str>,
) -> anyhow::Result<Option<PathBuf>> {
    let precheck_folder = find_latest_folder(&dirs.precheck, "precheck_");
    let postcheck_folder = find_latest_folder(&dirs.postcheck, "postcheck_");

    let Some(precheck_folder) = precheck_folder else {
        println!("No precheck folder found.");
        return Ok(None);
    };

    let Some(postcheck_folder) = postcheck_folder else {
        println!("No postcheck folder found.");
        return Ok(None);
    };

    fs::create_dir_all(&dirs.compare).with_context(|| format!("creating {}", dirs.compare.display()))?;
    let html_report = dirs.compare.join(format!("compare_{run_timestamp}.html"));

    let analysis = analysis::analyze(&precheck_folder, &postcheck_folder, pairs, expectations)?;
    let page = render_html(
        ticket,
        &precheck_folder,
        &postcheck_folder,
        &analysis,
        expectations_label,
    );

    fs::write(&html_report, page).with_context(|| format!("writing {}", html_report.display()))?;

    println!("HTML comparison report created.");
    println!("Created: {}", display_path(&html_report));

    Ok(Some(html_report))
}

/// The page's stylesheet, byte for byte the Python report's.
const STYLE_SHEET: &str = r##":root {
    --panel: rgba(15, 23, 42, 0.92);
    --text: #e5edf8;
    --muted: #94a3b8;
    --line: rgba(148, 163, 184, 0.22);
    --green: #22c55e;
    --blue: #38bdf8;
    --yellow: #f59e0b;
    --orange: #fb923c;
    --red: #ef4444;
    --purple: #a78bfa;
}

* { box-sizing: border-box; }

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;
    min-height: 100vh;
    font-family: "Segoe UI", Arial, sans-serif;
    background:
        radial-gradient(circle at top left, rgba(56, 189, 248, 0.16), transparent 32%),
        radial-gradient(circle at top right, rgba(167, 139, 250, 0.14), transparent 34%),
        linear-gradient(135deg, #020617 0%, #07111f 48%, #111827 100%);
    color: var(--text);
}

a {
    color: inherit;
    text-decoration: none;
}

.header {
    padding: 34px 44px;
    border-bottom: 1px solid var(--line);
    background: rgba(2, 6, 23, 0.72);
}

.brand {
    display: flex;
    align-items: center;
    gap: 14px;
}

.logo {
    width: 46px;
    height: 46px;
    border-radius: 14px;
    background: linear-gradient(135deg, var(--blue), var(--purple));
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    color: #020617;
}

.header h1 {
    margin: 0;
    font-size: 34px;
    letter-spacing: -0.04em;
}

.subtitle, .muted { color: var(--muted); }

.header-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
    margin-top: 20px;
    color: var(--muted);
    font-size: 13px;
}

.meta-pill {
    border: 1px solid var(--line);
    background: rgba(15, 23, 42, 0.65);
    border-radius: 999px;
    padding: 9px 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.container { padding: 26px 44px 44px 44px; }

.cards {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 28px;
}

.card, .chart-card, .device, .outcome-card, .attention-card {
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.28);
}

.card {
    padding: 18px;
    transition: transform 0.15s ease, border-color 0.15s ease;
}

.card.clickable:hover {
    transform: translateY(-2px);
    border-color: rgba(56, 189, 248, 0.65);
}

.label {
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.value {
    font-size: 30px;
    font-weight: 800;
    margin-top: 8px;
}

.health-stable { color: var(--green); }
.health-changed { color: var(--blue); }
.health-attention { color: var(--yellow); }
.health-action-required { color: var(--red); }

.outcome-card {
    padding: 22px;
    margin-bottom: 28px;
}

.outcome-grid {
    display: grid;
    grid-template-columns: 1.2fr 2fr;
    gap: 18px;
}

.outcome-pill {
    border: 1px solid var(--line);
    background: rgba(2, 6, 23, 0.38);
    border-radius: 14px;
    padding: 14px;
}

.outcome-list {
    margin: 0;
    padding-left: 20px;
    color: #dbeafe;
}

.attention-card {
    padding: 18px;
    margin-bottom: 28px;
    border-left: 4px solid var(--yellow);
}

.pair-card {
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.28);
    padding: 18px;
    margin-bottom: 28px;
    border-left: 4px solid var(--purple);
}

.attention-list {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    margin-top: 12px;
}

.attention-link {
    display: block;
    border: 1px solid var(--line);
    background: rgba(245, 158, 11, 0.10);
    border-radius: 12px;
    padding: 12px;
}

.attention-link:hover {
    border-color: rgba(245, 158, 11, 0.65);
}

.charts {
    display: grid;
    grid-template-columns: 1fr 1fr 1.4fr;
    gap: 16px;
    margin-bottom: 30px;
}

.chart-card { padding: 20px; }

.chart-card h3 { margin: 0 0 6px 0; }

.chart-note {
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 10px;
}

.chart-wrap {
    position: relative;
    height: 300px;
}

.section-title {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 30px 0 14px 0;
}

.section-dot {
    width: 10px;
    height: 10px;
    border-radius: 99px;
    background: var(--blue);
    box-shadow: 0 0 18px var(--blue);
}

.device {
    margin-bottom: 20px;
    overflow: hidden;
    scroll-margin-top: 24px;
}

.device-header {
    padding: 18px 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(90deg, rgba(56, 189, 248, 0.14), rgba(167, 139, 250, 0.08));
    border-bottom: 1px solid var(--line);
}

.device-name {
    font-size: 19px;
    font-weight: 800;
}

.device-summary {
    color: var(--muted);
    font-size: 13px;
}

.section {
    padding: 20px 22px;
    border-bottom: 1px solid var(--line);
}

.section:last-child { border-bottom: none; }

.finding {
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 16px;
    margin-bottom: 12px;
    background: rgba(15, 23, 42, 0.62);
}

.finding.stable {
    border-left: 4px solid var(--green);
    background: rgba(34, 197, 94, 0.14);
}

.finding.changed {
    border-left: 4px solid var(--blue);
    background: rgba(56, 189, 248, 0.12);
}

.finding.attention {
    border-left: 4px solid var(--yellow);
    background: rgba(245, 158, 11, 0.14);
}

.finding.action-required {
    border-left: 4px solid var(--red);
    background: rgba(239, 68, 68, 0.14);
}

.finding-title {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 12px;
}

.badge {
    display: inline-flex;
    border-radius: 999px;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
}

.badge-stable {
    background: rgba(34, 197, 94, 0.18);
    color: #86efac;
    border: 1px solid rgba(34, 197, 94, 0.42);
}

.badge-changed {
    background: rgba(56, 189, 248, 0.18);
    color: #bae6fd;
    border: 1px solid rgba(56, 189, 248, 0.42);
}

.badge-attention {
    background: rgba(245, 158, 11, 0.18);
    color: #fcd34d;
    border: 1px solid rgba(245, 158, 11, 0.42);
}

.badge-action {
    background: rgba(239, 68, 68, 0.18);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.42);
}

.finding-heading, .peer-name { font-weight: 800; }

.peer-ip, .peer-as {
    color: var(--muted);
    font-family: Consolas, monospace;
}

.finding-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 12px;
}

.finding-detail {
    margin-top: 10px;
}

.mini-label {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 6px;
}

.state-flow {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: Consolas, monospace;
    font-size: 14px;
}

.arrow { color: var(--blue); }

.explanation {
    color: #dbeafe;
    line-height: 1.45;
}

.evidence {
    margin-top: 8px;
    color: #bfdbfe;
    font-size: 13px;
}

.diff-box {
    background: rgba(2, 6, 23, 0.72);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 12px;
    overflow-x: auto;
}

.added {
    color: #86efac;
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}

.removed {
    color: #fca5a5;
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}

.context {
    color: var(--muted);
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}

details {
    margin-top: 10px;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: rgba(15, 23, 42, 0.54);
    overflow: hidden;
}

summary {
    cursor: pointer;
    padding: 12px 14px;
    color: #bae6fd;
    font-weight: 800;
}

details .diff-box {
    border: none;
    border-top: 1px solid var(--line);
    border-radius: 0;
}

.empty {
    color: var(--muted);
    font-style: italic;
}

.footer {
    color: var(--muted);
    text-align: center;
    padding: 24px;
    font-size: 12px;
}

@media (max-width: 1200px) {
    .cards, .charts, .outcome-grid, .pair-card {
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.28);
    padding: 18px;
    margin-bottom: 28px;
    border-left: 4px solid var(--purple);
}

.attention-list {
        grid-template-columns: 1fr;
    }

    .header-meta, .finding-grid {
        grid-template-columns: 1fr;
    }
}
"##;

/// The Chart.js setup, byte for byte the Python report's.
const CHART_SCRIPT: &str = r##"Chart.defaults.color = "#cbd5e1";
Chart.defaults.borderColor = "rgba(148, 163, 184, 0.18)";
Chart.defaults.font.family = "Segoe UI, Arial, sans-serif";

new Chart(document.getElementById("healthChart"), {
    type: "doughnut",
    data: {
        labels: healthLabels,
        datasets: [{
            data: healthValues,
            backgroundColor: [
                "rgba(34, 197, 94, 0.78)",
                "rgba(56, 189, 248, 0.78)",
                "rgba(245, 158, 11, 0.78)",
                "rgba(239, 68, 68, 0.78)"
            ],
            borderColor: "rgba(15, 23, 42, 0.92)",
            borderWidth: 3
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: "bottom" }
        },
        cutout: "68%"
    }
});

new Chart(document.getElementById("categoryChart"), {
    type: "bar",
    data: {
        labels: categoryLabels,
        datasets: [{
            label: "Findings / evidence items",
            data: categoryValues,
            backgroundColor: "rgba(56, 189, 248, 0.72)",
            borderRadius: 8
        }]
    },
    options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                beginAtZero: true,
                ticks: { precision: 0 }
            }
        },
        plugins: {
            legend: { display: false }
        }
    }
});

new Chart(document.getElementById("deviceImpactChart"), {
    type: "bar",
    data: {
        labels: deviceLabels,
        datasets: [{
            label: "Impact score",
            data: deviceImpact,
            backgroundColor: "rgba(167, 139, 250, 0.72)",
            borderRadius: 8
        }]
    },
    options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                beginAtZero: true,
                ticks: { precision: 0 }
            }
        },
        plugins: {
            legend: { position: "bottom" }
        }
    }
});
"##;
