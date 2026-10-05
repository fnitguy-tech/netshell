//! Prefix-list findings.
//!
//! A prefix-list entry that vanishes between the captures is a route
//! that stopped being advertised (or accepted), and an entry replaced
//! in place at the same sequence number is the EOS overwrite that a
//! careful change plan is written to avoid. Both must surface as
//! Attention findings, not as one grey line in the raw config diff.

use indexmap::IndexMap;
use mw_check::analysis::prefix_list::{parse_prefix_lists, prefix_list_findings};
use mw_check::analysis::{Classification, DiffLine, Field, Impact};
use mw_check::capture::{Sections, parse_sections_str};

const SHOW_PRE: [&str; 8] = [
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24 ( 812 matches )",
    "   seq 20 permit 198.51.100.0/24",
    "   seq 30 permit 198.51.100.240/28 le 32",
    "   seq 40 permit 198.51.100.243/32",
    "ip prefix-list ISP-IN",
    "   seq 10 deny 0.0.0.0/0",
    "   seq 20 permit 0.0.0.0/0 le 24",
];

fn lines(items: &[&str]) -> Vec<String> {
    items.iter().map(|line| line.to_string()).collect()
}

/// A capture built from `### command ###` sections, parsed the way a
/// capture file is.
fn capture(sections: &[(&str, &[String])]) -> Sections {
    let mut text = String::from("Hostname: SITE-A-SW-1\n");
    for (command, body) in sections {
        text.push_str(&format!(
            "### {command} ###\n--------------------------------------------------------------------------------\n"
        ));
        for line in body.iter() {
            text.push_str(line);
            text.push('\n');
        }
    }
    parse_sections_str(&text)
}

fn sections(show: &[String], config: Option<&[String]>) -> Sections {
    match config {
        Some(config) => capture(&[("show ip prefix-list", show), ("show running-config", config)]),
        None => capture(&[("show ip prefix-list", show)]),
    }
}

fn entries(items: &[(u64, &str)]) -> IndexMap<u64, String> {
    items.iter().map(|(seq, rule)| (*seq, rule.to_string())).collect()
}

#[test]
fn parse_show_output_drops_hit_counters() {
    let lists = parse_prefix_lists(&lines(&SHOW_PRE));

    let mut names: Vec<&String> = lists.keys().collect();
    names.sort();
    assert_eq!(names, ["ISP-IN", "ISP-OUT"]);
    assert_eq!(lists["ISP-OUT"][&10], "permit 203.0.113.0/24");
    assert_eq!(lists["ISP-OUT"][&30], "permit 198.51.100.240/28 le 32");
    assert_eq!(
        lists["ISP-IN"],
        entries(&[(10, "deny 0.0.0.0/0"), (20, "permit 0.0.0.0/0 le 24")])
    );
}

#[test]
fn parse_running_config_block_and_one_line_forms() {
    let config = lines(&[
        "ip prefix-list ISP-OUT",
        "   seq 10 permit 203.0.113.0/24",
        "!",
        "ip prefix-list LOOPBACKS seq 5 permit 192.0.2.0/24 ge 32",
        "ip prefix-list LOOPBACKS seq 10 permit 192.0.2.0/24",
        "!",
        "router bgp 64500",
        "   neighbor 10.0.0.2 remote-as 64500",
    ]);

    let lists = parse_prefix_lists(&config);

    assert_eq!(lists.len(), 2);
    assert_eq!(lists["ISP-OUT"], entries(&[(10, "permit 203.0.113.0/24")]));
    assert_eq!(
        lists["LOOPBACKS"],
        entries(&[(5, "permit 192.0.2.0/24 ge 32"), (10, "permit 192.0.2.0/24")])
    );
}

#[test]
fn untouched_lists_produce_no_findings() {
    // Only the hit counter moved.
    let post: Vec<String> = SHOW_PRE
        .iter()
        .map(|line| line.replace("812 matches", "944 matches"))
        .collect();

    assert_eq!(
        prefix_list_findings(&sections(&lines(&SHOW_PRE), None), &sections(&post, None)),
        []
    );
}

#[test]
fn removed_entry_is_attention() {
    let post = lines(
        &SHOW_PRE
            .iter()
            .copied()
            .filter(|line| !line.contains("seq 40"))
            .collect::<Vec<_>>(),
    );

    let findings = prefix_list_findings(&sections(&lines(&SHOW_PRE), None), &sections(&post, None));

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.title, "Prefix-List Entry Removed");
    assert_eq!(finding.impact, Impact::Attention);
    assert_eq!(finding.classification, Classification::Routing);
    assert_eq!(finding.subject, ["ISP-OUT", "seq 40"]);
    assert!(
        finding
            .fields
            .contains(&Field::new("Entry", "permit 198.51.100.243/32", "Not Present"))
    );
    assert_eq!(finding.evidence, "show ip prefix-list");
    assert!(finding.summary.contains("isn't advertised any more"));
}

#[test]
fn same_seq_different_prefix_is_attention() {
    // The replace-by-sequence overwrite: seq 40 was meant to be a new
    // entry but it already existed, so the old prefix is gone.
    let post: Vec<String> = SHOW_PRE
        .iter()
        .map(|line| line.replace("seq 40 permit 198.51.100.243/32", "seq 40 permit 198.51.100.244/32"))
        .collect();

    let findings = prefix_list_findings(&sections(&lines(&SHOW_PRE), None), &sections(&post, None));

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.title, "Prefix-List Entry Replaced");
    assert_eq!(finding.impact, Impact::Attention);
    assert!(finding.fields.contains(&Field::new(
        "Entry",
        "permit 198.51.100.243/32",
        "permit 198.51.100.244/32"
    )));
    assert!(finding.summary.contains("no longer appears anywhere"));
}

#[test]
fn new_seq_is_stable() {
    let mut post = lines(&SHOW_PRE[..5]);
    post.push("   seq 50 permit 198.51.100.244/32".to_string());
    post.extend(lines(&SHOW_PRE[5..]));

    let findings = prefix_list_findings(&sections(&lines(&SHOW_PRE), None), &sections(&post, None));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Prefix-List Entry Added");
    assert_eq!(findings[0].impact, Impact::Stable);
    assert_eq!(findings[0].subject, ["ISP-OUT", "seq 50"]);
}

#[test]
fn resequenced_entry_is_changed_not_withdrawn() {
    let post: Vec<String> = SHOW_PRE
        .iter()
        .map(|line| line.replace("seq 40 permit", "seq 45 permit"))
        .collect();

    let findings = prefix_list_findings(&sections(&lines(&SHOW_PRE), None), &sections(&post, None));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Prefix-List Entry Moved");
    assert_eq!(findings[0].impact, Impact::Changed);
    assert!(findings[0].fields.contains(&Field::new("Sequence", "40", "45")));
}

#[test]
fn whole_list_removed_is_one_attention_finding_with_detail() {
    let post = lines(&SHOW_PRE[5..]);

    let findings = prefix_list_findings(&sections(&lines(&SHOW_PRE), None), &sections(&post, None));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Prefix-List Removed");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(findings[0].subject, ["ISP-OUT"]);
    assert!(
        findings[0]
            .detail
            .contains(&DiffLine::removed("seq 40 permit 198.51.100.243/32"))
    );
}

#[test]
fn falls_back_to_running_config_when_show_is_not_captured() {
    let pre = capture(&[(
        "show running-config",
        &lines(&["ip prefix-list ISP-OUT", "   seq 10 permit 203.0.113.0/24", "!"]),
    )]);
    let post = capture(&[("show running-config", &lines(&["ip prefix-list ISP-OUT", "!"]))]);

    let findings = prefix_list_findings(&pre, &post);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Prefix-List Entry Removed");
    assert_eq!(findings[0].evidence, "show running-config");
}

/// The capture file the Python test writes to disk before running the
/// whole analysis; here it is parsed and interpreted directly.
fn full_capture(prefix_lines: &[String]) -> Sections {
    parse_sections_str(&format!(
        "Hostname: SITE-A-SW-1\n\
         ### show ip bgp summary ###\n--------------------------------------------------------------------------------\n  \
         ISP-B  198.51.100.9  4 64497  213  201  0  0  00:52:40  Estab  815  815\n\
         ### show ip prefix-list ###\n--------------------------------------------------------------------------------\n{}\n\
         ### show running-config ###\n--------------------------------------------------------------------------------\n\
         router bgp 64500\n   \
         neighbor 198.51.100.9 remote-as 64497\n",
        prefix_lines.join("\n")
    ))
}

#[test]
fn prefix_list_removal_in_a_full_capture_is_one_attention_routing_finding() {
    let pre = full_capture(&lines(&SHOW_PRE));
    let post = full_capture(&lines(
        &SHOW_PRE
            .iter()
            .copied()
            .filter(|line| !line.contains("seq 40"))
            .collect::<Vec<_>>(),
    ));

    let findings = prefix_list_findings(&pre, &post);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Prefix-List Entry Removed");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(findings[0].classification, Classification::Routing);
    assert_eq!(findings[0].evidence, "show ip prefix-list");
    assert!(
        findings[0]
            .fields
            .iter()
            .any(|field| field.before == "permit 198.51.100.243/32")
    );
}
