//! Pair symmetry.
//!
//! The real signature of a change applied to one member of a redundant
//! pair is not "a line vanished" but "SW-1 and SW-2 now disagree". A
//! per-device report cannot see that, so the two postcheck captures of
//! a pair are compared against each other: same-named prefix-lists and
//! route-maps entry for entry, and the parts of PAN-OS HA state that
//! do not depend on which member is active.

use mw_check::analysis::pairs::{infer_pairs, pair_findings, parse_ha_state, parse_route_maps, resolve_pairs};
use mw_check::analysis::prefix_list::prefix_list_findings;
use mw_check::analysis::{Classification, DiffLine, Field, Impact};
use mw_check::capture::{Sections, parse_sections_str};

const PREFIX_LIST: [&str; 4] = [
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24",
    "   seq 20 permit 198.51.100.0/24",
    "   seq 40 permit 198.51.100.243/32",
];

const ROUTE_MAP: [&str; 10] = [
    "route-map ISP-OUT permit 10",
    "  Description:",
    "  Match clauses:",
    "    match ip address prefix-list ISP-OUT",
    "  Match clauses hit: 4211",
    "  Set clauses:",
    "    set community 64500:100",
    "route-map ISP-OUT deny 20",
    "  Match clauses:",
    "  Set clauses:",
];

fn ha_state(state: &str, mgmt: &str, priority: u32, build: &str, cookie: &str, peer_state: &str) -> String {
    format!(
        "Mode: Active-Passive\n\
         Local Information:\n        \
         Version: 1\n        \
         Mode: Active-Passive\n        \
         State: {state} (last 61 days)\n        \
         Device Information:\n                \
         Management IPv4 Address: {mgmt}/24\n        \
         HA1 Control Links Joint Configuration:\n                \
         Encryption Enabled: no\n        \
         Election Option Information:\n                \
         Priority: {priority}\n                \
         Preemptive: no\n        \
         Version Information:\n                \
         Build Release: {build}\n                \
         Application Content: Match\n        \
         Session Synchronization Cookie: {cookie}\n\
         Peer Information:\n        \
         Connection status: up\n        \
         State: {peer_state}\n"
    )
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|line| line.to_string()).collect()
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

fn titles(findings: &[mw_check::analysis::Finding]) -> Vec<&str> {
    findings.iter().map(|finding| finding.title.as_str()).collect()
}

/// A capture with the running config every member has, plus whichever
/// of the compared commands the test gives it.
fn capture(prefix_lines: Option<&[&str]>, route_map_lines: Option<&[&str]>, ha: Option<&str>) -> Sections {
    let mut text = String::from("Hostname: x\n### show running-config ###\nhostname x\n");
    if let Some(lines) = prefix_lines {
        text.push_str("### show ip prefix-list ###\n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
    }
    if let Some(lines) = route_map_lines {
        text.push_str("### show route-map ###\n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
    }
    if let Some(ha) = ha {
        text.push_str("### show high-availability state ###\n");
        text.push_str(ha);
    }
    parse_sections_str(&text)
}

#[test]
fn infer_pairs_by_trailing_number() {
    let hosts = strings(&[
        "SITE-A-SW-1",
        "SITE-A-SW-2",
        "SITE-B-SW-1",
        "SITE-A-FW-1",
        "SITE-A-FW-2",
        "LEAF-1",
        "LEAF-2",
        "LEAF-3",
    ]);

    assert_eq!(
        infer_pairs(&hosts),
        [pair("SITE-A-FW-1", "SITE-A-FW-2"), pair("SITE-A-SW-1", "SITE-A-SW-2")]
    );
}

#[test]
fn bare_ip_captures_are_never_paired() {
    assert_eq!(infer_pairs(&strings(&["192.0.2.11", "192.0.2.12"])), []);
}

#[test]
fn explicit_pairs_take_precedence_and_inference_covers_the_rest() {
    let hosts = strings(&["CORE-EAST", "CORE-WEST", "SITE-A-SW-1", "SITE-A-SW-2", "EDGE-1"]);

    let pairs = resolve_pairs(
        &hosts,
        Some(&[pair("core-east", "CORE-WEST"), pair("EDGE-1", "EDGE-2")]),
    );

    // EDGE-2 was not captured, so that explicit pair is skipped.
    assert_eq!(
        pairs,
        [pair("CORE-EAST", "CORE-WEST"), pair("SITE-A-SW-1", "SITE-A-SW-2")]
    );
}

#[test]
fn parse_route_maps_drops_hit_counters() {
    let maps = parse_route_maps(&strings(&ROUTE_MAP));

    assert_eq!(maps.keys().collect::<Vec<_>>(), ["ISP-OUT"]);
    assert!(!maps["ISP-OUT"].join(" ").contains("Match clauses hit: 4211"));
    assert!(maps["ISP-OUT"].contains(&"match ip address prefix-list ISP-OUT".to_string()));
    assert_eq!(maps["ISP-OUT"][0], "route-map permit 10");
}

#[test]
fn parse_ha_state_ignores_role_dependent_keys() {
    let text = ha_state("active", "10.1.1.1", 100, "11.1.4-h7", "0x5", "passive");
    let values = parse_ha_state(&strings(&text.lines().collect::<Vec<_>>()));

    assert!(!values.contains_key("Local Information/State"));
    assert!(!values.contains_key("Local Information/Election Option Information/Priority"));
    assert!(!values.contains_key("Local Information/Device Information/Management IPv4 Address"));
    assert_eq!(
        values["Local Information/Version Information/Build Release"],
        "11.1.4-h7"
    );
    assert_eq!(values["Local Information/Session Synchronization Cookie"], "0x5");
    // Peer Information describes the other box and is not part of the local view.
    assert!(!values.keys().any(|key| key.starts_with("Peer")));
}

#[test]
fn prefix_list_divergence_is_attention_on_both_devices() {
    let pair = pair("SITE-A-SW-1", "SITE-A-SW-2");
    let sw1 = capture(Some(&PREFIX_LIST), None, None);
    let without_seq_40: Vec<&str> = PREFIX_LIST
        .iter()
        .copied()
        .filter(|line| !line.contains("seq 40"))
        .collect();
    let sw2 = capture(Some(&without_seq_40), None, None);

    let findings = pair_findings(&pair, &sw1, &sw2, None, None);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.title, "Pair Prefix-List Divergence");
    assert_eq!(finding.impact, Impact::Attention);
    assert_eq!(finding.category, "Pair symmetry");
    assert_eq!(finding.devices, ["SITE-A-SW-1", "SITE-A-SW-2"]);
    assert_eq!(finding.subject, ["SITE-A-SW-1 vs SITE-A-SW-2", "ISP-OUT"]);
    assert_eq!(
        finding.fields,
        [Field::new("seq 40", "permit 198.51.100.243/32", "Not Present")]
    );
    assert_eq!(finding.arrow, "vs");
}

#[test]
fn identical_members_produce_nothing() {
    let pair = pair("SITE-A-SW-1", "SITE-A-SW-2");
    let sw = capture(Some(&PREFIX_LIST), Some(&ROUTE_MAP), None);

    assert_eq!(pair_findings(&pair, &sw, &sw.clone(), None, None), []);
}

#[test]
fn lists_present_on_one_member_only_are_not_compared_unless_both_had_them() {
    let pair = pair("SITE-A-SW-1", "SITE-A-SW-2");
    let sw1 = capture(Some(&PREFIX_LIST), None, None);
    let sw2 = capture(Some(&[]), None, None);

    // Different roles, different lists: nothing to say without a precheck.
    assert_eq!(pair_findings(&pair, &sw1, &sw2, None, None), []);

    // Both had it before the window and one lost it: that is a finding.
    let findings = pair_findings(&pair, &sw1, &sw2, Some(&sw1), Some(&sw1));
    assert_eq!(titles(&findings), ["Pair Prefix-List Missing On One Device"]);
    assert!(findings[0].summary.contains("SITE-A-SW-2 no longer has it"));
    assert_eq!(findings[0].fields, [Field::new("Entries", "3", "Not Present")]);
}

#[test]
fn route_map_divergence_lists_the_differing_lines() {
    let pair = pair("SITE-A-SW-1", "SITE-A-SW-2");
    let sw1 = capture(None, Some(&ROUTE_MAP), None);
    let changed: Vec<String> = ROUTE_MAP
        .iter()
        .map(|line| line.replace("64500:100", "64500:200"))
        .collect();
    let changed: Vec<&str> = changed.iter().map(String::as_str).collect();
    let sw2 = capture(None, Some(&changed), None);

    let findings = pair_findings(&pair, &sw1, &sw2, None, None);

    assert_eq!(titles(&findings), ["Pair Route-Map Divergence"]);
    assert_eq!(findings[0].impact, Impact::Attention);
    assert!(
        findings[0]
            .detail
            .contains(&DiffLine::removed("SITE-A-SW-1: set community 64500:100"))
    );
    assert!(
        findings[0]
            .detail
            .contains(&DiffLine::added("SITE-A-SW-2: set community 64500:200"))
    );
    assert_eq!(
        findings[0].fields,
        [Field::new("Lines", "9", "9"), Field::new("Differing lines", "1", "1")]
    );
    assert_eq!(findings[0].evidence, "show route-map");
}

#[test]
fn ha_cookie_split_is_attention_but_active_passive_is_not() {
    let pair = pair("SITE-A-FW-1", "SITE-A-FW-2");
    let fw1 = capture(
        None,
        None,
        Some(&ha_state("active", "10.1.1.1", 100, "11.1.4-h7", "0x5", "passive")),
    );
    let fw2_in_sync = capture(
        None,
        None,
        Some(&ha_state("passive", "10.1.1.2", 110, "11.1.4-h7", "0x5", "active")),
    );
    let fw2_split = capture(
        None,
        None,
        Some(&ha_state("passive", "10.1.1.2", 110, "11.1.4-h7", "0x0", "active")),
    );

    assert_eq!(pair_findings(&pair, &fw1, &fw2_in_sync, None, None), []);

    let findings = pair_findings(&pair, &fw1, &fw2_split, None, None);
    assert_eq!(titles(&findings), ["Pair HA State Divergence"]);
    assert_eq!(findings[0].classification, Classification::Protocol);
    assert_eq!(
        findings[0].fields,
        [Field::new(
            "Local Information/Session Synchronization Cookie",
            "0x5",
            "0x0"
        )]
    );
    assert_eq!(findings[0].evidence, "show high-availability state");
}

/// The capture file the Python test writes to disk for each member.
fn member_capture(hostname: &str, prefix_lines: &[&str]) -> Sections {
    parse_sections_str(&format!(
        "Hostname: {hostname}\n### show ip prefix-list ###\n{}\n### show running-config ###\nhostname {hostname}\n",
        prefix_lines.join("\n")
    ))
}

#[test]
fn pair_finding_is_attributed_to_both_devices_beside_their_own_findings() {
    let overwritten: Vec<String> = PREFIX_LIST
        .iter()
        .map(|line| line.replace("seq 40 permit 198.51.100.243/32", "seq 40 permit 198.51.100.244/32"))
        .collect();
    let overwritten: Vec<&str> = overwritten.iter().map(String::as_str).collect();

    let pre_sw1 = member_capture("SITE-A-SW-1", &PREFIX_LIST);
    let post_sw1 = member_capture("SITE-A-SW-1", &PREFIX_LIST);
    let pre_sw2 = member_capture("SITE-A-SW-2", &PREFIX_LIST);
    let post_sw2 = member_capture("SITE-A-SW-2", &overwritten);
    let pre_sb1 = member_capture("SITE-B-SW-1", &PREFIX_LIST);
    let post_sb1 = member_capture("SITE-B-SW-1", &PREFIX_LIST);

    let hosts = strings(&["SITE-A-SW-1", "SITE-A-SW-2", "SITE-B-SW-1"]);
    let pairs = resolve_pairs(&hosts, None);
    assert_eq!(pairs, [pair("SITE-A-SW-1", "SITE-A-SW-2")]);

    let found = pair_findings(&pairs[0], &post_sw1, &post_sw2, Some(&pre_sw1), Some(&pre_sw2));
    assert_eq!(titles(&found), ["Pair Prefix-List Divergence"]);
    assert_eq!(found[0].impact, Impact::Attention);
    // Attributed to both members; the first member counts it in totals.
    assert_eq!(found[0].devices, ["SITE-A-SW-1", "SITE-A-SW-2"]);
    assert_eq!(found[0].subject[0], "SITE-A-SW-1 vs SITE-A-SW-2");
    assert_eq!(
        found[0].fields,
        [Field::new(
            "seq 40",
            "permit 198.51.100.243/32",
            "permit 198.51.100.244/32"
        )]
    );

    // SW-2 also has its own per-device overwrite finding; SW-1 only the pair one.
    assert_eq!(prefix_list_findings(&pre_sw1, &post_sw1), []);
    let own = prefix_list_findings(&pre_sw2, &post_sw2);
    assert_eq!(titles(&own), ["Prefix-List Sequence Overwritten"]);
    assert_eq!(own[0].impact, Impact::Attention);
    assert_eq!(prefix_list_findings(&pre_sb1, &post_sb1), []);
}

#[test]
fn explicit_pairs_are_compared_where_nothing_would_be_inferred() {
    let pre_east = member_capture("CORE-EAST", &PREFIX_LIST);
    let post_east = member_capture("CORE-EAST", &PREFIX_LIST);
    let pre_west = member_capture("CORE-WEST", &PREFIX_LIST);
    let post_west = member_capture("CORE-WEST", &PREFIX_LIST[..2]);

    let hosts = strings(&["CORE-EAST", "CORE-WEST"]);
    assert_eq!(resolve_pairs(&hosts, None), []);

    let pairs = resolve_pairs(&hosts, Some(&[pair("CORE-EAST", "CORE-WEST")]));
    assert_eq!(pairs, [pair("CORE-EAST", "CORE-WEST")]);

    let found = pair_findings(&pairs[0], &post_east, &post_west, Some(&pre_east), Some(&pre_west));
    assert_eq!(titles(&found), ["Pair Prefix-List Divergence"]);
}
