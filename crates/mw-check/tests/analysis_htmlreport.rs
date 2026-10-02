//! Port of the parts of the Python `tests/test_htmlreport.py` that
//! exercise normalization, BGP parsing, BGP findings and raw-diff
//! classification.

use std::collections::BTreeMap;

use mw_check::analysis::bgp::{bgp_neighbor_findings, parse_bgp_summary};
use mw_check::analysis::normalize::clean_line_for_compare;
use mw_check::analysis::rawdiff::classify_raw_diff_commands;
use mw_check::analysis::{Classification, Impact};
use mw_check::capture::Sections;

const BGP_ESTAB: &str = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Estab 100 98";
const BGP_IDLE: &str = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Idle(Admin)";

fn sections(command: &str, lines: &[&str]) -> Sections {
    let mut sections = Sections::new();
    sections.insert(command.to_string(), lines.iter().map(|line| line.to_string()).collect());
    sections
}

#[test]
fn parse_bgp_summary_reads_the_peer_row() {
    let peers = parse_bgp_summary(&["Neighbor V AS MsgRcvd".to_string(), BGP_ESTAB.to_string()]);

    assert_eq!(peers.len(), 1);
    let peer = &peers[0];
    assert_eq!(peer.name, "SPINE1");
    assert_eq!(peer.ip, "203.0.113.1");
    assert_eq!(peer.as_number, "65001");
    assert_eq!(peer.state, "Estab");
    assert_eq!(peer.prefixes_received, "100");
    assert_eq!(peer.prefixes_accepted, "98");
}

#[test]
fn clean_line_collapses_bgp_summary() {
    assert_eq!(
        clean_line_for_compare("show ip bgp summary", BGP_ESTAB).unwrap(),
        "SPINE1 203.0.113.1 AS65001 Estab 100 98"
    );
}

#[test]
fn clean_line_rules_for_other_commands() {
    assert_eq!(
        clean_line_for_compare("show ip bgp summary", BGP_IDLE).unwrap(),
        "SPINE1 203.0.113.1 AS65001 Idle(Admin)"
    );
    assert_eq!(
        clean_line_for_compare(
            "show ip bgp summary",
            "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 never Active"
        )
        .unwrap(),
        "SPINE1 203.0.113.1 AS65001 Active"
    );
    // Fewer than ten columns: left alone.
    assert_eq!(
        clean_line_for_compare("show ip bgp summary", "Neighbor V AS MsgRcvd").unwrap(),
        "Neighbor V AS MsgRcvd"
    );

    assert!(clean_line_for_compare("show interfaces transceiver", "anything").is_none());
    assert!(clean_line_for_compare("show logging last 200", "anything").is_none());
    assert!(clean_line_for_compare("show version", "  Uptime: 3 days").is_none());
    assert!(clean_line_for_compare("show system info", "uptime: 3 days").is_none());
    assert_eq!(
        clean_line_for_compare("show running-config", "   Uptime: kept verbatim").unwrap(),
        "   Uptime: kept verbatim"
    );

    assert_eq!(
        clean_line_for_compare(
            "show ip ospf neighbor",
            "1.1.1.1 1 FULL/DR 00:00:35 10.0.0.1 Ethernet1 0 0"
        )
        .unwrap(),
        "1.1.1.1 1 FULL/DR 00:00:35 10.0.0.1 0 0"
    );
    assert_eq!(
        clean_line_for_compare("show ip arp", "10.0.0.1 0:01:02 0011.2233.4455 Ethernet1").unwrap(),
        "10.0.0.1 0011.2233.4455 Ethernet1"
    );
    assert_eq!(
        clean_line_for_compare("show ip route", "O 10.0.0.0/24 [110/20] via 10.0.0.1, 3 Ethernet1").unwrap(),
        "O 10.0.0.0/24 [110/20] via 10.0.0.1, Ethernet1"
    );
    assert_eq!(
        clean_line_for_compare("show mac address-table", "240 0011.2233.4455 DYNAMIC Et1 0:01:02 ago").unwrap(),
        "240 0011.2233.4455 DYNAMIC Et1"
    );
    // The clock rule runs first; what it leaves no longer ends in "ago".
    assert_eq!(
        clean_line_for_compare("show lldp neighbors", "Et1 sw2 Et1 2 days, 1:02:03 ago").unwrap(),
        "Et1 sw2 Et1 2 days,"
    );
    assert_eq!(
        clean_line_for_compare("show lldp neighbors", "Et1 sw2 Et1 2 days, 1 hour ago").unwrap(),
        "Et1 sw2 Et1"
    );
    assert_eq!(
        clean_line_for_compare("show lldp neighbors", "Et1 sw2 Et1 120").unwrap(),
        "Et1 sw2 Et1 120"
    );
}

#[test]
fn peer_removed_is_attention() {
    let pre = sections("show ip bgp summary", &[BGP_ESTAB]);
    let post = sections("show ip bgp summary", &[]);

    let findings = bgp_neighbor_findings(&pre, &post, &[], None);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "BGP Peer Removed From Summary");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(findings[0].classification, Classification::Protocol);
    assert_eq!(findings[0].category, "BGP state");
    assert_eq!(findings[0].subject, ["SPINE1", "203.0.113.1", "AS65001"]);
    assert_eq!(findings[0].fields[0].after, "Not Present");
    assert_eq!(findings[0].fields[3].after, "Not Present");
    let bgp = findings[0].bgp.as_ref().unwrap();
    assert_eq!(bgp.peer.ip, "203.0.113.1");
    assert!(bgp.before.is_some());
    assert!(bgp.after.is_none());
}

#[test]
fn peer_added_is_stable() {
    let pre = sections("show ip bgp summary", &[]);
    let post = sections("show ip bgp summary", &[BGP_ESTAB]);

    let findings = bgp_neighbor_findings(&pre, &post, &[], None);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "BGP Peer Added");
    assert_eq!(findings[0].impact, Impact::Stable);
    assert_eq!(findings[0].fields[0].before, "Not Present");
    assert_eq!(findings[0].fields[0].after, "Estab");
}

#[test]
fn admin_shutdown_is_attention() {
    let pre = sections("show ip bgp summary", &[BGP_ESTAB]);
    let post = sections("show ip bgp summary", &[BGP_IDLE]);

    let findings = bgp_neighbor_findings(&pre, &post, &[], None);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "BGP Peer Administratively Disabled");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(
        findings[0].summary,
        "The peer transitioned from established to administratively idle."
    );
    assert_eq!(findings[0].evidence, "show ip bgp summary");
}

#[test]
fn activation_is_stable_and_other_state_changes_attention() {
    let idle = sections("show ip bgp summary", &[BGP_IDLE]);
    let estab = sections("show ip bgp summary", &[BGP_ESTAB]);

    let findings = bgp_neighbor_findings(&idle, &estab, &[], None);
    assert_eq!(findings[0].title, "BGP Peer Activated");
    assert_eq!(findings[0].impact, Impact::Stable);

    let active = sections(
        "show ip bgp summary",
        &["SPINE1 203.0.113.1 4 65001 12345 12340 0 0 never Active"],
    );
    let findings = bgp_neighbor_findings(&estab, &active, &[], None);
    assert_eq!(findings[0].title, "BGP Peer State Changed");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(findings[0].fields[0].after, "Active");
}

#[test]
fn classify_raw_diff_commands_counts_by_category() {
    let diffs: BTreeMap<String, Vec<mw_check::analysis::DiffLine>> = [
        "show running-config",
        "show ip bgp summary",
        "show interfaces status",
        "show vpn flow",
        "show vpn ipsec-sa",
        "show hobbies",
    ]
    .iter()
    .map(|command| (command.to_string(), Vec::new()))
    .collect();

    let categories = classify_raw_diff_commands(&diffs);

    assert_eq!(categories.get(Classification::Configuration), 1);
    assert_eq!(categories.get(Classification::Protocol), 3);
    assert_eq!(categories.get(Classification::Interface), 1);
    assert_eq!(categories.get(Classification::EvidenceOnly), 1);
    assert_eq!(categories.get(Classification::Routing), 0);
    assert_eq!(categories.total(), 6);
}

#[test]
fn clean_line_applies_shared_vpn_rule() {
    let pre = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x1a2b3c4d  CAFEF00D  1234";
    let post = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x9f8e7d6c  DEADBEEF  1301";
    assert_eq!(
        clean_line_for_compare("show vpn ike-sa", pre),
        clean_line_for_compare("show vpn ike-sa", post)
    );
    assert!(clean_line_for_compare("show global-protect-gateway current-satellite", "  Login Time : x").is_none());
}
