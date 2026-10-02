//! BGP session uptime. Port of the Python `tests/test_bgp_uptime.py`.
//!
//! The raw diff strips the Up/Down column because it moves on every
//! capture. The interpreted layer reads it on purpose: a peer that
//! reset and came straight back is Estab in both captures with the
//! same prefix counts, and a smaller uptime in the postcheck is the
//! only trace it leaves. These tests pin both the formats and the rule
//! that a reset is only ever flagged when the post value is
//! unambiguously smaller.

use mw_check::analysis::bgp::{bgp_neighbor_findings, parse_bgp_summary, parse_panos_bgp_peers, parse_uptime};
use mw_check::analysis::{Classification, Field, Impact};
use mw_check::capture::Sections;

fn row(updown: &str) -> String {
    format!("  ISP-B  198.51.100.9  4 64497  213  201  0  0  {updown}  Estab  815  815")
}

fn panos_block(secs: u64) -> Vec<String> {
    format!(
        "Peer: EACN-PEER-1 (id 1)\n  virtual router: default\n  Peer router id: 10.40.0.1\n  \
         Remote AS: 64510, peer group: EACN\n  Peer status: Established, for {secs} secs\n  \
         Peer address: 10.40.0.1:179\n  Local address: 10.40.0.2:179\n  \
         Prefix counter for AFI/SAFI: ipv4 unicast\n    Incoming total: 5, accepted: 5, rejected: 0\n    \
         Outgoing total: 3\n"
    )
    .lines()
    .map(str::to_string)
    .collect()
}

fn sections(command: &str, lines: Vec<String>) -> Sections {
    let mut sections = Sections::new();
    sections.insert(command.to_string(), lines);
    sections
}

fn summary(updown: &str) -> Sections {
    sections("show ip bgp summary", vec![row(updown)])
}

#[test]
fn parse_uptime_formats() {
    assert_eq!(parse_uptime("01:02:03"), Some((3723, 1)));
    assert_eq!(parse_uptime("00:12:33"), Some((753, 1)));
    assert_eq!(parse_uptime("1d02h"), Some((26 * 3600, 3600)));
    assert_eq!(parse_uptime("2w3d"), Some((17 * 86400, 86400)));
    assert_eq!(parse_uptime("5d02h"), Some((5 * 86400 + 2 * 3600, 3600)));
    assert_eq!(parse_uptime("123456 secs"), Some((123456, 1)));
    assert_eq!(parse_uptime("1y2w"), Some((365 * 86400 + 14 * 86400, 7 * 86400)));
    assert_eq!(parse_uptime(" 1 sec "), Some((1, 1)));
}

#[test]
fn parse_uptime_refuses_to_guess() {
    assert_eq!(parse_uptime("never"), None);
    assert_eq!(parse_uptime("Estab"), None);
    assert_eq!(parse_uptime(""), None);
}

#[test]
fn summary_keeps_updown_column() {
    let peers = parse_bgp_summary(&[row("5d02h")]);

    assert_eq!(peers[0].name, "ISP-B");
    assert_eq!(peers[0].ip, "198.51.100.9");
    assert_eq!(peers[0].updown.as_deref(), Some("5d02h"));
    assert_eq!(peers[0].state, "Estab");

    let idle =
        parse_bgp_summary(&["  ISP-A  198.51.100.1  4 64496  48377  48102  0  0  00:01:12  Idle(Admin)".to_string()]);
    assert_eq!(idle[0].updown.as_deref(), Some("00:01:12"));
    assert_eq!(idle[0].state, "Idle(Admin)");

    let never = parse_bgp_summary(&["  NEW  198.51.100.17  4 64498  0  0  0  0  never  Active".to_string()]);
    assert_eq!(never[0].updown.as_deref(), Some("never"));
    assert_eq!(never[0].state, "Active");

    // Too short a row to hold an Up/Down column after the AS.
    let short = parse_bgp_summary(&["  X  198.51.100.2  4 64499 Estab".to_string()]);
    assert_eq!(short[0].updown, None);
    assert_eq!(short[0].as_number, "64499");
}

#[test]
fn uptime_going_backwards_is_a_reset() {
    let findings = bgp_neighbor_findings(&summary("5d02h"), &summary("00:12:33"), &[], None);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.title, "BGP Session Reset");
    assert_eq!(finding.impact, Impact::Attention);
    assert_eq!(finding.classification, Classification::Protocol);
    assert!(finding.fields.contains(&Field::new("Up/Down", "5d02h", "00:12:33")));
    assert!(finding.summary.contains("dropped and came back during the window"));
    assert!(finding.summary.contains("Prefix counts came back the same."));
    assert!(finding.summary.contains("went from 5d02h to 00:12:33"));
}

#[test]
fn uptime_growing_is_not_a_finding() {
    assert!(bgp_neighbor_findings(&summary("5d02h"), &summary("5d04h"), &[], None).is_empty());
    assert!(bgp_neighbor_findings(&summary("23:59:10"), &summary("1d02h"), &[], None).is_empty());
    assert!(bgp_neighbor_findings(&summary("6d23h"), &summary("1w0d"), &[], None).is_empty());
}

#[test]
fn equal_coarse_uptime_is_not_a_reset() {
    // 34d11h in both captures: the true values differ by two hours but
    // the format cannot show it, and equal is not smaller.
    assert!(bgp_neighbor_findings(&summary("34d11h"), &summary("34d11h"), &[], None).is_empty());
}

#[test]
fn boundary_of_coarse_format_is_not_a_reset() {
    // 1d02h means [26h, 27h); a post value of 1d02h can never be shown
    // to be below a pre value of 1d02h, only 1d01h can.
    assert!(bgp_neighbor_findings(&summary("1d02h"), &summary("1d02h"), &[], None).is_empty());
    let findings = bgp_neighbor_findings(&summary("1d02h"), &summary("1d01h"), &[], None);
    assert_eq!(
        findings.iter().map(|f| f.title.as_str()).collect::<Vec<_>>(),
        ["BGP Session Reset"]
    );
}

#[test]
fn unparsable_uptime_never_flags() {
    assert!(bgp_neighbor_findings(&summary("never"), &summary("00:10:00"), &[], None).is_empty());
    assert!(bgp_neighbor_findings(&summary("5d02h"), &summary("never"), &[], None).is_empty());
}

#[test]
fn reset_with_prefix_change_is_one_attention_finding() {
    let post = sections(
        "show ip bgp summary",
        vec![row("00:12:33").replace("815  815", "812  812")],
    );

    let findings = bgp_neighbor_findings(&summary("5d02h"), &post, &[], None);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "BGP Session Reset");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert!(findings[0].summary.contains("changed by -3 across the reset"));
    assert!(
        findings[0]
            .fields
            .contains(&Field::new("Prefixes Received", "815", "812"))
    );
}

#[test]
fn panos_peer_block_parses_like_a_summary_row() {
    let peers = parse_panos_bgp_peers(&panos_block(123456));

    assert_eq!(peers.len(), 1);
    let peer = &peers[0];
    assert_eq!(peer.name, "EACN-PEER-1");
    assert_eq!(peer.ip, "10.40.0.1");
    assert_eq!(peer.as_number, "64510");
    assert_eq!(peer.state, "Estab");
    assert_eq!(peer.updown.as_deref(), Some("123456 secs"));
    assert_eq!(peer.prefixes_received, "5");
    assert_eq!(peer.prefixes_accepted, "5");
}

#[test]
fn panos_peer_without_an_address_is_not_a_peer() {
    let lines: Vec<String> = ["Peer: LONELY (id 2)", "  Remote AS: 64511", "  Peer status: Idle"]
        .iter()
        .map(|line| line.to_string())
        .collect();
    assert!(parse_panos_bgp_peers(&lines).is_empty());

    // Fields read before the address line still land on the peer.
    let mut ordered = lines.clone();
    ordered.push("  Peer address: 10.40.0.9:179".to_string());
    let peers = parse_panos_bgp_peers(&ordered);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].as_number, "64511");
    assert_eq!(peers[0].state, "Idle");
    assert_eq!(peers[0].updown, None);
}

#[test]
fn panos_peer_reset_is_attention() {
    let pre = sections("show routing protocol bgp peer", panos_block(123456));
    let post = sections("show routing protocol bgp peer", panos_block(310));

    let findings = bgp_neighbor_findings(&pre, &post, &[], None);

    assert_eq!(
        findings.iter().map(|f| f.title.as_str()).collect::<Vec<_>>(),
        ["BGP Session Reset"]
    );
    assert_eq!(findings[0].subject, ["EACN-PEER-1", "10.40.0.1", "AS64510"]);

    // Same peer, uptime grew: nothing to report.
    let later = sections("show routing protocol bgp peer", panos_block(130000));
    assert!(bgp_neighbor_findings(&pre, &later, &[], None).is_empty());
}
