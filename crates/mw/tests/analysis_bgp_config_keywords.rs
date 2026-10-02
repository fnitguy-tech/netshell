//! BGP-relevant config lines. Port of the Python
//! `tests/test_bgp_config_keywords.py`.
//!
//! `bgp_config_changes()` decides which changed running-config lines
//! are shown next to the BGP findings. It used to match only the
//! "router bgp" block itself (neighbor, route-map, community,
//! shutdown), so a prefix-list, peer-group, redistribution or PAN-OS
//! valid-networks edit - the things that actually change what a peer is
//! sent - never reached that context.

use mw::analysis::bgp::bgp_neighbor_findings;
use mw::analysis::config::{bgp_config_changes, count_config_changes};
use mw::analysis::{DiffKind, DiffLine};
use mw::capture::Sections;

const EOS_PRE: &[&str] = &[
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24",
    "   seq 40 permit 198.51.100.243/32",
    "!",
    "router bgp 64500",
    "   neighbor ISP peer group",
    "   neighbor ISP route-map ISP-OUT out",
    "   neighbor 198.51.100.1 peer group ISP",
    "   redistribute connected route-map CONN",
    "   bfd interval 300 min-rx 300 multiplier 3",
    "   link-state bandwidth 10g",
];

const PANOS_PRE: &[&str] = &[
    "set network virtual-router default protocol bgp peer-group EACN peer EACN-1 peer-address ip 10.40.0.1",
    "set network virtual-router default protocol bgp policy export rules EACN-OUT used-by EACN",
    "set network virtual-router default protocol bgp policy export rules EACN-OUT match address-prefix 10.20.0.0/16 exact yes",
    "set network virtual-router default protocol bgp redist-rules 10.20.0.0/16 enable yes",
    "set network virtual-router default protocol bgp auth-profile EACN-AUTH secret <REDACTED>",
    "set network virtual-router default protocol bgp valid-networks 10.20.0.0/16",
];

fn sections(command: &str, lines: &[String]) -> Sections {
    let mut sections = Sections::new();
    sections.insert(command.to_string(), lines.to_vec());
    sections
}

fn strings(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| line.to_string()).collect()
}

fn changes_for(pre: &[String], post: &[String], command: &str) -> Vec<DiffLine> {
    bgp_config_changes(&sections(command, pre), &sections(command, post))
}

fn ndiff(changes: &[DiffLine]) -> Vec<String> {
    changes.iter().map(DiffLine::ndiff).collect()
}

#[test]
fn prefix_list_edit_reaches_bgp_context() {
    let pre = strings(EOS_PRE);
    let post: Vec<String> = pre.iter().filter(|line| !line.contains("seq 40")).cloned().collect();

    let changes = changes_for(&pre, &post, "show running-config");

    assert_eq!(
        ndiff(&changes),
        ["  ip prefix-list ISP-OUT", "-    seq 40 permit 198.51.100.243/32"]
    );
    assert_eq!(changes[0].kind, DiffKind::Context);
    assert_eq!(changes[1].kind, DiffKind::Removed);
    assert_eq!(count_config_changes(&changes), 1);
}

#[test]
fn eos_policy_keywords_are_bgp_relevant() {
    let pre = strings(EOS_PRE);
    let mut post: Vec<String> = pre
        .iter()
        .filter(|line| {
            !line.contains("peer group ISP")
                && !line.contains("redistribute")
                && !line.contains("bfd")
                && !line.contains("link-state")
        })
        .cloned()
        .collect();
    post.push("ip access-list BGP-PEERS".to_string());
    post.push("   10 permit ip 198.51.100.0/24 any".to_string());
    post.push("   ip access-group BGP-PEERS in".to_string());

    let changes = changes_for(&pre, &post, "show running-config");
    let rendered = ndiff(&changes);
    let mut removed_or_added: Vec<String> = changes
        .iter()
        .filter(|line| line.kind != DiffKind::Context)
        .map(|line| line.text.trim().to_string())
        .collect();
    removed_or_added.sort();

    assert!(rendered.contains(&"  router bgp 64500".to_string()));

    for expected in [
        "neighbor 198.51.100.1 peer group ISP",
        "redistribute connected route-map CONN",
        "bfd interval 300 min-rx 300 multiplier 3",
        "link-state bandwidth 10g",
        "ip access-list BGP-PEERS",
        "ip access-group BGP-PEERS in",
    ] {
        assert!(removed_or_added.contains(&expected.to_string()), "{expected} missing");
    }
}

#[test]
fn panos_valid_networks_and_used_by_register() {
    let pre = strings(PANOS_PRE);
    let post: Vec<String> = pre
        .iter()
        .filter(|line| !line.contains("used-by"))
        .map(|line| {
            if line.contains("valid-networks") {
                line.replace("valid-networks 10.20.0.0/16", "valid-networks 10.20.0.0/17")
            } else {
                line.clone()
            }
        })
        .collect();

    let changes = changes_for(&pre, &post, "show config running");
    let text = ndiff(&changes).join("\n");

    assert!(text.contains("used-by EACN"));
    assert!(text.contains("valid-networks 10.20.0.0/16"));
    assert!(text.contains("valid-networks 10.20.0.0/17"));

    // Everything PAN-OS says under "protocol bgp" is BGP context, even
    // lines with none of the EOS keywords.
    let without_auth: Vec<String> = pre
        .iter()
        .filter(|line| !line.contains("auth-profile"))
        .cloned()
        .collect();
    let auth_only = changes_for(&pre, &without_auth, "show config running");
    assert_eq!(auth_only.len(), 1);
    assert!(auth_only[0].text.contains("auth-profile"));
    assert_eq!(auth_only[0].kind, DiffKind::Removed);
}

#[test]
fn unrelated_config_lines_stay_out() {
    let pre = strings(&[
        "interface Ethernet1",
        "   description users",
        "vlan 240",
        "   name ISP-B-TRANSIT",
    ]);
    let mut post = pre.clone();
    post.extend(strings(&["interface Vlan240", "   ip address 10.24.0.1/24"]));

    assert!(changes_for(&pre, &post, "show running-config").is_empty());
}

#[test]
fn both_config_commands_are_read_and_header_context_follows_each_side() {
    let pre = strings(&["router bgp 64500", "   neighbor 10.0.0.1 remote-as 64501"]);
    let post = strings(&[
        "router bgp 64500",
        "   neighbor 10.0.0.1 remote-as 64501",
        "   neighbor 10.0.0.1 shutdown",
    ]);

    let changes = bgp_config_changes(
        &sections("show config running", &pre),
        &sections("show config running", &post),
    );
    assert_eq!(
        ndiff(&changes),
        ["  router bgp 64500", "+    neighbor 10.0.0.1 shutdown"]
    );

    // A changed header is its own context: no extra context line.
    let renamed = strings(&["router bgp 64501", "   neighbor 10.0.0.1 remote-as 64501"]);
    let changes = changes_for(&pre, &renamed, "show running-config");
    assert_eq!(ndiff(&changes), ["- router bgp 64500", "+ router bgp 64501"]);
}

#[test]
fn prefix_list_change_is_cited_as_evidence_for_a_prefix_delta() {
    let row = |count: u32| format!("  ISP-B  198.51.100.9  4 64497  213  201  0  0  5d02h  Estab  {count}  {count}");
    let mut pre = sections("show ip bgp summary", &[row(815)]);
    pre.insert("show running-config".to_string(), strings(EOS_PRE));
    let mut post = sections("show ip bgp summary", &[row(814)]);
    post.insert(
        "show running-config".to_string(),
        strings(EOS_PRE)
            .into_iter()
            .filter(|line| !line.contains("seq 40"))
            .collect(),
    );

    let findings = bgp_neighbor_findings(&pre, &post, &bgp_config_changes(&pre, &post), None);

    assert_eq!(
        findings.iter().map(|f| f.title.as_str()).collect::<Vec<_>>(),
        ["BGP Prefix Count Changed"]
    );
    assert_eq!(
        findings[0].evidence,
        "show ip bgp summary + BGP prefix-list/valid-networks config"
    );
}

#[test]
fn shutdown_and_route_map_evidence() {
    let row = |state: &str| format!("  ISP-B  198.51.100.9  4 64497  213  201  0  0  5d02h  {state}");
    let mut pre = sections("show ip bgp summary", &[row("Estab  815  815")]);
    pre.insert(
        "show running-config".to_string(),
        strings(&["router bgp 64500", "   neighbor 198.51.100.9 remote-as 64497"]),
    );
    let mut post = sections("show ip bgp summary", &[row("Idle(Admin)")]);
    post.insert(
        "show running-config".to_string(),
        strings(&[
            "router bgp 64500",
            "   neighbor 198.51.100.9 remote-as 64497",
            "   neighbor 198.51.100.9 shutdown",
        ]),
    );

    let findings = bgp_neighbor_findings(&pre, &post, &bgp_config_changes(&pre, &post), None);
    assert_eq!(findings[0].title, "BGP Peer Administratively Disabled");
    assert_eq!(
        findings[0].evidence,
        "show ip bgp summary + related BGP shutdown/no shutdown config"
    );

    let mut post = sections("show ip bgp summary", &[row("Estab  812  812")]);
    post.insert(
        "show running-config".to_string(),
        strings(&[
            "router bgp 64500",
            "   neighbor 198.51.100.9 remote-as 64497",
            "   neighbor 198.51.100.9 route-map ISP-IN in",
        ]),
    );
    let findings = bgp_neighbor_findings(&pre, &post, &bgp_config_changes(&pre, &post), None);
    assert_eq!(findings[0].title, "BGP Prefix Count Changed");
    assert_eq!(
        findings[0].evidence,
        "show ip bgp summary + BGP route-map/community config"
    );
}
