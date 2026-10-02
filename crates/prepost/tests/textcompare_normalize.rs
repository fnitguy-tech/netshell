//! The normalization rules, ported from the Python tool's
//! `tests/test_textcompare.py` and `tests/test_lsvpn_normalization.py`.
//!
//! A maintenance on an LSVPN hub changes what is built: gateways,
//! tunnels, pools, certificates, the portal cookie lifetime, and the
//! route-maps or prefix-lists that decide what a peer is sent.
//! Everything else in those outputs moves on its own - traffic counters
//! climb, satellites connect and disconnect, hit counters tick - and
//! would bury the real finding. These tests pin that split: the
//! identity of a thing survives, the numbers that move without anyone
//! touching the device do not.

use prepost::textcompare::{NOISY_STARTS, SKIP_COMPARE_COMMANDS, normalize_line};

const FLOW: &str = "show global-protect-gateway flow-site-to-site";
const GATEWAY: &str = "show global-protect-gateway gateway";
const SATELLITE: &str = "show global-protect-gateway current-satellite";
const COOKIE: &str = "show global-protect-portal satellite-cookie-expiration";

fn same(line: &str) -> Option<String> {
    Some(line.to_string())
}

#[test]
fn noisy_lines_dropped() {
    assert_eq!(normalize_line("show version", "Uptime: 5 days"), None);
    assert_eq!(normalize_line("HEADER", "Generated: 2026-01-01 00:00:00"), None);
    assert_eq!(normalize_line("show interfaces transceiver", "anything at all"), None);
}

#[test]
fn every_noisy_start_is_dropped_wherever_it_sits() {
    for item in NOISY_STARTS {
        let line = format!("   {item} 42");
        assert_eq!(normalize_line("show anything", &line), None, "{item}");
    }
    for command in SKIP_COMPARE_COMMANDS {
        assert_eq!(normalize_line(command, "Et49/1  35.9  3.28"), None);
    }
}

#[test]
fn running_config_kept_verbatim() {
    // Config diffs must be exact - even lines that look "noisy"
    // elsewhere survive untouched.
    let line = "   uptime: banner text";
    assert_eq!(normalize_line("show running-config", line), same(line));
    assert_eq!(normalize_line("show config running", line), same(line));

    // Only the line terminator goes, never other trailing whitespace.
    assert_eq!(
        normalize_line("show running-config", "hostname sw \n"),
        same("hostname sw ")
    );
}

#[test]
fn bgp_summary_drops_timers_keeps_state() {
    let line = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Estab 100 98";
    assert_eq!(
        normalize_line("show ip bgp summary", line),
        same("SPINE1 203.0.113.1 4 Estab 100 98")
    );

    let line = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Idle(Admin)";
    assert_eq!(
        normalize_line("show ip bgp summary", line),
        same("SPINE1 203.0.113.1 4 Idle(Admin)")
    );

    // Anything else in that output (headers, Active/Connect peers) is
    // kept as it is.
    let line = "  Description       Neighbor         V AS           MsgRcvd   MsgSent";
    assert_eq!(normalize_line("show ip bgp summary", line), same(line));
}

#[test]
fn ospf_neighbor_drops_dead_timer() {
    // Column 6 (index 5) is the dead-timer countdown; everything else
    // must survive so real neighbor changes still show up.
    let line = "203.0.113.2 default 1 FULL 198.51.100.2 00:00:31 Ethernet49/1 0";
    let result = normalize_line("show ip ospf neighbor", line);
    assert_eq!(result, same("203.0.113.2 default 1 FULL 198.51.100.2 Ethernet49/1 0"));

    // Too few columns to be a neighbor row: left alone.
    let header = "Neighbor ID     Instance VRF      Pri State";
    assert_eq!(normalize_line("show ip ospf neighbor", header), same(header));
}

#[test]
fn arp_and_mac_ages_dropped() {
    let pre = "10.0.0.2 0:00:12 001c.7300.0002 Vlan4000, Ethernet47/1";
    let post = "10.0.0.2 1:17:45 001c.7300.0002 Vlan4000, Ethernet47/1";
    assert_eq!(normalize_line("show ip arp", pre), normalize_line("show ip arp", post));
    assert_eq!(
        normalize_line("show ip arp", pre),
        same("10.0.0.2 001c.7300.0002 Vlan4000, Ethernet47/1")
    );

    let pre = " 200  001c.7300.0002  DYNAMIC  Et1  1  0:00:12 ago";
    let post = " 200  001c.7300.0002  DYNAMIC  Et1  1  3 days, 2 hours ago";
    assert_eq!(
        normalize_line("show mac address-table", pre),
        normalize_line("show mac address-table", post)
    );
    assert_eq!(
        normalize_line("show mac address-table", pre),
        same(" 200  001c.7300.0002  DYNAMIC  Et1  1")
    );
}

#[test]
fn panos_route_age_dropped() {
    let pre = "198.51.100.0/24 198.51.100.9 10 3600 A B ethernet1/1";
    let post = "198.51.100.0/24 198.51.100.9 10 7200 A B ethernet1/1";
    assert_eq!(
        normalize_line("show routing route", pre),
        normalize_line("show routing route", post)
    );
    assert_eq!(
        normalize_line("show routing route", pre),
        same("198.51.100.0/24 198.51.100.9 A B ethernet1/1")
    );
}

#[test]
fn panos_peer_status_keeps_state_only() {
    let line = "  Peer status: Established, for 123456 secs";
    assert_eq!(
        normalize_line("show routing protocol bgp peer", line),
        same("Peer status: Established")
    );
    assert_eq!(
        normalize_line("show routing protocol bgp peer", "  Flap counts: 3"),
        None
    );
    assert_eq!(
        normalize_line("show routing protocol bgp peer", "  Peer status: Idle"),
        same("Peer status: Idle")
    );
    assert_eq!(
        normalize_line("show routing protocol bgp peer", "  Peer AS: 64496"),
        same("  Peer AS: 64496")
    );
}

#[test]
fn panos_system_info_versions_dropped() {
    assert_eq!(normalize_line("show system info", "app-version: 8900-9000"), None);
    assert_eq!(normalize_line("show system info", "  threat-version: 8900-9000"), None);
    assert_eq!(
        normalize_line("show system info", "sw-version: 11.1.4"),
        same("sw-version: 11.1.4")
    );
    assert_eq!(
        normalize_line("show routing protocol ospf neighbor", "  lifetime remain: 31"),
        None
    );
}

#[test]
fn vpn_ike_sa_drops_rekey_churn_keeps_identity() {
    // IKEv2 SA row: gateway ID, peer, name, role and algorithm survive;
    // the established/expiration timestamps and child count do not.
    let pre = "1  198.51.100.7  gw-siteA  Init  PSK/ DH14/A256/SHA256  Aug.31 10:11:12  Sep.01 10:11:12  1";
    let post = "1  198.51.100.7  gw-siteA  Init  PSK/ DH14/A256/SHA256  Sep.01 10:11:12  Sep.02 10:11:12  2";
    assert_eq!(
        normalize_line("show vpn ike-sa", pre),
        normalize_line("show vpn ike-sa", post)
    );
    assert_eq!(
        normalize_line("show vpn ike-sa", pre),
        same("1 198.51.100.7 gw-siteA Init PSK/ DH14/A256/SHA256")
    );

    // Child SA row: SPIs (with and without 0x) and the message ID churn.
    let pre = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x1a2b3c4d  CAFEF00D  1234";
    let post = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x9f8e7d6c  DEADBEEF  1301";
    assert_eq!(
        normalize_line("show vpn ike-sa", pre),
        normalize_line("show vpn ike-sa", post)
    );
    assert_eq!(
        normalize_line("show vpn ike-sa", pre),
        same("gw-siteA tunnel-siteA ESP/A256/SHA256")
    );
}

#[test]
fn vpn_ike_sa_count_line_kept() {
    let line = "Show IKEv2 IKE SA: Total 1 gateways found. 1 ike sa found.";
    assert_eq!(normalize_line("show vpn ike-sa", line), same(line));
}

#[test]
fn vpn_ipsec_sa_state_change_survives() {
    let pre = "1  1  198.51.100.7  tunnel-siteA(gw-siteA)  ethernet1/1  Active  4  3450/28800  1.2GB";
    let post = "1  1  198.51.100.7  tunnel-siteA(gw-siteA)  ethernet1/1  Init  0  0/28800  0KB";
    assert_eq!(
        normalize_line("show vpn ipsec-sa", pre),
        same("1 198.51.100.7 tunnel-siteA(gw-siteA) ethernet1/1 Active")
    );
    assert_ne!(
        normalize_line("show vpn ipsec-sa", pre),
        normalize_line("show vpn ipsec-sa", post)
    );
}

#[test]
fn vpn_flow_kept_verbatim() {
    let line = "1  tunnel-siteA  active  off  203.0.113.1  198.51.100.7  tunnel.1";
    assert_eq!(normalize_line("show vpn flow", line), same(line));
}

#[test]
fn lsvpn_satellite_login_time_dropped() {
    let cmd = "show global-protect-gateway current-satellite";
    assert_eq!(normalize_line(cmd, "        Login Time    : Aug.31 10:11:12"), None);
    assert_eq!(
        normalize_line(cmd, "    Satellite         : sat-siteA"),
        same("    Satellite         : sat-siteA")
    );

    let cmd = "show global-protect-satellite current-gateway";
    assert_eq!(normalize_line(cmd, "  Status : Active"), same("  Status : Active"));
}

#[test]
fn flow_counters_drop_but_tunnel_survives() {
    let before = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 148293 20481").unwrap();
    let after = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 992104 88123").unwrap();

    assert_eq!(before, after);
    assert!(before.contains("SIL-HCX-FW1"));
    assert!(before.contains("tunnel.511"));
}

#[test]
fn flow_state_change_is_visible() {
    let up = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 148293 20481");
    let down = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 init 10.2.0.9 148293 20481");

    assert_ne!(up, down);
}

#[test]
fn gateway_satellite_count_is_not_a_change() {
    assert_eq!(normalize_line(GATEWAY, "  Number of satellites connected: 4"), None);
    assert_eq!(normalize_line(GATEWAY, "  Current satellites : 2"), None);
}

#[test]
fn gateway_build_survives() {
    let line = "  Tunnel Interface: tunnel.511";

    assert_eq!(normalize_line(GATEWAY, line), same(line));
}

#[test]
fn satellite_login_time_is_not_a_change() {
    assert_eq!(normalize_line(SATELLITE, "Login time: Sep.28 04:15:11"), None);
}

#[test]
fn cookie_lifetime_is_compared_verbatim() {
    let line = "Satellite cookie expiration: 5";

    assert_eq!(normalize_line(COOKIE, line), same(line));
}

#[test]
fn route_map_hit_counters_drop() {
    assert_eq!(normalize_line("show route-map", "  Match clauses hit: 4211"), None);
    assert_eq!(normalize_line("show route-map", "  Set clauses hit: 12"), None);
    assert_eq!(normalize_line("show route-map", "  Clauses hit: 12"), None);
    assert_eq!(
        normalize_line("show route-map", "route-map VIASAT-OUT-P0 permit 10 ( 812 matches )"),
        same("route-map VIASAT-OUT-P0 permit 10")
    );
    assert_eq!(
        normalize_line("show ip prefix-list", "   seq 10 permit 10.0.0.0/8 (3 hits)"),
        same("   seq 10 permit 10.0.0.0/8")
    );
}

#[test]
fn prefix_list_entry_survives() {
    let line = "   seq 40 permit 198.51.100.243/32";

    assert_eq!(normalize_line("show ip prefix-list", line), same(line));
}

#[test]
fn age_columns_are_stripped_for_every_command() {
    assert_eq!(
        normalize_line("show something", "entry one 0:12:33 ago"),
        same("entry one")
    );
    assert_eq!(
        normalize_line("show something", "entry one 2 days, 1 hour ago"),
        same("entry one")
    );
    assert_eq!(
        normalize_line("show something", "entry one 1 day, 23 hours ago"),
        same("entry one")
    );
    // The clock rule runs first, so a days column followed by a clock
    // keeps its "N days," stub: the same on both captures, so harmless.
    assert_eq!(
        normalize_line("show something", "entry one 2 days, 1:00:00 ago"),
        same("entry one 2 days,")
    );
}
