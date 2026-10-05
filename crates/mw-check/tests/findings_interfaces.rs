//! Newly addressed interfaces.
//!
//! An interface that gained an IP address during the window and is up
//! is the change working; one that gained an address and is still down
//! means the step configured cleanly and does not work, which deserves
//! Attention. Status only ever comes from a show table: an interface
//! the capture cannot say is up or down is never rated.

use indexmap::IndexMap;
use mw_check::analysis::interfaces::{
    InterfaceState, interface_findings, parse_config_addresses, parse_interface_all, parse_interfaces_status,
    parse_ip_interface_brief,
};
use mw_check::analysis::{Classification, Field, Impact};
use mw_check::capture::{Sections, parse_sections_str};

fn eos_brief(status: &str) -> String {
    format!(
        "                                                                              Address\n\
         Interface         IP Address           Status       Protocol           MTU    Owner\n\
         ----------------- -------------------- ------------ -------------- ---------- -------\n\
         Ethernet49/1      198.51.100.2/30      up           up                 1500\n\
         Ethernet50/1      198.51.100.10/30     {status}\n\
         Loopback0         192.0.2.1/32         up           up                65535\n\
         Vlan240           unassigned           admin down   down               1500\n"
    )
}

fn panos_all(state: &str, address: &str) -> String {
    format!(
        "total configured hardware interfaces: 3\n\
         name                    id    speed/duplex/state    mac address\n\
         --------------------------------------------------------------------------------\n\
         ethernet1/1             16    1000/full/up          00:1b:17:00:00:11\n\
         ethernet1/2             17    1000/full/down        00:1b:17:00:00:12\n\
         ethernet1/3             18    ukn/ukn/{state}       00:1b:17:00:00:13\n\
         aggregation groups: 0\n\
         total configured logical interfaces: 5\n\
         name                id    vsys zone             forwarding               tag    address\n\
         ------------------- ----- ---- ---------------- ------------------------ ------ ------------------\n\
         ethernet1/1         16    1    outside          vr:default               0      10.10.200.254/24\n\
         ethernet1/2         17    1    inside           vr:default               0      10.20.0.1/16\n\
         ethernet1/3         18    1    dmz              vr:default               0      {address}\n\
         ethernet1/3.100     260   1    dmz-100          vr:default               100    10.30.100.1/24\n\
         tunnel.1            256   1    vpn              vr:default               0      10.99.0.1/30\n"
    )
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|line| line.to_string()).collect()
}

fn split(text: &str) -> Vec<String> {
    text.lines().map(str::to_string).collect()
}

fn state(address: Option<&str>, status: Option<&str>) -> InterfaceState {
    InterfaceState::new(address, status)
}

/// A capture built from `### command ###` sections, parsed the way a
/// capture file is.
fn capture(sections: &[(&str, &str)]) -> Sections {
    let mut text = String::from("Hostname: SITE-A-SW-1\n");
    for (command, body) in sections {
        text.push_str(&format!(
            "### {command} ###\n--------------------------------------------------------------------------------\n"
        ));
        text.push_str(body);
        if !body.ends_with('\n') {
            text.push('\n');
        }
    }
    parse_sections_str(&text)
}

fn addresses(items: &[(&str, &str)]) -> IndexMap<String, String> {
    items
        .iter()
        .map(|(name, address)| (name.to_string(), address.to_string()))
        .collect()
}

#[test]
fn parse_eos_ip_interface_brief() {
    let interfaces = parse_ip_interface_brief(&split(&eos_brief("down         down               1500")));

    assert_eq!(interfaces["Ethernet49/1"], state(Some("198.51.100.2/30"), Some("up")));
    assert_eq!(
        interfaces["Ethernet50/1"],
        state(Some("198.51.100.10/30"), Some("down down"))
    );
    assert_eq!(interfaces["Vlan240"], state(None, Some("admin down down")));
    assert!(!interfaces.contains_key("Interface"));
}

#[test]
fn parse_eos_interfaces_status_expands_names() {
    let statuses = parse_interfaces_status(&strings(&[
        "Port       Name               Status       Vlan     Duplex Speed  Type         Flags Encapsulation",
        "Et50/1     ISP-B uplink       notconnect   routed   full   10G    10GBASE-LR",
        "Et49/1     ISP-A uplink       connected    routed   full   10G    10GBASE-LR",
        "Po1        to SERVER-AGG      connected    trunk    full   20G    N/A",
    ]));

    assert_eq!(
        statuses,
        addresses(&[
            ("Ethernet50/1", "notconnect"),
            ("Ethernet49/1", "up"),
            ("Port-Channel1", "up")
        ])
    );
}

#[test]
fn parse_panos_interface_all() {
    let interfaces = parse_interface_all(&split(&panos_all("down", "10.30.0.1/24")));

    assert_eq!(interfaces["ethernet1/1"], state(Some("10.10.200.254/24"), Some("up")));
    assert_eq!(interfaces["ethernet1/3"], state(Some("10.30.0.1/24"), Some("down")));
    // Sub-interface takes the parent port's link state; a tunnel has none.
    assert_eq!(
        interfaces["ethernet1/3.100"],
        state(Some("10.30.100.1/24"), Some("down"))
    );
    assert_eq!(interfaces["tunnel.1"], state(Some("10.99.0.1/30"), None));
}

#[test]
fn parse_config_addresses_eos_and_panos() {
    let eos = strings(&[
        "interface Ethernet50/1",
        "   description ISP-B uplink",
        "   ip address 198.51.100.10/30",
        "!",
        "interface Vlan240",
        "   no autostate",
        "!",
        "router bgp 64500",
        "   neighbor 10.0.0.2 remote-as 64500",
    ]);
    let panos = strings(&[
        "set network interface ethernet ethernet1/1 layer3 ip 10.10.200.254/24",
        "set network interface ethernet ethernet1/3 layer3 units ethernet1/3.100 ip 10.30.100.1/24",
        "set network interface loopback units loopback.1 ip 192.0.2.99/32",
        "set network interface ethernet ethernet1/2 layer3 mtu 1500",
    ]);

    assert_eq!(
        parse_config_addresses(&eos),
        addresses(&[("Ethernet50/1", "198.51.100.10/30")])
    );
    assert_eq!(
        parse_config_addresses(&panos),
        addresses(&[
            ("ethernet1/1", "10.10.200.254/24"),
            ("ethernet1/3.100", "10.30.100.1/24"),
            ("loopback.1", "192.0.2.99/32"),
        ])
    );
}

fn eos(brief_status: &str, with_vlan240_address: bool) -> Sections {
    let mut brief = eos_brief(brief_status);
    if with_vlan240_address {
        brief = brief.replace(
            "Vlan240           unassigned           admin down   down",
            "Vlan240           10.24.0.1/24         up           up  ",
        );
    }
    capture(&[("show ip interface brief", &brief)])
}

#[test]
fn newly_addressed_interface_that_is_down_is_attention() {
    let pre = capture(&[(
        "show ip interface brief",
        "Interface         IP Address           Status       Protocol           MTU    Owner\n\
         Ethernet49/1      198.51.100.2/30      up           up                 1500\n\
         Loopback0         192.0.2.1/32         up           up                65535\n",
    )]);
    let post = eos("down         down               1500", false);

    let findings = interface_findings(&pre, &post);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.title, "New Address, Interface Still Down");
    assert_eq!(finding.impact, Impact::Attention);
    assert_eq!(finding.classification, Classification::Interface);
    assert_eq!(finding.category, "Interface address");
    assert_eq!(finding.subject, ["Ethernet50/1", "198.51.100.10/30"]);
    assert!(
        finding
            .fields
            .contains(&Field::new("Address", "Not Present", "198.51.100.10/30"))
    );
    assert!(
        finding
            .fields
            .contains(&Field::new("Status", "Not Present", "down down"))
    );
    assert_eq!(finding.evidence, "show ip interface brief");
    assert!(finding.summary.contains("reads 'down down' in the postcheck"));
}

#[test]
fn newly_addressed_interface_that_is_up_is_stable() {
    let pre = eos("down         down               1500", false);
    let post = eos("down         down               1500", true);

    let findings = interface_findings(&pre, &post);

    let rated: Vec<(&str, Impact)> = findings.iter().map(|f| (f.title.as_str(), f.impact)).collect();
    assert_eq!(rated, [("New Address, Interface Up", Impact::Stable)]);
    assert!(
        findings[0]
            .fields
            .contains(&Field::new("Address", "unassigned", "10.24.0.1/24"))
    );
    assert!(
        findings[0]
            .fields
            .contains(&Field::new("Status", "admin down down", "up"))
    );
    assert_eq!(
        findings[0].summary,
        "Vlan240 gained 10.24.0.1/24 during the window and is up in the postcheck."
    );
}

#[test]
fn interface_that_already_had_its_address_is_not_a_finding() {
    // Ethernet50/1 was addressed but down before the window and is still
    // down: nothing gained, nothing to say here (the raw diff is empty too).
    let pre = eos("down         down               1500", false);
    let post = eos("down         down               1500", false);

    assert_eq!(interface_findings(&pre, &post), []);
}

#[test]
fn panos_newly_addressed_port_down_is_attention_and_tunnel_is_never_rated() {
    let pre = capture(&[("show interface all", &panos_all("down", "N/A"))]);
    let post = capture(&[("show interface all", &panos_all("down", "10.30.0.1/24"))]);

    let findings = interface_findings(&pre, &post);

    let subjects: Vec<&str> = findings.iter().map(|f| f.subject[0].as_str()).collect();
    assert_eq!(subjects, ["ethernet1/3"]);
    assert_eq!(findings[0].title, "New Address, Interface Still Down");
    assert_eq!(findings[0].evidence, "show interface all");

    // tunnel.1 appears with an address only in the postcheck but has no
    // link state: no status, no rating.
    let without_tunnel: String = panos_all("down", "10.30.0.1/24")
        .lines()
        .filter(|line| !line.starts_with("tunnel.1"))
        .collect::<Vec<_>>()
        .join("\n");
    let pre_without_tunnel = capture(&[("show interface all", &without_tunnel)]);
    assert_eq!(interface_findings(&pre_without_tunnel, &post), []);
}

#[test]
fn config_address_with_interfaces_status_fallback() {
    // Inventory without "show ip interface brief": the address comes from
    // the config and the link state from "show interfaces status".
    let status = |state: &str| {
        format!(
            "Port       Name               Status       Vlan     Duplex Speed  Type         Flags Encapsulation\n\
             Et50/1     ISP-B uplink       {state}   routed   full   10G    10GBASE-LR\n"
        )
    };
    let pre_config = "interface Ethernet50/1\n   description ISP-B uplink\n!\n";
    let post_config = "interface Ethernet50/1\n   ip address 198.51.100.10/30\n!\n";
    let pre = capture(&[
        ("show running-config", pre_config),
        ("show interfaces status", &status("notconnect")),
    ]);
    let post = capture(&[
        ("show running-config", post_config),
        ("show interfaces status", &status("notconnect")),
    ]);

    let findings = interface_findings(&pre, &post);

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(titles, ["New Address, Interface Still Down"]);
    assert_eq!(findings[0].evidence, "running config + show interfaces status");
    assert!(
        findings[0]
            .fields
            .contains(&Field::new("Address", "Not Present", "198.51.100.10/30"))
    );
    assert!(
        findings[0]
            .fields
            .contains(&Field::new("Status", "Not Present", "notconnect"))
    );

    // Same config change, nothing that reports link state: never rated.
    let pre = capture(&[("show running-config", pre_config)]);
    let post = capture(&[("show running-config", post_config)]);
    assert_eq!(interface_findings(&pre, &post), []);
}

#[test]
fn down_interface_in_a_full_capture_is_the_attention_finding() {
    let pre = parse_sections_str(
        "Hostname: SITE-A-SW-1\n### show ip interface brief ###\n--------------------------------------------------------------------------------\n\
         Loopback0         192.0.2.1/32         up           up                65535\n",
    );
    let post = parse_sections_str(
        "Hostname: SITE-A-SW-1\n### show ip interface brief ###\n--------------------------------------------------------------------------------\n\
         Ethernet50/1      198.51.100.10/30     down         down               1500\n\
         Loopback0         192.0.2.1/32         up           up                65535\n",
    );

    let findings = interface_findings(&pre, &post);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "New Address, Interface Still Down");
    assert_eq!(findings[0].impact, Impact::Attention);
    assert_eq!(findings[0].subject, ["Ethernet50/1", "198.51.100.10/30"]);
    assert!(findings[0].summary.contains("198.51.100.10/30"));
}
