//! Normalized added/removed lines per command, and the operational
//! category each changed command counts toward.

use std::collections::{BTreeMap, BTreeSet};

use crate::capture::Sections;
use crate::difflib::ndiff;
use crate::vpn::{VPN_FLOW_COMMANDS, VPN_GATEWAY_COMMANDS, VPN_SA_COMMANDS, VPN_SATELLITE_COMMANDS};

use super::finding::{Classification, ClassificationCounts, DiffLine};
use super::normalize::normalized_section;

/// Normalized added/removed lines for every command whose normalized
/// output differs, keyed by command (sorted).
pub fn raw_diffs(pre: &Sections, post: &Sections) -> BTreeMap<String, Vec<DiffLine>> {
    let all_commands: BTreeSet<&String> = pre.keys().chain(post.keys()).collect();
    let empty: Vec<String> = Vec::new();
    let mut diffs = BTreeMap::new();

    for command in all_commands {
        let pre_lines = normalized_section(command, pre.get(command).unwrap_or(&empty));
        let post_lines = normalized_section(command, post.get(command).unwrap_or(&empty));

        if pre_lines == post_lines {
            continue;
        }

        let mut diff_lines = Vec::new();

        // ndiff order, so the evidence reads exactly as the Python report.
        for line in ndiff(&pre_lines, &post_lines) {
            if let Some(text) = line.strip_prefix("- ") {
                diff_lines.push(DiffLine::removed(text));
            } else if let Some(text) = line.strip_prefix("+ ") {
                diff_lines.push(DiffLine::added(text));
            }
        }

        if !diff_lines.is_empty() {
            diffs.insert(command.clone(), diff_lines);
        }
    }

    diffs
}

const CONFIGURATION_COMMANDS: &[&str] = &["show running-config", "show config running"];

const PROTOCOL_COMMANDS: &[&str] = &[
    "show ip bgp summary",
    "show ip ospf neighbor",
    "show high-availability state",
    "show mlag",
    "show vpn flow",
    "show global-protect-portal satellite-cookie-expiration",
];

const ROUTING_COMMANDS: &[&str] = &[
    "show route-map",
    "show ip prefix-list",
    "show ip route",
    "show ip route ospf",
    "show ip bgp",
    "show routing route",
];

const INTERFACE_COMMANDS: &[&str] = &[
    "show interfaces status",
    "show interfaces trunk",
    "show port-channel summary",
    "show interfaces counters errors",
    "show interfaces description",
];

const LAYER2_COMMANDS: &[&str] = &["show mac address-table", "show vlan brief", "show lldp neighbors"];

const FIREWALL_COMMANDS: &[&str] = &[
    "show session info",
    "show counter global filter severity drop",
    "show jobs all",
];

const SYSTEM_COMMANDS: &[&str] = &["show system info", "show version", "show system resources"];

/// The operational category one changed command counts toward.
fn classify_command(command: &str) -> Classification {
    if CONFIGURATION_COMMANDS.contains(&command) {
        Classification::Configuration
    } else if PROTOCOL_COMMANDS.contains(&command)
        || VPN_SA_COMMANDS.contains(&command)
        || VPN_SATELLITE_COMMANDS.contains(&command)
        || VPN_FLOW_COMMANDS.contains(&command)
        || VPN_GATEWAY_COMMANDS.contains(&command)
    {
        Classification::Protocol
    } else if ROUTING_COMMANDS.contains(&command) {
        Classification::Routing
    } else if INTERFACE_COMMANDS.contains(&command) {
        Classification::Interface
    } else if LAYER2_COMMANDS.contains(&command) {
        Classification::Layer2
    } else if FIREWALL_COMMANDS.contains(&command) {
        Classification::Firewall
    } else if SYSTEM_COMMANDS.contains(&command) {
        Classification::System
    } else {
        Classification::EvidenceOnly
    }
}

/// Count changed commands by operational category.
pub fn classify_raw_diff_commands(diffs: &BTreeMap<String, Vec<DiffLine>>) -> ClassificationCounts {
    let mut categories = ClassificationCounts::default();

    for command in diffs.keys() {
        categories.add(classify_command(command), 1);
    }

    categories
}
