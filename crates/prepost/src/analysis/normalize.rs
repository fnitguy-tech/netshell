//! The HTML report's normalization: looser than the text diff's on
//! purpose, so the collapsible raw-diff evidence sections read
//! naturally. Port of `htmlreport.clean_line_for_compare` and
//! `normalized_section`.

use std::sync::LazyLock;

use regex::Regex;

use crate::vpn::{
    VPN_FLOW_COMMANDS, VPN_GATEWAY_COMMANDS, VPN_SA_COMMANDS, VPN_SATELLITE_COMMANDS, normalize_vpn_line,
};

/// Commands captured for evidence only: never diffed.
const NEVER_DIFFED: &[&str] = &[
    "show interfaces transceiver",
    "show logging last 200",
    "show log system direction equal backward",
    "show log traffic direction equal backward",
];

/// The running config is kept verbatim.
const CONFIG_COMMANDS: &[&str] = &["show running-config", "show config running"];

/// Line starts (after stripping) that are churn on every capture.
const NOISY_STARTS: &[&str] = &[
    "Generated:",
    "Uptime:",
    "Free memory:",
    "Last table change time",
    "Number of table inserts",
    "Number of table deletes",
    "time:",
    "uptime:",
    "url-filtering-version:",
    "Last update age:",
    "Update messages:",
    "Total messages:",
    "Flap counts:",
    "lifetime remain:",
];

static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+\.\d+\.\d+\.\d+$").unwrap());
static ARP_AGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+:\d+:\d+$").unwrap());
static AGO_CLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+\d+:\d+:\d+ ago$").unwrap());
static AGO_DAYS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+\d+ days?,.*ago$").unwrap());

/// Python's `str.isdigit()` for ASCII: non-empty, every character a digit.
pub(crate) fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_digit())
}

/// Strip a trailing "N:NN:NN ago" or "N days, ... ago" age column.
fn strip_age(line: &str) -> String {
    let line = AGO_CLOCK.replace(line, "");
    AGO_DAYS.replace(&line, "").into_owned()
}

/// Normalize one line for diffing, or `None` to drop it as noise.
pub fn clean_line_for_compare(command: &str, line: &str) -> Option<String> {
    let line = line.trim_end_matches('\n');

    if NEVER_DIFFED.contains(&command) {
        return None;
    }

    if CONFIG_COMMANDS.contains(&command) {
        return Some(line.to_string());
    }

    let stripped = line.trim();

    if NOISY_STARTS.iter().any(|item| stripped.starts_with(item)) {
        return None;
    }

    // IPsec/IKE/LSVPN churn (SPIs, rekey timers, login times) - one
    // rule shared with textcompare so the two reports agree.
    if VPN_SA_COMMANDS.contains(&command)
        || VPN_SATELLITE_COMMANDS.contains(&command)
        || VPN_FLOW_COMMANDS.contains(&command)
        || VPN_GATEWAY_COMMANDS.contains(&command)
    {
        return normalize_vpn_line(command, line);
    }

    if command == "show ip bgp summary" {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 10
            && let Some(peer_ip_index) = parts.iter().position(|part| IPV4.is_match(part))
            && peer_ip_index >= 1
        {
            let peer_name = parts[..peer_ip_index].join(" ");
            let peer_ip = parts[peer_ip_index];
            let peer_as = parts.get(peer_ip_index + 2).copied().unwrap_or("UNKNOWN");

            if let Some(state_index) = parts.iter().position(|part| *part == "Estab") {
                let prefixes = parts[state_index + 1..].join(" ");
                return Some(format!("{peer_name} {peer_ip} AS{peer_as} Estab {prefixes}"));
            }

            if parts.contains(&"Idle(Admin)") {
                return Some(format!("{peer_name} {peer_ip} AS{peer_as} Idle(Admin)"));
            }

            let last = parts[parts.len() - 1];
            return Some(format!("{peer_name} {peer_ip} AS{peer_as} {last}"));
        }

        return Some(line.to_string());
    }

    if command == "show ip ospf neighbor" {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 8 {
            let kept: Vec<&str> = parts[0..5].iter().chain(parts[6..].iter()).copied().collect();
            return Some(kept.join(" "));
        }
        return Some(line.to_string());
    }

    if command == "show ip arp" {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && ARP_AGE.is_match(parts[1]) {
            let kept: Vec<&str> = std::iter::once(parts[0]).chain(parts[2..].iter().copied()).collect();
            return Some(kept.join(" "));
        }
        return Some(line.to_string());
    }

    if command == "show ip route" || command == "show ip route ospf" {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 && is_digits(parts[parts.len() - 2]) {
            let kept: Vec<&str> = parts[..parts.len() - 2]
                .iter()
                .copied()
                .chain(std::iter::once(parts[parts.len() - 1]))
                .collect();
            return Some(kept.join(" "));
        }
        return Some(line.to_string());
    }

    if command == "show mac address-table" {
        return Some(strip_age(line));
    }

    Some(strip_age(line))
}

/// A section's lines, normalized and with noise dropped.
pub fn normalized_section(command: &str, lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| clean_line_for_compare(command, line))
        .collect()
}
