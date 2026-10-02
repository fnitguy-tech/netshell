//! Interfaces that gained an address during the window but are still
//! down: the step configured cleanly and still does not work.
//!
//! An interface that gained an IP address during the window and is up
//! in the postcheck is the change working; one that gained an address
//! and is still down means the step configured cleanly and does not
//! work.

use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::capture::Sections;

use super::finding::{Classification, Field, Finding, Impact};

/// The category every interface finding carries.
pub const CATEGORY: &str = "Interface address";

static IPV4_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+\.\d+\.\d+\.\d+/\d+$").unwrap());

/// EOS abbreviates names in "show interfaces status" (Et50/1) but
/// spells them out in "show ip interface brief" and the config
/// (Ethernet50/1).
pub const EOS_SHORT_NAMES: [(&str, &str); 5] = [
    ("Et", "Ethernet"),
    ("Po", "Port-Channel"),
    ("Ma", "Management"),
    ("Vl", "Vlan"),
    ("Lo", "Loopback"),
];

static EOS_CONFIG_INTERFACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^interface\s+(\S+)\s*$").unwrap());
static EOS_CONFIG_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s+ip address\s+(\d+\.\d+\.\d+\.\d+/\d+)").unwrap());
/// "set network interface ethernet ethernet1/1 layer3 ip A/B" names
/// the port directly; sub-interfaces, loopbacks, tunnels and VLAN
/// interfaces are "... units <name> ip A/B".
static PANOS_CONFIG_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^set network interface (\S+) (.+?)\s+ip\s+(\d+\.\d+\.\d+\.\d+/\d+)\s*$").unwrap()
});

/// What is known about one interface after merging every source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceState {
    pub address: Option<String>,
    /// "up", "down", or `None` when no source reported a status.
    pub status: Option<String>,
}

impl InterfaceState {
    pub fn new(address: Option<&str>, status: Option<&str>) -> InterfaceState {
        InterfaceState {
            address: address.map(str::to_string),
            status: status.map(str::to_string),
        }
    }
}

/// Python's `str.isdigit()`: non-empty and every character a digit.
fn is_digits(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| c.is_ascii_digit())
}

fn is_ipv4_prefix(token: &str) -> bool {
    IPV4_PREFIX.is_match(token)
}

/// `Et1` -> `Ethernet1` and friends.
pub fn expand_eos_name(name: &str) -> String {
    for (short, full) in EOS_SHORT_NAMES {
        if let Some(rest) = name.strip_prefix(short)
            && rest.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return format!("{full}{rest}");
        }
    }
    name.to_string()
}

/// EOS 'show ip interface brief' -> `{name: InterfaceState}`.
///
/// Status is "up" only when both the Status and Protocol columns say
/// so; otherwise the columns are kept verbatim ("down down", "admin
/// down down") so the finding can show them.
pub fn parse_ip_interface_brief(lines: &[String]) -> IndexMap<String, InterfaceState> {
    let mut interfaces = IndexMap::new();

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 4
            || matches!(parts[0].to_lowercase().as_str(), "interface" | "address")
            || parts[0].starts_with('-')
        {
            continue;
        }

        let address = is_ipv4_prefix(parts[1]).then_some(parts[1]);

        if address.is_none() && parts[1].to_lowercase() != "unassigned" {
            continue;
        }

        let status_tokens: Vec<String> = parts[2..]
            .iter()
            .take_while(|token| !is_digits(token))
            .map(|token| token.to_lowercase())
            .collect();

        if status_tokens.is_empty() {
            continue;
        }

        let status = if status_tokens == ["up", "up"] {
            "up".to_string()
        } else {
            status_tokens.join(" ")
        };
        interfaces.insert(parts[0].to_string(), InterfaceState::new(address, Some(&status)));
    }

    interfaces
}

/// EOS 'show interfaces status' -> `{full name: "up" | "<status>"}`.
pub fn parse_interfaces_status(lines: &[String]) -> IndexMap<String, String> {
    let mut statuses = IndexMap::new();

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3
            || parts[0].to_lowercase() == "port"
            || !parts[0].chars().next().is_some_and(char::is_alphabetic)
        {
            continue;
        }

        for token in &parts[1..] {
            let token = token.to_lowercase();
            if matches!(
                token.as_str(),
                "connected" | "notconnect" | "disabled" | "errdisabled" | "inactive"
            ) {
                let status = if token == "connected" { "up".to_string() } else { token };
                statuses.insert(expand_eos_name(parts[0]), status);
                break;
            }
        }
    }

    statuses
}

/// PAN-OS 'show interface all' -> `{name: InterfaceState}`.
///
/// The hardware table ("name id speed/duplex/state mac") gives link
/// state per physical port; the logical table ("name id vsys zone
/// forwarding tag address") gives addresses. A sub-interface takes its
/// parent's link state; tunnel and loopback interfaces have none, so
/// their status stays `None` and is never rated.
pub fn parse_interface_all(lines: &[String]) -> IndexMap<String, InterfaceState> {
    let mut hardware: IndexMap<String, String> = IndexMap::new();
    let mut logical: IndexMap<String, Option<String>> = IndexMap::new();

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 || !is_digits(parts[1]) {
            continue;
        }

        let speed_duplex_state: Vec<&str> = parts[2].split('/').collect();

        if speed_duplex_state.len() == 3 && !is_ipv4_prefix(parts[2]) {
            hardware.insert(parts[0].to_string(), speed_duplex_state[2].to_lowercase());
        } else {
            let last = parts[parts.len() - 1];
            logical.insert(parts[0].to_string(), is_ipv4_prefix(last).then(|| last.to_string()));
        }
    }

    let mut interfaces = IndexMap::new();

    for (name, address) in &logical {
        let parent = name.split('.').next().unwrap_or(name);
        let state = hardware.get(name).or_else(|| hardware.get(parent));
        interfaces.insert(
            name.clone(),
            InterfaceState::new(address.as_deref(), state.map(String::as_str)),
        );
    }

    for (name, state) in &hardware {
        interfaces
            .entry(name.clone())
            .or_insert_with(|| InterfaceState::new(None, Some(state)));
    }

    interfaces
}

/// Interface addresses from an EOS or PAN-OS (set format) config.
pub fn parse_config_addresses(lines: &[String]) -> IndexMap<String, String> {
    let mut addresses = IndexMap::new();
    let mut current: Option<String> = None;

    for line in lines {
        if let Some(panos) = PANOS_CONFIG_ADDRESS.captures(line) {
            let tokens: Vec<&str> = panos[2].split_whitespace().collect();
            let Some(first) = tokens.first() else {
                continue;
            };
            let units = tokens[..tokens.len() - 1].iter().position(|token| *token == "units");
            let name = units.map_or(*first, |index| tokens[index + 1]);
            addresses.insert(name.to_string(), panos[3].to_string());
            continue;
        }

        if let Some(header) = EOS_CONFIG_INTERFACE.captures(line) {
            current = Some(header[1].to_string());
            continue;
        }

        let Some(name) = current.as_deref() else {
            continue;
        };

        if !line.chars().next().is_some_and(char::is_whitespace) {
            current = None;
            continue;
        }

        if let Some(address) = EOS_CONFIG_ADDRESS.captures(line) {
            addresses.insert(name.to_string(), address[1].to_string());
        }
    }

    addresses
}

/// Address + link status per interface from whatever one capture has,
/// plus the sources that contributed ("show ip interface brief",
/// "show interface all", "running config", "show interfaces status").
///
/// Addresses come from the show tables first and the config second;
/// status only ever comes from a show table, so an interface the
/// capture cannot say is up or down gets `None` and no finding.
pub fn parse_interfaces_with_sources(sections: &Sections) -> (IndexMap<String, InterfaceState>, Vec<&'static str>) {
    let mut interfaces: IndexMap<String, InterfaceState> = IndexMap::new();
    let mut sources: Vec<&'static str> = Vec::new();

    if let Some(lines) = sections.get("show ip interface brief") {
        interfaces.extend(parse_ip_interface_brief(lines));
        sources.push("show ip interface brief");
    }

    if let Some(lines) = sections.get("show interface all") {
        interfaces.extend(parse_interface_all(lines));
        sources.push("show interface all");
    }

    let config_lines: Vec<String> = ["show running-config", "show config running"]
        .iter()
        .filter_map(|command| sections.get(*command))
        .flatten()
        .cloned()
        .collect();

    for (name, address) in parse_config_addresses(&config_lines) {
        let entry = interfaces.entry(name).or_default();

        if entry.address.is_none() {
            entry.address = Some(address);
            if !sources.contains(&"running config") {
                sources.push("running config");
            }
        }
    }

    if let Some(lines) = sections.get("show interfaces status") {
        let statuses = parse_interfaces_status(lines);

        for (name, entry) in interfaces.iter_mut() {
            if entry.status.is_none()
                && let Some(status) = statuses.get(name)
            {
                entry.status = Some(status.clone());
                if !sources.contains(&"show interfaces status") {
                    sources.push("show interfaces status");
                }
            }
        }
    }

    (interfaces, sources)
}

/// Merge `show ip interface brief`, `show interface all`, `show
/// interfaces status` and config addresses into one map.
pub fn parse_interfaces(sections: &Sections) -> IndexMap<String, InterfaceState> {
    parse_interfaces_with_sources(sections).0
}

/// Gained address + down -> Attention; gained + up -> Stable; status
/// unknown -> no finding.
///
/// Interfaces that gained an address during the window, rated by
/// whether they are up in the postcheck. Never rated when the
/// postcheck cannot say (no status column for that interface).
pub fn interface_findings(pre: &Sections, post: &Sections) -> Vec<Finding> {
    let (pre, _pre_sources) = parse_interfaces_with_sources(pre);
    let (post, sources) = parse_interfaces_with_sources(post);
    let mut findings = Vec::new();

    let mut names: Vec<&String> = post.keys().collect();
    names.sort();

    for name in names {
        let after = &post[name];
        let before = pre.get(name);

        let (Some(address), Some(status)) = (after.address.as_deref(), after.status.as_deref()) else {
            continue;
        };

        if before.is_some_and(|before| before.address.is_some()) {
            continue;
        }

        let status_before = match before.and_then(|before| before.status.as_deref()) {
            Some(status) if !status.is_empty() => status,
            _ => "Not Present",
        };
        let fields = vec![
            Field::new(
                "Address",
                if before.is_none() { "Not Present" } else { "unassigned" },
                address,
            ),
            Field::new("Status", status_before, status),
        ];
        let evidence = sources.join(" + ");

        let (impact, title, summary) = if status == "up" {
            (
                Impact::Stable,
                "New Address, Interface Up",
                format!("{name} gained {address} during the window and is up in the postcheck."),
            )
        } else {
            (
                Impact::Attention,
                "New Address, Interface Still Down",
                format!(
                    "The config is fine and the link isn't. {name} gained {address} during the window but reads \
                     '{status}' in the postcheck. Check the admin state, the cable, or the far end before you \
                     close the window."
                ),
            )
        };

        let mut finding = Finding::new(Classification::Interface, CATEGORY, impact, title);
        finding.subject = vec![name.clone(), address.to_string()];
        finding.fields = fields;
        finding.summary = summary;
        finding.evidence = evidence;
        findings.push(finding);
    }

    findings
}
