//! BGP: summary-table and PAN-OS peer-block parsing, uptime parsing,
//! session-reset detection and the per-peer findings.

use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::capture::Sections;
use crate::expectations::{self, Expectation, Expected};

use super::finding::{BgpContext, BgpPeer, Classification, DiffLine, Field, Finding, Impact};
use super::normalize::is_digits;
use super::{TITLE_AS_PLANNED, TITLE_DIFFERS, TITLE_NOT_MET, TITLE_UNEXPLAINED};

/// The generic caveat a prefix delta carries when nobody wrote down
/// what the change was meant to do.
pub const PREFIX_DELTA_HEDGE: &str = "That's normal if this window touched routing policy, communities, \
                                      failover, or advertised routes. Write the expected count into the \
                                      expectations file and the next run will rate it for you.";

// EOS "Up/Down" column formats. The timer rolls over to a coarser unit
// as the session ages: 00:52:40 under a day, 1d02h under a week, 2w3d
// after that (and 1y2w eventually). "never" means the session has never
// come up.
static UPTIME_CLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+):(\d{2}):(\d{2})$").unwrap());
static UPTIME_UNITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:\d+[ywdhms])+$").unwrap());
static UPTIME_UNIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)([ywdhms])").unwrap());
static UPTIME_SECS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+)\s*secs?$").unwrap());

fn unit_seconds(unit: &str) -> u64 {
    match unit {
        "y" => 365 * 86400,
        "w" => 7 * 86400,
        "d" => 86400,
        "h" => 3600,
        "m" => 60,
        _ => 1,
    }
}

/// Parse an Up/Down token into `(seconds, granularity_seconds)`.
/// Handles `HH:MM:SS`, `1d02h`, `2w3d`, `1y2w`, PAN-OS `N secs`;
/// `never` and anything unparseable are `None`.
///
/// Granularity is the smallest unit the format shows (1s for a clock,
/// 1h for "1d02h", 1d for "2w3d"): the true value lies anywhere in
/// [seconds, seconds + granularity), which the reset check honours so a
/// coarse timer is never read as having gone backwards when it has not.
/// Anything unparsable (including "never") is `None`, never a guess.
pub fn parse_uptime(token: &str) -> Option<(u64, u64)> {
    let token = token.trim();

    if let Some(clock) = UPTIME_CLOCK.captures(token) {
        let hours: u64 = clock[1].parse().ok()?;
        let minutes: u64 = clock[2].parse().ok()?;
        let seconds: u64 = clock[3].parse().ok()?;
        return Some((hours * 3600 + minutes * 60 + seconds, 1));
    }

    let lowered = token.to_lowercase();

    if UPTIME_UNITS.is_match(&lowered) {
        let mut total: u64 = 0;
        let mut granularity = 1;

        for part in UPTIME_UNIT.captures_iter(&lowered) {
            let amount: u64 = part[1].parse().ok()?;
            granularity = unit_seconds(&part[2]);
            total = total.checked_add(amount.checked_mul(granularity)?)?;
        }

        return Some((total, granularity));
    }

    // PAN-OS: "Peer status: Established, for 123456 secs".
    if let Some(secs) = UPTIME_SECS.captures(&lowered) {
        return Some((secs[1].parse().ok()?, 1));
    }

    None
}

/// True when the postcheck uptime is unambiguously smaller than the
/// precheck uptime (post + post_granularity <= pre).
///
/// The postcheck is always taken after the precheck, so a session that
/// stayed up can only show an equal (coarse format) or larger value. A
/// smaller one means the session was torn down and came back in
/// between, which the state column alone (Estab -> Estab) can never
/// show.
pub fn session_reset(before: &BgpPeer, after: &BgpPeer) -> bool {
    let pre = before.updown.as_deref().and_then(parse_uptime);
    let post = after.updown.as_deref().and_then(parse_uptime);

    match (pre, post) {
        (Some((pre_seconds, _)), Some((post_seconds, post_granularity))) => {
            post_seconds + post_granularity <= pre_seconds
        }
        _ => false,
    }
}

static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+\.\d+\.\d+\.\d+$").unwrap());

/// The key peers are merged on: `"<name> <ip>"`.
fn peer_key(peer: &BgpPeer) -> String {
    format!("{} {}", peer.name, peer.ip)
}

/// Peers keyed as the Python dicts are, so a later source for the same
/// peer replaces the earlier one in place.
type PeerMap = IndexMap<String, BgpPeer>;

fn parse_bgp_summary_map(lines: &[String]) -> PeerMap {
    let mut peers = PeerMap::new();

    for line in lines {
        let clean = line.trim();

        if clean.is_empty() {
            continue;
        }

        if ["Neighbor", "VRF", "Router", "BGP", "Pfx"]
            .iter()
            .any(|prefix| clean.starts_with(prefix))
        {
            continue;
        }

        let parts: Vec<&str> = clean.split_whitespace().collect();

        let Some(peer_ip_index) = parts.iter().position(|part| IPV4.is_match(part)) else {
            continue;
        };

        let peer_name = parts[..peer_ip_index].join(" ");
        let peer_ip = parts[peer_ip_index];
        let peer_as = parts.get(peer_ip_index + 2).copied().unwrap_or("UNKNOWN");

        let mut state = parts[parts.len() - 1];
        let mut state_index = parts.len() - 1;
        let mut prefixes_received = "0";
        let mut prefixes_accepted = "0";

        if let Some(index) = parts.iter().position(|part| *part == "Estab") {
            state = "Estab";
            state_index = index;

            if parts.len() > state_index + 2 {
                prefixes_received = parts[state_index + 1];
                prefixes_accepted = parts[state_index + 2];
            }
        } else if let Some(index) = parts.iter().position(|part| *part == "Idle(Admin)") {
            state = "Idle(Admin)";
            state_index = index;
        }

        // Up/Down sits immediately before State. Only trust it when it
        // lies after the AS column, so a short or odd row yields None.
        let updown = (state_index as i64 - 1 > peer_ip_index as i64 + 2).then(|| parts[state_index - 1].to_string());

        let peer = BgpPeer {
            name: peer_name,
            ip: peer_ip.to_string(),
            as_number: peer_as.to_string(),
            state: state.to_string(),
            prefixes_received: prefixes_received.to_string(),
            prefixes_accepted: prefixes_accepted.to_string(),
            updown,
        };

        peers.insert(peer_key(&peer), peer);
    }

    peers
}

/// Peers from an EOS/IOS `show ip bgp summary` table.
///
/// The Up/Down column is kept even though the raw-diff normalizers
/// strip it: it is churn in a diff but the highest-signal field in the
/// interpreted layer, because uptime going backwards is the only trace
/// a reset-and-recovered session leaves in this table.
pub fn parse_bgp_summary(lines: &[String]) -> Vec<BgpPeer> {
    parse_bgp_summary_map(lines).into_values().collect()
}

// PAN-OS "show routing protocol bgp peer" is one indented block per
// peer rather than a table. These are the lines that carry the same
// facts the EOS summary row does; everything else in the block is
// ignored.
static PANOS_PEER_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*Peer:\s*(\S+)").unwrap());
static PANOS_PEER_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Peer address:\s*(\d+\.\d+\.\d+\.\d+)").unwrap());
static PANOS_PEER_AS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*Remote AS:\s*(\d+)").unwrap());
static PANOS_PEER_STATUS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Peer status:\s*([A-Za-z]+)(?:,\s*for\s+(\d+)\s*secs?)?").unwrap());
static PANOS_PEER_INCOMING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Incoming total:\s*(\d+),\s*accepted:\s*(\d+)").unwrap());

fn parse_panos_bgp_peers_map(lines: &[String]) -> PeerMap {
    let mut peers = PeerMap::new();
    // The peer block being read, and its key once its address is known
    // (the Python dict is shared with the map, so later fields in the
    // block update the stored peer too).
    let mut current: Option<(BgpPeer, Option<String>)> = None;

    for line in lines {
        if let Some(start) = PANOS_PEER_START.captures(line) {
            current = Some((
                BgpPeer {
                    name: start[1].to_string(),
                    ip: String::new(),
                    as_number: "UNKNOWN".to_string(),
                    state: "UNKNOWN".to_string(),
                    prefixes_received: "0".to_string(),
                    prefixes_accepted: "0".to_string(),
                    updown: None,
                },
                None,
            ));
            continue;
        }

        let Some((peer, key)) = current.as_mut() else {
            continue;
        };

        if let Some(address) = PANOS_PEER_ADDRESS.captures(line) {
            peer.ip = address[1].to_string();
            *key = Some(peer_key(peer));
        } else if let Some(remote_as) = PANOS_PEER_AS.captures(line) {
            peer.as_number = remote_as[1].to_string();
        } else if let Some(status) = PANOS_PEER_STATUS.captures(line) {
            let state = &status[1];
            peer.state = if state.eq_ignore_ascii_case("established") {
                "Estab".to_string()
            } else {
                state.to_string()
            };

            if let Some(secs) = status.get(2) {
                peer.updown = Some(format!("{} secs", secs.as_str()));
            }
        } else if let Some(incoming) = PANOS_PEER_INCOMING.captures(line)
            && peer.prefixes_received == "0"
        {
            // First AFI/SAFI block only (ipv4 unicast comes first).
            peer.prefixes_received = incoming[1].to_string();
            peer.prefixes_accepted = incoming[2].to_string();
        } else {
            continue;
        }

        if let Some(key) = key {
            peers.insert(key.clone(), peer.clone());
        }
    }

    peers
}

/// Peers from PAN-OS `show routing protocol bgp peer` blocks, in the
/// same shape [`parse_bgp_summary`] produces, so the BGP findings treat
/// a firewall peer exactly like a switch peer.
///
/// "Established" is stored as "Estab" so the state transitions and the
/// uptime reset check share one vocabulary; other PAN-OS states (Idle,
/// Active, Connect, OpenSent) are kept as written.
pub fn parse_panos_bgp_peers(lines: &[String]) -> Vec<BgpPeer> {
    parse_panos_bgp_peers_map(lines).into_values().collect()
}

fn parse_bgp_peers_map(sections: &Sections) -> PeerMap {
    let empty: Vec<String> = Vec::new();
    let mut peers = parse_bgp_summary_map(sections.get("show ip bgp summary").unwrap_or(&empty));
    peers.extend(parse_panos_bgp_peers_map(
        sections.get("show routing protocol bgp peer").unwrap_or(&empty),
    ));
    peers
}

/// Peers from whichever BGP command the capture holds.
pub fn parse_bgp_peers(sections: &Sections) -> Vec<BgpPeer> {
    parse_bgp_peers_map(sections).into_values().collect()
}

/// One BGP peer finding in the shared finding shape.
///
/// The peer context is kept (before / after / peer) because tests and
/// the summary text read it; subject and fields are what the renderer
/// uses, so a BGP finding and a prefix-list finding draw the same way.
#[allow(clippy::too_many_arguments)]
fn bgp_finding(
    classification: Classification,
    category: &str,
    impact: Impact,
    title: &str,
    peer: &BgpPeer,
    before: Option<&BgpPeer>,
    after: Option<&BgpPeer>,
    summary: String,
    evidence: &str,
) -> Finding {
    fn updown_of(peer: &BgpPeer) -> &str {
        peer.updown
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("n/a")
    }

    let state_before = before.map_or("Not Present", |p| p.state.as_str());
    let state_after = after.map_or("Not Present", |p| p.state.as_str());
    let rx_before = before.map_or("0", |p| p.prefixes_received.as_str());
    let rx_after = after.map_or("0", |p| p.prefixes_received.as_str());
    let acc_before = before.map_or("0", |p| p.prefixes_accepted.as_str());
    let acc_after = after.map_or("0", |p| p.prefixes_accepted.as_str());
    let updown_before = before.map_or("Not Present", updown_of);
    let updown_after = after.map_or("Not Present", updown_of);

    let mut finding = Finding::new(classification, category, impact, title);
    finding.subject = vec![peer.name.clone(), peer.ip.clone(), format!("AS{}", peer.as_number)];
    finding.fields = vec![
        Field::new("State", state_before, state_after),
        Field::new("Prefixes Received", rx_before, rx_after),
        Field::new("Prefixes Accepted", acc_before, acc_after),
        Field::new("Up/Down", updown_before, updown_after),
    ];
    finding.summary = summary;
    finding.evidence = evidence.to_string();
    finding.bgp = Some(BgpContext {
        peer: peer.clone(),
        before: before.cloned(),
        after: after.cloned(),
    });
    finding
}

/// A prefix count as a number; anything that is not plain digits is 0.
fn received_count(peer: &BgpPeer) -> i64 {
    if is_digits(&peer.prefixes_received) {
        peer.prefixes_received.parse().unwrap_or(0)
    } else {
        0
    }
}

fn note_suffix(entry: &Expectation) -> String {
    if entry.note.is_empty() {
        String::new()
    } else {
        format!(" Note: {}", entry.note)
    }
}

/// Rate a prefix-count change against the device's expectations.
///
/// `expectations` is `None` when no file is in play (Changed + hedge),
/// else the list of entries for this device, possibly empty (every
/// delta is then either as planned, different from plan, or
/// unexplained).
fn prefix_delta_finding(
    peer: &BgpPeer,
    before: &BgpPeer,
    after: &BgpPeer,
    delta: i64,
    expectations: Option<&[Expectation]>,
    evidence: &str,
) -> Finding {
    let Some(expectations) = expectations else {
        return bgp_finding(
            Classification::Routing,
            "BGP prefixes",
            Impact::Changed,
            "BGP Prefix Count Changed",
            peer,
            Some(before),
            Some(after),
            format!("Prefix count changed by {delta:+}. {PREFIX_DELTA_HEDGE}"),
            evidence,
        );
    };

    let Some(entry) = expectations::match_peer(expectations, peer) else {
        return bgp_finding(
            Classification::Routing,
            "BGP prefixes",
            Impact::Attention,
            TITLE_UNEXPLAINED,
            peer,
            Some(before),
            Some(after),
            format!("Prefix count changed by {delta:+}, and no entry in your expectations file covers this peer."),
            evidence,
        );
    };

    let planned = expectations::describe(entry);
    let note = note_suffix(entry);
    let after_received = received_count(after);
    let met = match entry.expected {
        Expected::Delta(expected) => expected == delta,
        Expected::Prefixes(expected) => expected == after_received,
    };

    if met {
        return bgp_finding(
            Classification::Routing,
            "BGP prefixes",
            Impact::Stable,
            TITLE_AS_PLANNED,
            peer,
            Some(before),
            Some(after),
            format!("Prefix count changed by {delta:+}, which is what you planned for ({planned}).{note}"),
            evidence,
        );
    }

    bgp_finding(
        Classification::Routing,
        "BGP prefixes",
        Impact::Attention,
        TITLE_DIFFERS,
        peer,
        Some(before),
        Some(after),
        format!("Prefix count changed by {delta:+}, but you planned for {planned}.{note}"),
        evidence,
    )
}

/// Per-peer findings: state changes, prefix deltas (rated against
/// expectations when given), resets, peers that appeared or vanished.
///
/// `expectations`: this device's entries from the expectations file, or
/// `None` when no file is in play.
pub fn bgp_neighbor_findings(
    pre: &Sections,
    post: &Sections,
    config_changes: &[DiffLine],
    expectations: Option<&[Expectation]>,
) -> Vec<Finding> {
    let pre_bgp = parse_bgp_peers_map(pre);
    let post_bgp = parse_bgp_peers_map(post);

    let mut findings = Vec::new();
    let config_text = config_changes
        .iter()
        .map(DiffLine::ndiff)
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();

    let mut removed: Vec<&String> = pre_bgp.keys().filter(|key| !post_bgp.contains_key(*key)).collect();
    removed.sort();

    for key in removed {
        let before = &pre_bgp[key];

        findings.push(bgp_finding(
            Classification::Protocol,
            "BGP state",
            Impact::Attention,
            "BGP Peer Removed From Summary",
            before,
            Some(before),
            None,
            "This peer is in the precheck and gone from the postcheck. Either the neighbor was removed from \
             the config, or the session never came back."
                .to_string(),
            "show ip bgp summary",
        ));
    }

    let mut added: Vec<&String> = post_bgp.keys().filter(|key| !pre_bgp.contains_key(*key)).collect();
    added.sort();

    for key in added {
        let after = &post_bgp[key];

        findings.push(bgp_finding(
            Classification::Protocol,
            "BGP state",
            Impact::Stable,
            "BGP Peer Added",
            after,
            None,
            Some(after),
            "This peer isn't in the precheck and shows up in the postcheck. It's new since the window started."
                .to_string(),
            "show ip bgp summary",
        ));
    }

    let mut common: Vec<&String> = pre_bgp.keys().filter(|key| post_bgp.contains_key(*key)).collect();
    common.sort();

    for key in common {
        let before = &pre_bgp[key];
        let after = &post_bgp[key];

        let detected_evidence = if config_text.contains(&after.ip.to_lowercase()) && config_text.contains("shutdown") {
            "show ip bgp summary + related BGP shutdown/no shutdown config"
        } else if config_text.contains("prefix-list") || config_text.contains("valid-networks") {
            "show ip bgp summary + BGP prefix-list/valid-networks config"
        } else if config_text.contains("community") || config_text.contains("route-map") {
            "show ip bgp summary + BGP route-map/community config"
        } else {
            "show ip bgp summary"
        };

        if before.state != after.state {
            let (title, impact, summary) = if before.state == "Idle(Admin)" && after.state == "Estab" {
                (
                    "BGP Peer Activated",
                    Impact::Stable,
                    "Someone un-shut this peer during the window and it came up.",
                )
            } else if before.state == "Estab" && after.state == "Idle(Admin)" {
                (
                    "BGP Peer Shut Down",
                    Impact::Attention,
                    "Someone shut this peer down during the window. It's idle on purpose, not broken.",
                )
            } else {
                (
                    "BGP Peer State Changed",
                    Impact::Attention,
                    "This peer isn't in the state it started the window in.",
                )
            };

            findings.push(bgp_finding(
                Classification::Protocol,
                "BGP state",
                impact,
                title,
                after,
                Some(before),
                Some(after),
                summary.to_string(),
                detected_evidence,
            ));
        } else if after.state == "Estab" && session_reset(before, after) {
            // Estab -> Estab looks healthy; a smaller uptime is the only
            // trace of a session that dropped and came straight back.
            let delta = received_count(after) - received_count(before);
            let prefix_note = if delta == 0 && before.prefixes_accepted == after.prefixes_accepted {
                "Prefix counts came back the same.".to_string()
            } else {
                format!("Prefix count also changed by {delta:+} across the reset.")
            };
            let updown_before = before.updown.as_deref().unwrap_or_default();
            let updown_after = after.updown.as_deref().unwrap_or_default();

            findings.push(bgp_finding(
                Classification::Protocol,
                "BGP state",
                Impact::Attention,
                "BGP Session Reset",
                after,
                Some(before),
                Some(after),
                format!(
                    "This session dropped and came back during the window. It reads Established in both \
                     captures, so nothing else gives it away - but uptime went from {updown_before} to \
                     {updown_after}, and a session that never dropped can only count up. {prefix_note}"
                ),
                detected_evidence,
            ));
        } else if before.prefixes_received != after.prefixes_received
            || before.prefixes_accepted != after.prefixes_accepted
        {
            let delta = received_count(after) - received_count(before);

            findings.push(prefix_delta_finding(
                after,
                before,
                after,
                delta,
                expectations,
                detected_evidence,
            ));
        } else if let Some(expectations) = expectations.filter(|entries| !entries.is_empty()) {
            // Nothing moved on this peer. If the plan said it would, that
            // is the change not having taken effect.
            let after_received = received_count(after);
            let unmet = expectations::match_peer(expectations, after).filter(|entry| match entry.expected {
                Expected::Delta(expected) => expected != 0,
                Expected::Prefixes(expected) => expected != after_received,
            });

            if let Some(entry) = unmet {
                let note = note_suffix(entry);
                let planned = expectations::describe(entry);
                findings.push(bgp_finding(
                    Classification::Routing,
                    "BGP prefixes",
                    Impact::Attention,
                    TITLE_NOT_MET,
                    after,
                    Some(before),
                    Some(after),
                    format!(
                        "You planned for {planned}, but the count didn't move - {after_received} received in \
                         both captures.{note}"
                    ),
                    detected_evidence,
                ));
            }
        }
    }

    findings
}
