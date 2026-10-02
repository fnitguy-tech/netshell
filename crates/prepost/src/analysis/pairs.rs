//! Pair symmetry: the two members of a redundant pair compared against
//! each other, because "SW-1 and SW-2 now disagree" is invisible to a
//! strictly per-device report.
//!
//! A redundant pair (SW-1 / SW-2, FW-1 / FW-2) is supposed to carry
//! the same policy. The per-device findings cannot see "SW-1 and SW-2
//! now disagree", which is the real signature of a change applied to
//! one member only, so the two postcheck captures are compared against
//! each other as well.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::capture::Sections;
use crate::difflib::ndiff;

use super::finding::{Classification, DiffKind, DiffLine, Field, Finding, Impact};
use super::prefix_list::{
    PREFIX_LIST_HITS, PrefixLists, SHOW_RUNNING_CONFIG, collapse_whitespace, prefix_lists_with_source,
};

/// The category every pair-symmetry finding carries.
pub const CATEGORY: &str = "Pair symmetry";

/// The command route-maps are read from when both captures have it.
pub const SHOW_ROUTE_MAP: &str = "show route-map";
/// The PAN-OS HA command compared between the members of a pair.
pub const HA_COMMAND: &str = "show high-availability state";

static PAIR_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.*?)(\d+)$").unwrap());
static IPV4_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+\.\d+\.\d+\.\d+$").unwrap());

static ROUTE_MAP_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*route-map\s+(\S+?),?(\s+.*)?$").unwrap());
static ROUTE_MAP_HIT_LINES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(Match|Set)?\s*clauses?\s+hit").unwrap());

/// PAN-OS "show high-availability state" keys that differ between the
/// two members of a healthy pair by design (one is active, one
/// passive; each has its own addresses, serial and timers). Everything
/// else - mode, software and content versions, sync state, encryption,
/// cookies - is expected to match, and a mismatch is what a
/// half-applied change looks like.
pub const HA_ROLE_KEYS: [&str; 12] = [
    "state",
    "priority",
    "address",
    "mac",
    "serial",
    "hostname",
    "last ",
    "duration",
    "time",
    "connection",
    "preempt hold",
    "uptime",
];

/// Pairs whose hostnames differ only by a trailing number. Groups of
/// three or more and bare-IP capture names are never paired.
///
/// SITE-A-SW-1 / SITE-A-SW-2 pair up; SITE-B-SW-1 alone does not; a
/// group of three or more (LEAF-1/2/3) is not a pair and is left alone
/// rather than guessed at. A capture named after a bare management IP
/// (the collector's fallback for platforms it cannot ask for a
/// hostname) is never paired: 192.0.2.11 and 192.0.2.12 share a stem
/// by accident.
pub fn infer_pairs(hostnames: &[String]) -> Vec<(String, String)> {
    let mut groups: BTreeMap<String, Vec<&String>> = BTreeMap::new();

    for hostname in hostnames {
        if let Some(suffix) = PAIR_SUFFIX.captures(hostname)
            && !IPV4_NAME.is_match(hostname)
        {
            groups.entry(suffix[1].to_lowercase()).or_default().push(hostname);
        }
    }

    groups
        .into_values()
        .filter(|members| members.len() == 2)
        .map(|mut members| {
            members.sort();
            (members[0].clone(), members[1].clone())
        })
        .collect()
}

/// Explicit pairs (from the inventory) take precedence for the devices
/// they name; the rest are inferred.
///
/// Explicit inventory pairs count only where both members were
/// captured; inferred pairs cover the devices the explicit list does
/// not mention.
pub fn resolve_pairs(hostnames: &[String], explicit: Option<&[(String, String)]>) -> Vec<(String, String)> {
    let by_lower: HashMap<String, &String> = hostnames.iter().map(|host| (host.to_lowercase(), host)).collect();
    let mut pairs = Vec::new();
    let mut claimed: HashSet<&String> = HashSet::new();

    for (first, second) in explicit.unwrap_or_default() {
        let members = (
            by_lower.get(&first.to_lowercase()),
            by_lower.get(&second.to_lowercase()),
        );

        if let (Some(&first), Some(&second)) = members
            && first != second
        {
            let mut sorted = [first, second];
            sorted.sort();
            pairs.push((sorted[0].clone(), sorted[1].clone()));
            claimed.insert(first);
            claimed.insert(second);
        }
    }

    let unclaimed: Vec<String> = hostnames
        .iter()
        .filter(|host| !claimed.contains(host))
        .cloned()
        .collect();
    pairs.extend(infer_pairs(&unclaimed));

    pairs
}

/// `{route-map name: [body lines]}` from `show route-map`, hit counters stripped.
///
/// Parses 'show route-map' (or the config's route-map blocks) into
/// `{name: [normalized lines]}`, hit counters dropped, whitespace
/// collapsed, so two captures of the same policy compare equal line
/// for line.
pub fn parse_route_maps(lines: &[String]) -> IndexMap<String, Vec<String>> {
    let mut maps: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut current: Option<String> = None;

    for line in lines {
        if let Some(header) = ROUTE_MAP_HEADER.captures(line) {
            let name = header[1].to_string();
            let rest = collapse_whitespace(&header.get(2).map_or("", |m| m.as_str()).replace(',', " "));
            maps.entry(name.clone())
                .or_default()
                .push(format!("route-map {rest}").trim().to_string());
            current = Some(name);
            continue;
        }

        let Some(name) = current.as_deref() else {
            continue;
        };

        if line.trim().is_empty() {
            continue;
        }

        if !line.starts_with([' ', '\t']) {
            // Non-indented, not a header: the block (or the section) ended.
            current = None;
            continue;
        }

        if ROUTE_MAP_HIT_LINES.is_match(line) {
            continue;
        }

        let normalized = collapse_whitespace(&PREFIX_LIST_HITS.replace_all(line, ""));
        maps.entry(name.to_string()).or_default().push(normalized);
    }

    maps
}

/// Route-maps for one capture, from the same source as its partner.
pub fn route_maps_from(
    sections: &Sections,
    other_sections: &Sections,
) -> (IndexMap<String, Vec<String>>, &'static str) {
    if sections.contains_key(SHOW_ROUTE_MAP) && other_sections.contains_key(SHOW_ROUTE_MAP) {
        return (parse_route_maps(&sections[SHOW_ROUTE_MAP]), SHOW_ROUTE_MAP);
    }

    let config_lines = sections.get(SHOW_RUNNING_CONFIG).map(Vec::as_slice).unwrap_or(&[]);
    (parse_route_maps(config_lines), SHOW_RUNNING_CONFIG)
}

/// PAN-OS HA "Local Information" key/values minus role-dependent keys.
///
/// Local-side key/value lines of 'show high-availability state' as
/// `{"Block/Key": value}`, stopping at the Peer Information block
/// (which describes the other member and is compared from its own
/// capture).
pub fn parse_ha_state(lines: &[String]) -> IndexMap<String, String> {
    let mut values = IndexMap::new();
    let mut stack: Vec<(usize, String)> = Vec::new();

    for line in lines {
        let stripped = line.trim();

        if stripped.is_empty() || !stripped.contains(':') {
            continue;
        }

        let indent = line.chars().count() - line.trim_start().chars().count();
        let (key, value) = stripped.split_once(':').unwrap_or((stripped, ""));
        let key = key.trim();
        let value = value.trim();

        while stack.last().is_some_and(|(top, _)| *top >= indent) {
            stack.pop();
        }

        let lower = key.to_lowercase();

        if lower.starts_with("peer information") {
            break;
        }

        if value.is_empty() {
            stack.push((indent, key.to_string()));
            continue;
        }

        if HA_ROLE_KEYS.iter().any(|role_key| lower.contains(role_key)) {
            continue;
        }

        let path = stack
            .iter()
            .map(|(_, name)| name.as_str())
            .chain(std::iter::once(key))
            .collect::<Vec<_>>()
            .join("/");
        values.insert(path, value.to_string());
    }

    values
}

/// One pair-symmetry finding: Attention, attributed to both members.
pub fn pair_finding(
    classification: Classification,
    title: &str,
    pair: &(String, String),
    subject: Vec<String>,
    fields: Vec<Field>,
    summary: String,
    evidence: &str,
) -> Finding {
    let (a, b) = pair;
    let mut finding = Finding::new(classification, CATEGORY, Impact::Attention, title);
    finding.subject = std::iter::once(format!("{a} vs {b}")).chain(subject).collect();
    finding.fields = fields;
    finding.arrow = "vs".to_string();
    finding.summary = summary;
    finding.evidence = evidence.to_string();
    finding.devices = vec![a.clone(), b.clone()];
    finding
}

/// The Python `str(len(x)) if x else "Not Present"`: a missing or
/// empty collection reads "Not Present".
fn count_or_not_present(len: Option<usize>) -> String {
    match len {
        Some(len) if len > 0 => len.to_string(),
        _ => "Not Present".to_string(),
    }
}

/// The empty capture a missing precheck stands in for.
fn empty_sections() -> Sections {
    Sections::new()
}

/// Attention findings attributed to both members: same-named
/// prefix-lists and route-maps that differ, entries present on both in
/// the precheck but missing on one in the postcheck, HA state splits.
///
/// Only commands present in both captures are compared. Same-named
/// prefix-lists and route-maps must match entry for entry; a list that
/// both members had in the precheck but only one has now is reported
/// too, since that is what a list deleted on one side looks like.
pub fn pair_findings(
    pair: &(String, String),
    post_a: &Sections,
    post_b: &Sections,
    pre_a: Option<&Sections>,
    pre_b: Option<&Sections>,
) -> Vec<Finding> {
    let (a, b) = pair;
    let mut findings = Vec::new();
    let empty = empty_sections();
    let pre_a = pre_a.unwrap_or(&empty);
    let pre_b = pre_b.unwrap_or(&empty);

    let (lists_a, source): (PrefixLists, &str) = prefix_lists_with_source(post_a, post_b);
    let (lists_b, _) = prefix_lists_with_source(post_b, post_a);
    let (pre_lists_a, _) = prefix_lists_with_source(pre_a, pre_b);
    let (pre_lists_b, _) = prefix_lists_with_source(pre_b, pre_a);

    let names: BTreeSet<&String> = lists_a.keys().chain(lists_b.keys()).collect();

    for name in names {
        let entries_a = lists_a.get(name);
        let entries_b = lists_b.get(name);

        let (Some(entries_a), Some(entries_b)) = (entries_a, entries_b) else {
            if pre_lists_a.contains_key(name) && pre_lists_b.contains_key(name) {
                let missing_on = if entries_a.is_none() { a } else { b };
                findings.push(pair_finding(
                    Classification::Routing,
                    "Pair Prefix-List Missing On One Device",
                    pair,
                    vec![name.clone()],
                    vec![Field::new(
                        "Entries",
                        count_or_not_present(entries_a.map(IndexMap::len)),
                        count_or_not_present(entries_b.map(IndexMap::len)),
                    )],
                    format!("Both members had prefix-list {name} in the precheck; {missing_on} no longer has it."),
                    source,
                ));
            }
            continue;
        };

        let differing: BTreeSet<u64> = entries_a
            .keys()
            .chain(entries_b.keys())
            .copied()
            .filter(|seq| entries_a.get(seq) != entries_b.get(seq))
            .collect();

        if !differing.is_empty() {
            let not_present = || "Not Present".to_string();
            let fields = differing
                .iter()
                .map(|seq| {
                    Field::new(
                        format!("seq {seq}"),
                        entries_a.get(seq).cloned().unwrap_or_else(not_present),
                        entries_b.get(seq).cloned().unwrap_or_else(not_present),
                    )
                })
                .collect();
            findings.push(pair_finding(
                Classification::Routing,
                "Pair Prefix-List Divergence",
                pair,
                vec![name.clone()],
                fields,
                format!(
                    "Prefix-list {name} differs between the two members at {} sequence(s). A redundant pair is \
                     expected to carry the same policy; a one-sided edit (or an overwritten sequence on one side) \
                     advertises or accepts different routes depending on which member a peer talks to.",
                    differing.len()
                ),
                source,
            ));
        }
    }

    let (maps_a, map_source) = route_maps_from(post_a, post_b);
    let (maps_b, _) = route_maps_from(post_b, post_a);
    let (pre_maps_a, _) = route_maps_from(pre_a, pre_b);
    let (pre_maps_b, _) = route_maps_from(pre_b, pre_a);

    let names: BTreeSet<&String> = maps_a.keys().chain(maps_b.keys()).collect();

    for name in names {
        let body_a = maps_a.get(name).map(Vec::as_slice);
        let body_b = maps_b.get(name).map(Vec::as_slice);

        let (Some(body_a), Some(body_b)) = (body_a, body_b) else {
            if pre_maps_a.contains_key(name) && pre_maps_b.contains_key(name) {
                let missing_on = if body_a.is_none() { a } else { b };
                findings.push(pair_finding(
                    Classification::Routing,
                    "Pair Route-Map Missing On One Device",
                    pair,
                    vec![name.clone()],
                    vec![Field::new(
                        "Lines",
                        count_or_not_present(body_a.map(<[String]>::len)),
                        count_or_not_present(body_b.map(<[String]>::len)),
                    )],
                    format!("Both members had route-map {name} in the precheck; {missing_on} no longer has it."),
                    map_source,
                ));
            }
            continue;
        };

        if body_a == body_b {
            continue;
        }

        let detail = differing_lines(a, body_a, b, body_b);
        let removed = detail.iter().filter(|line| line.kind == DiffKind::Removed).count();
        let added = detail.len() - removed;

        let mut finding = pair_finding(
            Classification::Routing,
            "Pair Route-Map Divergence",
            pair,
            vec![name.clone()],
            vec![
                Field::new("Lines", body_a.len().to_string(), body_b.len().to_string()),
                Field::new("Differing lines", removed.to_string(), added.to_string()),
            ],
            format!(
                "Route-map {name} differs between the two members. Lines only on {a} are shown in red, lines only \
                 on {b} in green."
            ),
            map_source,
        );
        finding.detail = detail;
        findings.push(finding);
    }

    if post_a.contains_key(HA_COMMAND) && post_b.contains_key(HA_COMMAND) {
        let ha_a = parse_ha_state(&post_a[HA_COMMAND]);
        let ha_b = parse_ha_state(&post_b[HA_COMMAND]);
        let differing: BTreeSet<&String> = ha_a
            .keys()
            .chain(ha_b.keys())
            .filter(|key| ha_a.get(*key) != ha_b.get(*key))
            .collect();

        if !differing.is_empty() {
            let not_present = || "Not Present".to_string();
            let fields = differing
                .iter()
                .map(|key| {
                    Field::new(
                        key.as_str(),
                        ha_a.get(*key).cloned().unwrap_or_else(not_present),
                        ha_b.get(*key).cloned().unwrap_or_else(not_present),
                    )
                })
                .collect();
            findings.push(pair_finding(
                Classification::Protocol,
                "Pair HA State Divergence",
                pair,
                vec!["high-availability".to_string()],
                fields,
                "HA state values that should match on both members of a healthy pair differ (role-dependent \
                 values such as State and Priority are ignored). A version, sync or cookie mismatch means one \
                 member did not receive what the other did."
                    .to_string(),
                HA_COMMAND,
            ));
        }
    }

    findings
}

/// Lines only in `body_a` (removed, prefixed `"{a}: "`) and only in
/// `body_b` (added, prefixed `"{b}: "`), in diff order.
fn differing_lines(a: &str, body_a: &[String], b: &str, body_b: &[String]) -> Vec<DiffLine> {
    let mut detail = Vec::new();

    for line in ndiff(body_a, body_b) {
        if let Some(text) = line.strip_prefix("- ") {
            detail.push(DiffLine::removed(format!("{a}: {text}")));
        } else if let Some(text) = line.strip_prefix("+ ") {
            detail.push(DiffLine::added(format!("{b}: {text}")));
        }
    }

    detail
}
