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

/// Route-map lines that bias which member of a pair is preferred, rather
/// than deciding which routes match or where they go. A redundant pair is
/// deliberately asymmetric in exactly these, so they are dropped before the
/// two members are compared.
///
/// Their *absence* is a setting too: the preferred member of a pair has no
/// prepend line at all where the backup has `set as-path prepend 4280000001`,
/// so masking the value is not enough - the line has to go. Clause 30 of one
/// fleet's EACN-OUT is that case, and it read as 22 lines against 23.
///
/// What stays is everything that decides reachability: the clause headers and
/// their permit/deny, every match line, `set ip next-hop`, `set origin`. Those
/// must agree, because a peer that lands on either member has to be offered
/// and accept the same routes.
static ROUTE_MAP_TUNING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)^(
              description
            | set \s+ as-path \s+ prepend
            | set \s+ local-preference
            | set \s+ metric
            | set \s+ (ext)?community
            | set \s+ weight
        )\b",
    )
    .unwrap()
});

/// A PAN-OS HA group header, with or without the group's local label.
static HA_GROUP_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^Group\s+\d+$").unwrap());

/// A route-map body with the per-member preference tuning dropped.
fn canonical_route_map(body: &[String]) -> Vec<&str> {
    body.iter()
        .map(|line| line.trim())
        .filter(|line| !ROUTE_MAP_TUNING.is_match(line))
        .collect()
}

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

        // "Group 1:" on one member and "Group 1: MMP-E-HA" on the other are
        // the same block, but only the bare form looks like a block header to
        // the rule below, so one member's leaves land under "Group 1/Local
        // Information/Mode" and the other's under "Local Information/Mode".
        // Every key then differs and a synchronized pair reads as 26
        // mismatches. The label is a local name an operator typed, not
        // synchronized state - one fleet's four firewalls carry "",
        // "MMP-E-HA", "MMP-W-FW1" and "MMP-W-BU" - so treat the line as a
        // header either way and drop the label.
        if HA_GROUP_HEADER.is_match(key) {
            stack.push((indent, key.to_string()));
            continue;
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
                    format!(
                        "{missing_on} lost prefix-list {name} during this window. Both members had it in the \
                         precheck."
                    ),
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
                "Pair Prefix-Lists Differ",
                pair,
                vec![name.clone()],
                fields,
                format!(
                    "A peer gets different routes depending on which member it lands on. Prefix-list {name} \
                     differs at {} sequence(s), and a redundant pair is supposed to carry the same policy. Either \
                     one side was edited alone, or a sequence got overwritten on one side.",
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
                    format!(
                        "{missing_on} lost route-map {name} during this window. Both members had it in the \
                         precheck."
                    ),
                    map_source,
                ));
            }
            continue;
        };

        if body_a == body_b {
            continue;
        }

        // A redundant pair is deliberately asymmetric: you make one member
        // preferred by prepending your own AS more times on it, by setting a
        // lower local-preference, and you label the result "Path 1".."Path 4".
        // Those differences are the design, not a defect, and on one fleet
        // they accounted for 25 of 30 findings - enough noise to bury the 5
        // that mattered. Compare the bodies with the tuning dropped: if they
        // match once the knob settings are set aside, there is nothing to
        // report. Anything that changes which routes match, or where they go,
        // still differs and still fires.
        if canonical_route_map(body_a) == canonical_route_map(body_b) {
            continue;
        }

        let detail = differing_lines(a, body_a, b, body_b);
        let removed = detail.iter().filter(|line| line.kind == DiffKind::Removed).count();
        let added = detail.len() - removed;

        let mut finding = pair_finding(
            Classification::Routing,
            "Pair Route-Maps Differ",
            pair,
            vec![name.clone()],
            vec![
                Field::new("Lines", body_a.len().to_string(), body_b.len().to_string()),
                Field::new("Differing lines", removed.to_string(), added.to_string()),
            ],
            format!(
                "Route-map {name} differs between the two members in a way that isn't preference tuning. Lines \
                 only on {a} are red, lines only on {b} are green. This skips prepend depth, local-preference, \
                 metric, and community, because a pair is meant to differ in those."
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
                "Pair HA State Differs",
                pair,
                vec!["high-availability".to_string()],
                fields,
                format!(
                    "These two members disagree on {} HA value(s) that a healthy pair keeps in sync. Values that \
                     depend on which member is active - state, priority, and addresses - don't count. A version, \
                     sync, or cookie mismatch means one member didn't get what the other did.",
                    differing.len()
                ),
                HA_COMMAND,
            ));
        }

        // The firewall grades its own content versions against its peer's and
        // reports the verdict. Both members print the same verdict, so a
        // Mismatch reads as agreement to the key-by-key compare above and
        // slips through it - it needs asking for directly.
        let mismatched: BTreeSet<&String> = ha_a
            .keys()
            .chain(ha_b.keys())
            .filter(|key| {
                key.to_lowercase().contains("compatibility")
                    && [ha_a.get(*key), ha_b.get(*key)]
                        .iter()
                        .flatten()
                        .any(|value| value.to_lowercase().contains("mismatch"))
            })
            .collect();

        if !mismatched.is_empty() {
            let not_present = || "Not Present".to_string();
            let fields = mismatched
                .iter()
                .map(|key| {
                    Field::new(
                        key.rsplit('/').next().unwrap_or(key),
                        ha_a.get(*key).cloned().unwrap_or_else(not_present),
                        ha_b.get(*key).cloned().unwrap_or_else(not_present),
                    )
                })
                .collect();
            findings.push(pair_finding(
                Classification::Protocol,
                "Pair HA Content Version Mismatch",
                pair,
                vec!["high-availability".to_string()],
                fields,
                format!(
                    "This pair disagrees with itself: {} content version(s) read Mismatch. Both members print \
                     the same verdict, so comparing the two captures can't catch it. Policy that leans on that \
                     content - an application, a threat signature, an IoT device profile - can decide differently \
                     after a failover than before it. Run 'show system info' on both members to see which file is \
                     behind, then push that update to the stale one.",
                    mismatched.len()
                ),
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
