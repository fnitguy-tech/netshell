//! Prefix lists parsed entry by entry, so a withdrawn permit or a
//! same-sequence overwrite becomes an impact-rated finding instead of
//! one grey line in a 380-line raw diff.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::capture::Sections;

use super::finding::{Classification, DiffLine, Field, Finding, Impact};

/// `{list name: {seq: rule}}`, hit counters stripped.
pub type PrefixLists = IndexMap<String, IndexMap<u64, String>>;

/// The command prefix lists are read from when both captures have it.
pub const SHOW_PREFIX_LIST: &str = "show ip prefix-list";
/// The fallback source: the running config carries the same entries.
pub const SHOW_RUNNING_CONFIG: &str = "show running-config";

/// The category every prefix-list finding carries.
pub const CATEGORY: &str = "Prefix-list";

/// "ip prefix-list NAME" opens a list in both the EOS show output and
/// the running config; the one-line config form carries the entry on
/// the same line ("ip prefix-list NAME seq 10 permit 10.0.0.0/8"). A
/// Cisco-style header ("ip prefix-list NAME: 3 entries") leaves a
/// colon on the name.
static PREFIX_LIST_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(?:ip|ipv6)\s+prefix-list\s+(\S+)(.*)$").unwrap());
static PREFIX_LIST_ENTRY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*seq\s+(\d+)\s+(.+?)\s*$").unwrap());
/// Per-entry hit counters tick on their own; the entry is the point.
pub(crate) static PREFIX_LIST_HITS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\s*\(\s*\d+\s+(?:matches|hits)\s*\)\s*$").unwrap());

/// Collapse runs of whitespace, as Python's `" ".join(s.split())`.
pub(crate) fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse prefix-list listings into `{list_name: {seq: rule}}`.
///
/// `rule` is the entry text after the sequence number with hit counters
/// and extra whitespace removed, e.g. "permit 198.51.100.0/24 le 32",
/// so two captures of an untouched list compare equal.
pub fn parse_prefix_lists(lines: &[String]) -> PrefixLists {
    let mut lists = PrefixLists::new();
    let mut current: Option<String> = None;

    for line in lines {
        let header = PREFIX_LIST_HEADER.captures(line);

        let rest: &str = if let Some(header) = &header {
            let name = header
                .get(1)
                .map_or("", |m| m.as_str())
                .trim_end_matches(':')
                .to_string();
            lists.entry(name.clone()).or_default();
            current = Some(name);
            header.get(2).map_or("", |m| m.as_str())
        } else if current.is_some() {
            line
        } else {
            continue;
        };

        let Some(name) = current.as_deref() else {
            continue;
        };

        if let Some(entry) = PREFIX_LIST_ENTRY.captures(rest) {
            let Ok(seq) = entry[1].parse::<u64>() else {
                continue;
            };
            let rule = collapse_whitespace(&PREFIX_LIST_HITS.replace_all(&entry[2], ""));
            lists.entry(name.to_string()).or_default().insert(seq, rule);
        } else if header.is_none() && !rest.trim().is_empty() && !rest.starts_with([' ', '\t']) {
            // A non-indented line that is not a header ends the block
            // (config "!" separators, the next command's output).
            current = None;
        }
    }

    lists
}

/// Prefix-lists for one capture, plus which command they came from.
///
/// "show ip prefix-list" is preferred because it shows the list as the
/// device holds it; inventories that do not capture it still carry the
/// same entries in the running config. Both captures of a pair must
/// use the same source so a list is never compared against itself.
pub fn prefix_lists_with_source(sections: &Sections, other_sections: &Sections) -> (PrefixLists, &'static str) {
    if sections.contains_key(SHOW_PREFIX_LIST) && other_sections.contains_key(SHOW_PREFIX_LIST) {
        return (parse_prefix_lists(&sections[SHOW_PREFIX_LIST]), SHOW_PREFIX_LIST);
    }

    let config_lines = sections.get(SHOW_RUNNING_CONFIG).map(Vec::as_slice).unwrap_or(&[]);
    (parse_prefix_lists(config_lines), SHOW_RUNNING_CONFIG)
}

/// Prefix lists from `show ip prefix-list`, falling back to the
/// running config when that command was not captured.
pub fn prefix_lists_from(sections: &Sections) -> PrefixLists {
    prefix_lists_with_source(sections, sections).0
}

/// One prefix-list finding in the shared finding shape.
pub fn prefix_list_finding(
    impact: Impact,
    title: &str,
    name: &str,
    seq_label: Option<String>,
    fields: Vec<Field>,
    summary: String,
    evidence: &str,
) -> Finding {
    let mut finding = Finding::new(Classification::Routing, CATEGORY, impact, title);
    finding.subject = std::iter::once(name.to_string()).chain(seq_label).collect();
    finding.fields = fields;
    finding.summary = summary;
    finding.evidence = evidence.to_string();
    finding
}

/// Sequence + entry columns for a single-entry prefix-list finding.
pub fn entry_fields(
    seq_before: Option<u64>,
    seq_after: Option<u64>,
    rule_before: Option<&str>,
    rule_after: Option<&str>,
) -> Vec<Field> {
    fn seq(value: Option<u64>) -> String {
        value.map_or_else(|| "Not Present".to_string(), |seq| seq.to_string())
    }

    fn rule(value: Option<&str>) -> String {
        match value {
            Some(rule) if !rule.is_empty() => rule.to_string(),
            _ => "Not Present".to_string(),
        }
    }

    vec![
        Field::new("Sequence", seq(seq_before), seq(seq_after)),
        Field::new("Entry", rule(rule_before), rule(rule_after)),
    ]
}

/// Entries of one list in sequence order.
fn sorted_entries(entries: &IndexMap<u64, String>) -> Vec<(u64, &str)> {
    let mut sorted: Vec<(u64, &str)> = entries.iter().map(|(seq, rule)| (*seq, rule.as_str())).collect();
    sorted.sort_by_key(|(seq, _)| *seq);
    sorted
}

/// The lowest sequence in `entries` holding `rule`.
fn first_seq_holding(entries: &IndexMap<u64, String>, rule: &str) -> Option<u64> {
    sorted_entries(entries)
        .into_iter()
        .find(|(_, r)| *r == rule)
        .map(|(seq, _)| seq)
}

/// Interpret prefix-list changes entry by entry into impact-rated findings.
///
/// A permit that disappears is a withdrawn advertisement (or a route no
/// longer accepted, if the list is applied inbound), so it is rated
/// Attention, as is a sequence whose entry changed in place: on EOS,
/// configuring an existing sequence number silently replaces that
/// entry, which is the easiest way to drop a prefix without meaning
/// to. An entry that merely moved to a new sequence is Changed; a new
/// sequence is Stable. A whole list appearing or vanishing is reported
/// once.
pub fn prefix_list_findings(pre: &Sections, post: &Sections) -> Vec<Finding> {
    let (pre_lists, evidence) = prefix_lists_with_source(pre, post);
    let (post_lists, _) = prefix_lists_with_source(post, pre);

    let mut findings = Vec::new();
    let names: BTreeSet<&String> = pre_lists.keys().chain(post_lists.keys()).collect();

    for name in names {
        let (before, after) = match (pre_lists.get(name), post_lists.get(name)) {
            (Some(before), None) => {
                let mut finding = prefix_list_finding(
                    Impact::Attention,
                    "Prefix-List Removed",
                    name,
                    None,
                    vec![Field::new("Entries", before.len().to_string(), "Not Present")],
                    format!(
                        "Anything that still points at this list now matches nothing. All {} entries are gone \
                         from the postcheck, so every route the list used to permit falls through.",
                        before.len()
                    ),
                    evidence,
                );
                finding.detail = sorted_entries(before)
                    .into_iter()
                    .map(|(seq, rule)| DiffLine::removed(format!("seq {seq} {rule}")))
                    .collect();
                findings.push(finding);
                continue;
            }
            (None, Some(after)) => {
                let mut finding = prefix_list_finding(
                    Impact::Stable,
                    "Prefix-List Added",
                    name,
                    None,
                    vec![Field::new("Entries", "Not Present", after.len().to_string())],
                    format!(
                        "Nothing changes yet. The postcheck has a new list of {} entries, and it does nothing \
                         until a route-map or neighbor points at it.",
                        after.len()
                    ),
                    evidence,
                );
                finding.detail = sorted_entries(after)
                    .into_iter()
                    .map(|(seq, rule)| DiffLine::added(format!("seq {seq} {rule}")))
                    .collect();
                findings.push(finding);
                continue;
            }
            (Some(before), Some(after)) => (before, after),
            (None, None) => continue,
        };

        let before_rules: BTreeSet<&str> = before.values().map(String::as_str).collect();
        let seqs: BTreeSet<u64> = before.keys().chain(after.keys()).copied().collect();

        for seq in seqs {
            let rule_before = before.get(&seq).map(String::as_str);
            let rule_after = after.get(&seq).map(String::as_str);

            match (rule_before, rule_after) {
                (Some(rule_before), Some(rule_after)) => {
                    if rule_before == rule_after {
                        continue;
                    }

                    let fate = match first_seq_holding(after, rule_before) {
                        Some(moved_to) => format!("The previous entry still appears at seq {moved_to}."),
                        None => "The previous entry no longer appears anywhere in the list.".to_string(),
                    };

                    findings.push(prefix_list_finding(
                        Impact::Attention,
                        "Prefix-List Entry Replaced",
                        name,
                        Some(format!("seq {seq}")),
                        entry_fields(Some(seq), Some(seq), Some(rule_before), Some(rule_after)),
                        format!(
                            "seq {seq} now holds '{rule_after}' instead of '{rule_before}'. Reusing a sequence \
                             number replaces that entry instead of adding one, so the old line is gone. {fate}"
                        ),
                        evidence,
                    ));
                }
                (Some(rule_before), None) => {
                    if let Some(moved_to) = first_seq_holding(after, rule_before) {
                        findings.push(prefix_list_finding(
                            Impact::Changed,
                            "Prefix-List Entry Moved",
                            name,
                            Some(format!("seq {seq}")),
                            entry_fields(Some(seq), Some(moved_to), Some(rule_before), Some(rule_before)),
                            format!(
                                "The same entry moved from seq {seq} to seq {moved_to}. The list still matches \
                                 the same routes, unless this moved it past a deny."
                            ),
                            evidence,
                        ));
                    } else {
                        let action = rule_before
                            .split_whitespace()
                            .next()
                            .map_or_else(|| "permit".to_string(), str::to_lowercase);
                        let effect = if action == "permit" {
                            "Applied outbound, this route isn't advertised any more. Applied inbound, it isn't \
                             accepted."
                        } else {
                            "Routes this deny used to stop now get through."
                        };
                        findings.push(prefix_list_finding(
                            Impact::Attention,
                            "Prefix-List Entry Removed",
                            name,
                            Some(format!("seq {seq}")),
                            entry_fields(Some(seq), None, Some(rule_before), None),
                            format!(
                                "'{rule_before}' at seq {seq} is gone, and it doesn't come back at another \
                                 sequence. {effect}"
                            ),
                            evidence,
                        ));
                    }
                }
                (None, Some(rule_after)) => {
                    // An entry that was already in the list at another
                    // seq is reported once, as the resequence or
                    // overwrite above.
                    if before_rules.contains(rule_after) {
                        continue;
                    }
                    findings.push(prefix_list_finding(
                        Impact::Stable,
                        "Prefix-List Entry Added",
                        name,
                        Some(format!("seq {seq}")),
                        entry_fields(None, Some(seq), None, Some(rule_after)),
                        format!("'{rule_after}' was added at seq {seq}; existing entries are untouched."),
                        evidence,
                    ));
                }
                (None, None) => {}
            }
        }
    }

    findings
}
