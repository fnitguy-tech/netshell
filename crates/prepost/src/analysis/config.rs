//! BGP-relevant lines that changed in the running config.

use crate::capture::Sections;

use super::finding::DiffLine;

/// Keywords that make a config line BGP-relevant, on the line itself or
/// on the block header an indented change sits under.
pub const BGP_CONFIG_KEYWORDS: &[&str] = &[
    "router bgp",
    "neighbor",
    "route-map",
    "community",
    "shutdown",
    "prefix-list",
    "access-list",
    "access-group",
    "peer-group",
    "redist",
    "aggregate-address",
    "valid-networks",
    "auth-profile",
    "used-by",
    "bfd",
    "link-state",
    "protocol bgp",
];

/// ndiff-style lines: removed, added, and context for the block header
/// an indented change sits under.
pub fn bgp_config_changes(pre: &Sections, post: &Sections) -> Vec<DiffLine> {
    let _ = (pre, post);
    todo!("port of htmlreport.bgp_config_changes()")
}

/// Added/removed lines only; block-header context lines do not count.
pub fn count_config_changes(changes: &[DiffLine]) -> usize {
    changes
        .iter()
        .filter(|line| !matches!(line.kind, super::finding::DiffKind::Context))
        .count()
}
