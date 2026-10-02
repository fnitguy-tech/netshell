//! Normalized added/removed lines per command, and the operational
//! category each changed command counts toward.

use std::collections::BTreeMap;

use crate::capture::Sections;

use super::finding::{ClassificationCounts, DiffLine};

/// Normalized added/removed lines for every command whose normalized
/// output differs, keyed by command (sorted).
pub fn raw_diffs(pre: &Sections, post: &Sections) -> BTreeMap<String, Vec<DiffLine>> {
    let _ = (pre, post);
    todo!("port of htmlreport.raw_diffs()")
}

/// Count changed commands by operational category.
pub fn classify_raw_diff_commands(diffs: &BTreeMap<String, Vec<DiffLine>>) -> ClassificationCounts {
    let _ = diffs;
    todo!("port of htmlreport.classify_raw_diff_commands()")
}
