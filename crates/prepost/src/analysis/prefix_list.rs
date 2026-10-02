//! Prefix lists parsed entry by entry, so a withdrawn permit or a
//! same-sequence overwrite becomes an impact-rated finding instead of
//! one grey line in a 380-line raw diff.

use indexmap::IndexMap;

use crate::capture::Sections;

use super::finding::Finding;

/// `{list name: {seq: rule}}`, hit counters stripped.
pub type PrefixLists = IndexMap<String, IndexMap<u64, String>>;

pub fn parse_prefix_lists(lines: &[String]) -> PrefixLists {
    let _ = lines;
    todo!("port of htmlreport.parse_prefix_lists()")
}

/// Prefix lists from `show ip prefix-list`, falling back to the
/// running config when that command was not captured.
pub fn prefix_lists_from(sections: &Sections) -> PrefixLists {
    let _ = sections;
    todo!("port of htmlreport.prefix_lists_from()")
}

/// Entry withdrawn / same-seq overwrite / whole list removed are
/// Attention, resequenced is Changed, added is Stable.
pub fn prefix_list_findings(pre: &Sections, post: &Sections) -> Vec<Finding> {
    let _ = (pre, post);
    todo!("port of htmlreport.prefix_list_findings()")
}
