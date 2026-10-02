//! Interfaces that gained an address during the window but are still
//! down: the step configured cleanly and still does not work.

use indexmap::IndexMap;

use crate::capture::Sections;

use super::finding::Finding;

/// What is known about one interface after merging every source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceState {
    pub address: Option<String>,
    /// "up", "down", or `None` when no source reported a status.
    pub status: Option<String>,
}

/// `Et1` -> `Ethernet1` and friends.
pub fn expand_eos_name(name: &str) -> String {
    let _ = name;
    todo!("port of htmlreport.expand_eos_name()")
}

/// Merge `show ip interface brief`, `show interface all`, `show
/// interfaces status` and config addresses into one map.
pub fn parse_interfaces(sections: &Sections) -> IndexMap<String, InterfaceState> {
    let _ = sections;
    todo!("port of htmlreport.parse_interfaces()")
}

/// Gained address + down -> Attention; gained + up -> Stable; status
/// unknown -> no finding.
pub fn interface_findings(pre: &Sections, post: &Sections) -> Vec<Finding> {
    let _ = (pre, post);
    todo!("port of htmlreport.interface_findings()")
}
