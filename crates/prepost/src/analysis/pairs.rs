//! Pair symmetry: the two members of a redundant pair compared against
//! each other, because "SW-1 and SW-2 now disagree" is invisible to a
//! strictly per-device report.

use indexmap::IndexMap;

use crate::capture::Sections;

use super::finding::Finding;

/// Pairs whose hostnames differ only by a trailing number. Groups of
/// three or more and bare-IP capture names are never paired.
pub fn infer_pairs(hostnames: &[String]) -> Vec<(String, String)> {
    let _ = hostnames;
    todo!("port of htmlreport.infer_pairs()")
}

/// Explicit pairs (from the inventory) take precedence for the devices
/// they name; the rest are inferred.
pub fn resolve_pairs(hostnames: &[String], explicit: Option<&[(String, String)]>) -> Vec<(String, String)> {
    let _ = (hostnames, explicit);
    todo!("port of htmlreport.resolve_pairs()")
}

/// `{route-map name: [body lines]}` from `show route-map`, hit counters stripped.
pub fn parse_route_maps(lines: &[String]) -> IndexMap<String, Vec<String>> {
    let _ = lines;
    todo!("port of htmlreport.parse_route_maps()")
}

/// PAN-OS HA "Local Information" key/values minus role-dependent keys.
pub fn parse_ha_state(lines: &[String]) -> IndexMap<String, String> {
    let _ = lines;
    todo!("port of htmlreport.parse_ha_state()")
}

/// Attention findings attributed to both members: same-named
/// prefix-lists and route-maps that differ, entries present on both in
/// the precheck but missing on one in the postcheck, HA state splits.
pub fn pair_findings(
    pair: &(String, String),
    post_a: &Sections,
    post_b: &Sections,
    pre_a: Option<&Sections>,
    pre_b: Option<&Sections>,
) -> Vec<Finding> {
    let _ = (pair, post_a, post_b, pre_a, pre_b);
    todo!("port of htmlreport.pair_findings()")
}
