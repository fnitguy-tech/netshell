//! BGP: summary-table and PAN-OS peer-block parsing, uptime parsing,
//! session-reset detection and the per-peer findings.

use crate::capture::Sections;
use crate::expectations::Expectation;

use super::finding::{BgpPeer, DiffLine, Finding};

/// The generic caveat a prefix delta carries when nobody wrote down
/// what the change was meant to do.
pub const PREFIX_DELTA_HEDGE: &str =
    "This may be expected when routing policy, communities, failover, or advertised routes change.";

/// Parse an Up/Down token into `(seconds, granularity_seconds)`.
/// Handles `HH:MM:SS`, `1d02h`, `2w3d`, `1y2w`, PAN-OS `N secs`;
/// `never` and anything unparseable are `None`.
pub fn parse_uptime(token: &str) -> Option<(u64, u64)> {
    let _ = token;
    todo!("port of htmlreport.parse_uptime()")
}

/// True when the postcheck uptime is unambiguously smaller than the
/// precheck uptime (post + post_granularity <= pre).
pub fn session_reset(before: &BgpPeer, after: &BgpPeer) -> bool {
    let _ = (before, after);
    todo!("port of htmlreport.session_reset()")
}

/// Peers from an EOS/IOS `show ip bgp summary` table.
pub fn parse_bgp_summary(lines: &[String]) -> Vec<BgpPeer> {
    let _ = lines;
    todo!("port of htmlreport.parse_bgp_summary()")
}

/// Peers from PAN-OS `show routing protocol bgp peer` blocks.
pub fn parse_panos_bgp_peers(lines: &[String]) -> Vec<BgpPeer> {
    let _ = lines;
    todo!("port of htmlreport.parse_panos_bgp_peers()")
}

/// Peers from whichever BGP command the capture holds.
pub fn parse_bgp_peers(sections: &Sections) -> Vec<BgpPeer> {
    let _ = sections;
    todo!("port of htmlreport.parse_bgp_peers()")
}

/// Per-peer findings: state changes, prefix deltas (rated against
/// expectations when given), resets, peers that appeared or vanished.
pub fn bgp_neighbor_findings(
    pre: &Sections,
    post: &Sections,
    config_changes: &[DiffLine],
    expectations: Option<&[Expectation]>,
) -> Vec<Finding> {
    let _ = (pre, post, config_changes, expectations);
    todo!("port of htmlreport.bgp_neighbor_findings()")
}
