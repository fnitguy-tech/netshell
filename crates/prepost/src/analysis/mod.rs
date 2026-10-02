//! Interpretation: parse the captures, produce impact-rated findings,
//! roll them up per device and network-wide.
//!
//! The pipeline mirrors the Python `htmlreport.analyze()`:
//!
//! 1. per device: BGP neighbour findings (with config-change context
//!    and optional expectations), prefix-list findings, interface
//!    findings, and the normalized raw diff of every command;
//! 2. pair symmetry findings across each redundant pair, attributed to
//!    both members but counted once;
//! 3. counts, weighted impact score, totals and ordering.

pub mod bgp;
pub mod config;
pub mod finding;
pub mod interfaces;
pub mod normalize;
pub mod pairs;
pub mod prefix_list;
pub mod rawdiff;

use std::path::Path;

pub use finding::{
    Analysis, BgpContext, BgpPeer, Classification, ClassificationCounts, DeviceReport, DiffKind, DiffLine,
    ExpectationTotals, Field, Finding, Impact, ImpactCounts,
};

use crate::expectations::Expectation;

/// Titles produced by the expectation rating, so the outcome summary
/// can say "23 as planned, 1 unexplained".
pub const TITLE_AS_PLANNED: &str = "BGP Prefix Count Changed As Planned";
pub const TITLE_DIFFERS: &str = "BGP Prefix Count Differs From Expectation";
pub const TITLE_UNEXPLAINED: &str = "BGP Prefix Count Changed Unexpectedly";
pub const TITLE_NOT_MET: &str = "Expected BGP Prefix Change Did Not Happen";

/// Diff every common device file between the two run folders and roll
/// up findings and totals.
///
/// `pairs`: explicit pairs from the inventory; pairs whose hostnames
/// differ only by a trailing number are inferred anyway.
/// `expectations`: entries from the expectations file, or `None` when
/// no file is in play (prefix deltas then keep the generic hedge).
pub fn analyze(
    precheck_folder: &Path,
    postcheck_folder: &Path,
    pairs: Option<&[(String, String)]>,
    expectations: Option<&[Expectation]>,
) -> anyhow::Result<Analysis> {
    let _ = (precheck_folder, postcheck_folder, pairs, expectations);
    todo!("port of htmlreport.analyze()")
}
