//! The interpreted HTML report: one self-contained file with the
//! health verdict, outcome summary, attention items, pair symmetry,
//! charts (Chart.js from a CDN is the only external asset), per-device
//! findings and every raw diff behind a collapsible section.

use std::path::{Path, PathBuf};

use crate::analysis::Analysis;
use crate::expectations::Expectation;
use crate::layout::TicketDirs;

/// Render the analysis into a single HTML page.
pub fn render_html(
    ticket: &str,
    precheck_folder: &Path,
    postcheck_folder: &Path,
    analysis: &Analysis,
    expectations_label: Option<&str>,
) -> String {
    let _ = (ticket, precheck_folder, postcheck_folder, analysis, expectations_label);
    todo!("port of htmlreport.render_html()")
}

/// Analyze the latest precheck/postcheck pair and write
/// `Compare/compare_<run_timestamp>.html`, printing the summary.
/// Returns the report path, or `None` when a run folder is missing.
pub fn build_html_report(
    ticket: &str,
    dirs: &TicketDirs,
    run_timestamp: &str,
    pairs: Option<&[(String, String)]>,
    expectations: Option<&[Expectation]>,
    expectations_label: Option<&str>,
) -> anyhow::Result<Option<PathBuf>> {
    let _ = (ticket, dirs, run_timestamp, pairs, expectations, expectations_label);
    todo!("port of htmlreport.build_html_report()")
}
