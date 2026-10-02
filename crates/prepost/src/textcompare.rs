//! Quick plain-text pre/post comparison: the fast on-call view written
//! at the end of a postcheck run. One `.txt` diffing the latest
//! precheck against the latest postcheck, command by command, with
//! expected churn filtered out. Port of the Python `textcompare.py`.

use std::path::PathBuf;

use crate::layout::TicketDirs;

/// Commands captured for evidence but too volatile to ever diff.
pub const SKIP_COMPARE_COMMANDS: &[&str] = &["show interfaces transceiver"];

/// Normalize one line for the text diff, or `None` to drop it.
pub fn normalize_line(command: &str, line: &str) -> Option<String> {
    let _ = (command, line);
    todo!("port of textcompare.normalize_line()")
}

/// Write `Compare/compare_<run_timestamp>.txt` from the latest
/// precheck and postcheck folders, printing progress and the summary.
/// Returns the report path, or `None` when a run folder is missing.
pub fn write_compare_report(ticket: &str, dirs: &TicketDirs, run_timestamp: &str) -> anyhow::Result<Option<PathBuf>> {
    let _ = (ticket, dirs, run_timestamp);
    todo!("port of textcompare.write_compare_report()")
}
