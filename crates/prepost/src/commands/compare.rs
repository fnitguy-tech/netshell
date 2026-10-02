//! `prepost compare`: the interpreted HTML report from the latest
//! precheck/postcheck pair. Port of `scripts/compare.py`.
//!
//! Needs no device access: it only reads files already captured by
//! `prepost precheck` and `prepost postcheck`. The inventory is
//! optional here and is read only for its `pairs:` list; pairs whose
//! hostnames differ only by a trailing number (SW-1 / SW-2) are
//! inferred from the captures without it. The expectations file
//! (default `reports/<TICKET>/expectations.yml` when it exists) states
//! the BGP prefix deltas the change was meant to cause, so the report
//! can say "as planned" or "unexplained" instead of hedging on every
//! delta.

use std::path::{Path, PathBuf};

use crate::expectations::load_expectations;
use crate::inventory::load_inventory;
use crate::layout;
use crate::report::build_html_report;

use super::resolve_ticket;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Change/Jira ticket number (prompted if omitted)
    #[arg(long)]
    pub ticket: Option<String>,

    /// Inventory YAML, read only for its optional pairs: list
    /// (default: inventory/devices.yml when present)
    #[arg(long)]
    pub inventory: Option<PathBuf>,

    /// Expectations YAML (default: reports/<TICKET>/expectations.yml when present)
    #[arg(long)]
    pub expectations: Option<PathBuf>,
}

/// The `pairs:` list of an inventory, or `None` when the file is
/// absent. The HTML report can be built on a machine that has no
/// inventory (only the captured evidence), so a missing file is not
/// an error here.
pub fn load_pairs(path: Option<&Path>) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let default = layout::default_inventory();
    let path = path.unwrap_or(&default);

    if !path.exists() {
        return Ok(None);
    }

    Ok(Some(load_inventory(path)?.pairs))
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let ticket = resolve_ticket(args.ticket.as_deref())?;

    let dirs = layout::ticket_dirs(&ticket);
    let run_timestamp = layout::timestamp();
    let pairs = load_pairs(args.inventory.as_deref())?.unwrap_or_default();

    let expectations_path = args.expectations.clone().unwrap_or_else(|| dirs.expectations.clone());
    let mut expected = None;

    if args.expectations.is_some() || expectations_path.exists() {
        let entries = load_expectations(&expectations_path, Some(&ticket))?;
        println!(
            "Expectations: {} ({} entries)",
            layout::display_path(&expectations_path),
            entries.len()
        );
        expected = Some(entries);
    }

    let expectations_label = layout::display_path(&expectations_path);

    build_html_report(
        &ticket,
        &dirs,
        &run_timestamp,
        Some(&pairs),
        expected.as_deref(),
        Some(&expectations_label),
    )?;

    Ok(())
}
