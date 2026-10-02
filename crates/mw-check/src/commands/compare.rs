//! `mw report`: the interpreted HTML report from the latest
//! precheck/postcheck pair. Port of `scripts/compare.py`.
//!
//! Needs no device access: it only reads files already captured by
//! `mw before` and `mw after`. The inventory is
//! optional here and is read only for its `pairs:` list; pairs whose
//! hostnames differ only by a trailing number (SW-1 / SW-2) are
//! inferred from the captures without it. The expectations file
//! (default `reports/<TICKET>/expectations.yml` when it exists) states
//! the BGP prefix deltas the change was meant to cause, so the report
//! can say "as planned" or "unexplained" instead of hedging on every
//! delta.

use std::path::{Path, PathBuf};

use crate::inventory::load_inventory;
use crate::layout;
use crate::report::build_html_report;

use super::resolve_ticket;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Change/Jira ticket number, e.g. NET-123 (prompted if omitted)
    #[arg(value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Inventory YAML, read only for its optional pairs: list
    /// (default: inventory/devices.yml when present)
    #[arg(short, long, value_name = "FILE")]
    pub inventory: Option<PathBuf>,

    /// Your notes on the window, as Markdown
    /// (default: reports/<TICKET>/notes.md when present). Rendered above the
    /// findings. `mw notes` starts one for you.
    #[arg(short, long, value_name = "FILE")]
    pub notes: Option<PathBuf>,
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

    let notes_path = args.notes.clone().unwrap_or_else(|| dirs.notes.clone());
    let notes_text = crate::notes::load(&notes_path);

    match notes_text.as_deref() {
        None => println!(
            "No maintenance notes at {}. Run `mw notes` to start one.",
            layout::display_path(&notes_path)
        ),
        Some(text) if crate::notes::render_html(text).is_empty() => {
            // A template nobody filled in must not pass for a finished
            // write-up, so say so rather than rendering empty headings.
            println!(
                "Notes: {} is still a blank template; leaving it out.",
                layout::display_path(&notes_path)
            );
        }
        Some(text) => {
            let open = crate::notes::open_task_count(text);
            let suffix = if open > 0 {
                format!(", {open} item(s) still open")
            } else {
                String::new()
            };
            println!("Notes: {}{suffix}", layout::display_path(&notes_path));
        }
    }

    build_html_report(&ticket, &dirs, &run_timestamp, Some(&pairs), notes_text.as_deref())?;

    Ok(())
}
