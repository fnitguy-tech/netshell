//! `mw report`: the interpreted HTML report from the latest
//! precheck/postcheck pair. Port of `scripts/compare.py`.
//!
//! Needs no device access: it only reads files already captured by
//! `mw before` and `mw after`. The inventory is
//! optional here and is read only for its `pairs:` list; pairs whose
//! hostnames differ only by a trailing number (SW-1 / SW-2) are
//! inferred from the captures without it.
//!
//! The notes file (default `reports/<TICKET>/notes.md`) is your own
//! account of the window. Whatever you write there is rendered above the
//! machine findings, so the ticket carries both.

use std::path::{Path, PathBuf};

use crate::inventory::load_pairs;
use crate::layout::{self, TicketDirs};
use crate::notes;
use crate::report::build_html_report;

use super::resolve_ticket;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Change/Jira ticket number, e.g. NET-123 (prompted if omitted)
    #[arg(value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Inventory YAML, read only for its optional pairs: list, so a file
    /// with nothing but pairs: works
    /// (default: inventory/devices.yml when present)
    #[arg(short, long, value_name = "FILE")]
    pub inventory: Option<PathBuf>,

    /// Your notes on the window, as Markdown
    /// (default: reports/<TICKET>/notes.md when present). Rendered above the
    /// findings. `mw notes` starts one for you.
    #[arg(short, long, value_name = "FILE")]
    pub notes: Option<PathBuf>,
}

/// Read the notes file and tell the user what was found.
///
/// A file that's there but can't be read is a warning, and the report
/// is still built: the findings don't depend on the notes, and "no
/// notes" would send you looking for a file that's sitting right there.
pub fn load_notes(notes_path: &Path, dirs: &TicketDirs) -> Option<String> {
    let shown = dirs.display(notes_path);

    let notes_text = match notes::load(notes_path) {
        Ok(text) => text,
        Err(error) => {
            println!("WARNING: {error} The report is being built without your notes.");
            return None;
        }
    };

    match notes_text.as_deref() {
        None => println!("No maintenance notes at {shown}. Run `mw notes` to start one."),
        Some(text) if notes::render_html(text).is_empty() => {
            // A template nobody filled in must not pass for a finished
            // write-up, so say so rather than rendering empty headings.
            println!("Notes: {shown} is still a blank template; leaving it out.");
        }
        Some(text) => {
            let open = notes::open_task_count(text);
            let suffix = if open > 0 {
                format!(", {open} item(s) still open")
            } else {
                String::new()
            };
            println!("Notes: {shown}{suffix}");
        }
    }

    notes_text
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let ticket = resolve_ticket(args.ticket.as_deref())?;
    let root = layout::root();

    let dirs = layout::ticket_dirs_in(&root, &ticket)?;
    let run_timestamp = layout::timestamp();

    // Only the pairs: list is read, so a file that holds nothing else
    // is fine here, and so is no file at all.
    let inventory_path = args
        .inventory
        .clone()
        .unwrap_or_else(|| layout::default_inventory_in(&root));
    let pairs = load_pairs(&inventory_path)?;

    let notes_path = args.notes.clone().unwrap_or_else(|| dirs.notes.clone());
    let notes_text = load_notes(&notes_path, &dirs);

    build_html_report(&ticket, &dirs, &run_timestamp, Some(&pairs), notes_text.as_deref())?;

    Ok(())
}
