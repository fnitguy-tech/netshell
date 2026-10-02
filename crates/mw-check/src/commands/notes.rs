//! `mw notes` - start the maintenance notes for a ticket.
//!
//! Writes `reports/<TICKET>/notes.md`, seeded with what the captures
//! already know - the ticket, the window times, the devices - and a heading
//! per question worth answering after a window. Fill it in with any editor;
//! `mw report` renders it above the machine findings, so the report on the
//! ticket carries your account as well as the parser's.
//!
//! Nothing here touches a device. It only reads the capture folders.
//!
//! An existing file is never overwritten: half-finished notes are more use
//! than a fresh skeleton.

use std::path::PathBuf;

use crate::layout::{self, find_latest_folder};
use crate::notes;

use super::resolve_ticket;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Change/Jira ticket number, e.g. NET-123 (prompted if omitted)
    #[arg(value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Where to write the notes (default: reports/<TICKET>/notes.md)
    #[arg(short, long, value_name = "FILE")]
    pub notes: Option<PathBuf>,
}

/// The hostnames in a capture folder, without the `.txt`.
///
/// A `<host>_FAILED.txt` is a device that could not be reached, so it is
/// not a device the notes should claim was captured.
fn captured_hostnames(folder: Option<&std::path::Path>) -> Vec<String> {
    let Some(folder) = folder else {
        return Vec::new();
    };

    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };

    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".txt")?;

            if stem.ends_with("_FAILED") {
                return None;
            }

            Some(stem.to_string())
        })
        .collect();

    names.sort();
    names
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let ticket = resolve_ticket(args.ticket.as_deref())?;
    let dirs = layout::ticket_dirs(&ticket);

    let precheck_folder = find_latest_folder(&dirs.precheck, "precheck_");
    let postcheck_folder = find_latest_folder(&dirs.postcheck, "postcheck_");
    let notes_path = args.notes.unwrap_or_else(|| dirs.notes.clone());

    let mut hostnames = captured_hostnames(postcheck_folder.as_deref());

    if hostnames.is_empty() {
        hostnames = captured_hostnames(precheck_folder.as_deref());
    }

    let label = |folder: Option<&std::path::PathBuf>| {
        folder.map_or_else(|| "not captured yet".to_string(), |path| layout::display_path(path))
    };

    let written = notes::write_template(
        &notes_path,
        &ticket,
        &label(precheck_folder.as_ref()),
        &label(postcheck_folder.as_ref()),
        &hostnames,
    )?;

    if !written {
        println!(
            "Notes already exist: {} (left as they are)",
            layout::display_path(&notes_path)
        );
        return Ok(());
    }

    println!("Notes template created: {}", layout::display_path(&notes_path));
    println!(
        "Seeded with {} device(s). Fill it in, then run `mw report`.",
        hostnames.len()
    );

    Ok(())
}
