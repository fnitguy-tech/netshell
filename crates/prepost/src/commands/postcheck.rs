//! `prepost postcheck`: capture post-change state and diff it against
//! the precheck.
//!
//! Run this AFTER the change is complete. Collects the same evidence as
//! the precheck, zips it under `reports/<TICKET>/Postcheck/`, then
//! immediately writes a plain-text comparison against the latest
//! precheck so you know before leaving the window whether anything
//! unexpected changed. Run `prepost compare` afterwards for the full
//! HTML report.

use std::fs;

use anyhow::Context;

use super::CaptureArgs;
use crate::collect::{SshConnector, run_collection};
use crate::inventory::{build_jobs, load_inventory, prompt_credentials};
use crate::{layout, textcompare};

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    #[command(flatten)]
    pub capture: CaptureArgs,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let ticket = super::resolve_ticket(args.capture.ticket.as_deref())?;

    let inventory_path = args.capture.inventory.clone().unwrap_or_else(layout::default_inventory);
    let inventory = load_inventory(&inventory_path)?;
    let (username, password) = prompt_credentials(args.capture.username.as_deref())?;
    let jobs = build_jobs(&inventory, &username, &password);

    let dirs = layout::ticket_dirs(&ticket);
    let run_timestamp = layout::timestamp();

    fs::create_dir_all(&dirs.postcheck).with_context(|| format!("could not create {}", dirs.postcheck.display()))?;

    let (_folder, zip_name) = run_collection(
        &jobs,
        "postcheck",
        &dirs.postcheck,
        &run_timestamp,
        args.capture.redact,
        &SshConnector,
    )?;

    textcompare::write_compare_report(&ticket, &dirs, &run_timestamp)?;

    println!();
    println!("SUCCESS");
    println!("Postcheck ZIP created: {}", layout::display_path(&zip_name));

    Ok(())
}
