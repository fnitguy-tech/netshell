//! `prepost precheck`: capture pre-change device state.
//!
//! Run this BEFORE the maintenance window starts. Collects every
//! command in the inventory from every device in parallel and zips the
//! evidence under `reports/<TICKET>/Precheck/`.

use std::fs;

use anyhow::Context;

use super::CaptureArgs;
use crate::collect::{SshConnector, run_collection};
use crate::inventory::{build_jobs, load_inventory, prompt_credentials};
use crate::layout;

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

    fs::create_dir_all(&dirs.precheck).with_context(|| format!("could not create {}", dirs.precheck.display()))?;

    let (_folder, zip_name) = run_collection(
        &jobs,
        "precheck",
        &dirs.precheck,
        &run_timestamp,
        args.capture.redact,
        &SshConnector,
    )?;

    println!();
    println!("SUCCESS");
    println!("Precheck ZIP created: {}", layout::display_path(&zip_name));

    Ok(())
}
