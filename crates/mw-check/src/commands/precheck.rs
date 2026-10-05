//! `mw before`: capture pre-change device state.
//!
//! Run this BEFORE the maintenance window starts. Collects every
//! command in the inventory from every device in parallel and zips the
//! evidence under `reports/<TICKET>/Precheck/`.
//!
//! Exit code: 0 when every device was captured, 1 when some weren't, 2
//! when none were. The last lines printed say which, for example:
//!
//! ```text
//! 7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
//! ```

use std::fs;

use anyhow::Context;

use super::CaptureArgs;
use crate::collect::{report_run, run_collection};
use crate::inventory::{build_jobs, load_inventory, prompt_credentials};
use crate::layout;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    #[command(flatten)]
    pub capture: CaptureArgs,
}

/// Returns the exit code to leave with.
pub fn run(args: Args) -> anyhow::Result<u8> {
    let ticket = super::resolve_ticket(args.capture.ticket.as_deref())?;
    let root = layout::root();

    let inventory_path = args
        .capture
        .inventory
        .clone()
        .unwrap_or_else(|| layout::default_inventory_in(&root));
    let inventory = load_inventory(&inventory_path)?;
    let (username, password) = prompt_credentials(args.capture.username.as_deref())?;
    let jobs = build_jobs(&inventory, &username, &password);
    let connector = args.capture.connector()?;

    let dirs = layout::ticket_dirs_in(&root, &ticket)?;
    let run_timestamp = layout::timestamp();

    fs::create_dir_all(&dirs.precheck).with_context(|| format!("could not create {}", dirs.precheck.display()))?;

    let result = run_collection(
        &jobs,
        "precheck",
        &dirs.precheck,
        &run_timestamp,
        args.capture.redact,
        &connector,
    )?;

    Ok(report_run(&result, "precheck", &dirs.display(&result.zip)))
}
