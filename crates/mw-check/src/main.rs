//! One binary, short subcommands:
//!
//! ```text
//! mw init   [-H DIR]                             make a folder ready: inventory/ + reports/
//! mw before NET-123 [-u USER] [-i FILE] [-r]     capture before the change
//! mw after  NET-123 [-u USER] [-i FILE] [-r]     capture after the change
//!           (both: --known-hosts FILE, --accept-new-host-key HOST,
//!            --insecure-accept-any-host-key, --legacy-algorithms,
//!            --enable, --user-mode)
//! mw report NET-123 [-i FILE] [-e FILE]          the interpreted HTML report
//! mw demo   [-H DIR]                             the whole workflow, no devices
//! ```
//!
//! mw is short for maintenance window. The Python tool's names
//! (`precheck`, `postcheck`, `compare`) still work as aliases. Anything
//! not given is prompted for; the SSH password and the enable secret
//! are always prompted, never a flag.
//!
//! `mw before` and `mw after` exit 0 when every device was captured, 1
//! when some weren't, and 2 when none were. A ticket that can't name a
//! folder exits 2 as well, like any other usage error.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mw_check::commands::{compare, demo, init, notes, postcheck, precheck};
use mw_check::layout::TicketError;

#[derive(Parser)]
#[command(
    name = "mw",
    version,
    about = "Maintenance window check: capture device state before and after a change, report what changed",
    after_help = "Example:\n  mw init                 make this folder ready (example inventory, reports/)\n  mw before NET-123 -r    capture before the change, secrets stripped\n  mw after NET-123 -r     capture after, quick text diff\n  mw report NET-123       interpreted HTML report"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make this folder ready for captures: inventory/devices.example.yml and reports/
    Init(init::Args),
    /// Capture device state before the change (reports/<TICKET>/Precheck/)
    #[command(aliases = ["pre", "precheck"])]
    Before(precheck::Args),
    /// Capture device state after the change and write the quick text diff
    #[command(aliases = ["post", "postcheck"])]
    After(postcheck::Args),
    /// Build the interpreted HTML report from the latest pre/post captures
    #[command(aliases = ["compare", "diff"])]
    Report(compare::Args),
    /// Start the maintenance notes for a ticket (reports/<TICKET>/notes.md)
    Notes(notes::Args),
    /// Run the whole workflow on the bundled fictional dataset, no devices
    Demo(demo::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // A capture leaves with 0, 1, or 2: all, some, or none of the
    // devices captured. The other commands leave with 0.
    let result = match cli.command {
        Command::Init(args) => init::run(args).map(|()| 0),
        Command::Before(args) => precheck::run(args),
        Command::After(args) => postcheck::run(args),
        Command::Report(args) => compare::run(args).map(|()| 0),
        Command::Notes(args) => notes::run(args).map(|()| 0),
        Command::Demo(args) => demo::run(args).map(|()| 0),
    };

    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("mw: {error:#}");
            // A ticket that can't name a folder is a usage error, like a
            // flag mw doesn't know: exit 2, as the Python tool does.
            if error.downcast_ref::<TicketError>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
