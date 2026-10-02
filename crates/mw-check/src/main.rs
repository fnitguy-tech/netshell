//! One binary, four short subcommands:
//!
//! ```text
//! mw before NET-123 [-u USER] [-i FILE] [-r]     capture before the change
//! mw after  NET-123 [-u USER] [-i FILE] [-r]     capture after the change
//! mw report NET-123 [-i FILE] [-e FILE]          the interpreted HTML report
//! mw demo   [-H DIR]                             the whole workflow, no devices
//! ```
//!
//! mw is short for maintenance window. The Python tool's names
//! (`precheck`, `postcheck`, `compare`) still work as aliases. Anything not given is prompted for; the SSH password is
//! always prompted, never a flag.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mw_check::commands::{compare, demo, postcheck, precheck};

#[derive(Parser)]
#[command(
    name = "mw",
    version,
    about = "Maintenance window check: capture device state before and after a change, report what changed",
    after_help = "Example:\n  mw before NET-123 -r    capture before the change, secrets stripped\n  mw after NET-123 -r     capture after, quick text diff\n  mw report NET-123       interpreted HTML report"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture device state before the change (reports/<TICKET>/Precheck/)
    #[command(aliases = ["pre", "precheck"])]
    Before(precheck::Args),
    /// Capture device state after the change and write the quick text diff
    #[command(aliases = ["post", "postcheck"])]
    After(postcheck::Args),
    /// Build the interpreted HTML report from the latest pre/post captures
    #[command(aliases = ["compare", "diff"])]
    Report(compare::Args),
    /// Run the whole workflow on the bundled fictional dataset, no devices
    Demo(demo::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Before(args) => precheck::run(args),
        Command::After(args) => postcheck::run(args),
        Command::Report(args) => compare::run(args),
        Command::Demo(args) => demo::run(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mw: {error:#}");
            ExitCode::FAILURE
        }
    }
}
