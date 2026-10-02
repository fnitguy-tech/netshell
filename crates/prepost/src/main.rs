//! One binary, four short subcommands:
//!
//! ```text
//! prepost pre    [TICKET] [-u USER] [-i FILE] [-r]     before the change
//! prepost post   [TICKET] [-u USER] [-i FILE] [-r]     after the change
//! prepost report [TICKET] [-i FILE] [-e FILE]          the HTML report
//! prepost demo   [-H DIR]                              no devices needed
//! ```
//!
//! The long names (`precheck`, `postcheck`, `compare`) still work as
//! aliases. Anything not given is prompted for; the SSH password is
//! always prompted, never a flag.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use prepost::commands::{compare, demo, postcheck, precheck};

#[derive(Parser)]
#[command(
    name = "prepost",
    version,
    about = "Pre/post change validation for network maintenance windows",
    after_help = "Example:\n  prepost pre NET-123 -r      capture before the change, secrets stripped\n  prepost post NET-123 -r     capture after, quick text diff\n  prepost report NET-123      interpreted HTML report"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture device state before the change (reports/<TICKET>/Precheck/)
    #[command(alias = "precheck")]
    Pre(precheck::Args),
    /// Capture device state after the change and write the quick text diff
    #[command(alias = "postcheck")]
    Post(postcheck::Args),
    /// Build the interpreted HTML report from the latest pre/post captures
    #[command(aliases = ["compare", "diff"])]
    Report(compare::Args),
    /// Run the whole workflow on the bundled fictional dataset, no devices
    Demo(demo::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Pre(args) => precheck::run(args),
        Command::Post(args) => postcheck::run(args),
        Command::Report(args) => compare::run(args),
        Command::Demo(args) => demo::run(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("prepost: {error:#}");
            ExitCode::FAILURE
        }
    }
}
