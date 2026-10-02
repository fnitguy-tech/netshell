//! One binary, four subcommands, the same shape as the Python scripts:
//!
//! ```text
//! prepost precheck  [--ticket T] [--username U] [--inventory F] [--redact-secrets]
//! prepost postcheck [--ticket T] [--username U] [--inventory F] [--redact-secrets]
//! prepost compare   [--ticket T] [--inventory F] [--expectations F]
//! prepost demo
//! ```
//!
//! Every prompt-able value can be given as a flag; the SSH password is
//! always prompted, never a flag.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use prepost::commands::{compare, demo, postcheck, precheck};

#[derive(Parser)]
#[command(
    name = "prepost",
    version,
    about = "Pre/post change validation for network maintenance windows"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture pre-change device state into reports/<TICKET>/Precheck/
    Precheck(precheck::Args),
    /// Capture post-change state and write the quick text diff
    Postcheck(postcheck::Args),
    /// Build the interpreted HTML report from the latest pre/post captures
    Compare(compare::Args),
    /// Run the whole workflow on the bundled fictional dataset, no devices
    Demo(demo::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Precheck(args) => precheck::run(args),
        Command::Postcheck(args) => postcheck::run(args),
        Command::Compare(args) => compare::run(args),
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
