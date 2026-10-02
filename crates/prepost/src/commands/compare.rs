//! `prepost compare`: the interpreted HTML report from the latest
//! precheck/postcheck pair.

use std::path::PathBuf;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Change/Jira ticket number (prompted if omitted)
    #[arg(long)]
    pub ticket: Option<String>,

    /// Inventory YAML, read only for its optional pairs: list
    /// (default: inventory/devices.yml when present)
    #[arg(long)]
    pub inventory: Option<PathBuf>,

    /// Expectations YAML (default: reports/<TICKET>/expectations.yml when present)
    #[arg(long)]
    pub expectations: Option<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let _ = args;
    todo!("port of scripts/compare.py")
}
