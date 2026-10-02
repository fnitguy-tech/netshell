//! `prepost demo`: the whole workflow on the bundled fictional dataset.
//! No devices, no SSH: the connector replays the captures in
//! `fixtures/NET-DEMO/`, everything else is the real code path.

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Where to write reports/ (default: $PREPOST_HOME or the current directory)
    #[arg(long)]
    pub home: Option<std::path::PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let _ = args;
    todo!("port of scripts/demo.py")
}
