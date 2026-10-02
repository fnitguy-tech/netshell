//! `prepost postcheck`.

use super::CaptureArgs;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    #[command(flatten)]
    pub capture: CaptureArgs,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let _ = args;
    todo!("port of scripts/postcheck.py")
}
