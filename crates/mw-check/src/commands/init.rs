//! `mw init` - make a folder ready for captures.
//!
//! A downloaded `mw.exe` has no source tree around it, so the example
//! inventory has to come out of the binary. This writes it to
//! `inventory/devices.example.yml` under the working root, makes
//! `reports/`, and says what to do next.
//!
//! Idempotent: a second run changes nothing. An existing
//! `inventory/devices.yml` is never touched, and an example file that
//! someone has edited is left as it is.

use std::path::{Path, PathBuf};

use crate::inventory::EXAMPLE_INVENTORY_TEXT;
use crate::layout;

#[derive(Clone, Debug, clap::Args)]
pub struct Args {
    /// Folder to prepare (default: $MW_HOME or the current directory)
    #[arg(short = 'H', long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

/// What `init` found and did, for the console and for tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub root: PathBuf,
    pub example: PathBuf,
    pub inventory: PathBuf,
    pub reports: PathBuf,
    /// The example was written on this run (false: it was already there).
    pub example_written: bool,
    /// `inventory/devices.yml` already exists, so there is nothing to copy.
    pub inventory_exists: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let root = args.home.clone().unwrap_or_else(layout::root);
    let report = run_in(&root)?;
    let shown = |path: &Path| {
        path.strip_prefix(&report.root)
            .map(|rel| rel.display().to_string())
            .unwrap_or_else(|_| path.display().to_string())
    };

    println!("Working folder: {}", report.root.display());
    if report.example_written {
        println!("Wrote {}", shown(&report.example));
    } else {
        println!("{} is already there (left as it is)", shown(&report.example));
    }
    println!("Reports will go under {}", shown(&report.reports));

    if report.inventory_exists {
        println!(
            "{} already exists (left as it is). You're ready: mw before <TICKET> -r",
            shown(&report.inventory)
        );
    } else {
        println!(
            "Next: copy {} to {} and put your devices in it. Then: mw before <TICKET> -r",
            shown(&report.example),
            shown(&report.inventory)
        );
    }
    println!("To run mw from any folder, set MW_HOME to {}", report.root.display());

    Ok(())
}

/// `init` under an explicit root. Nothing here reads the environment.
pub fn run_in(root: &Path) -> anyhow::Result<Report> {
    let inventory_dir = root.join("inventory");
    let reports = root.join("reports");
    std::fs::create_dir_all(&inventory_dir)?;
    std::fs::create_dir_all(&reports)?;

    let example = inventory_dir.join("devices.example.yml");
    let example_written = if example.exists() {
        false
    } else {
        std::fs::write(&example, EXAMPLE_INVENTORY_TEXT)?;
        true
    };

    let inventory = layout::default_inventory_in(root);

    Ok(Report {
        root: root.to_path_buf(),
        inventory_exists: inventory.exists(),
        example,
        inventory,
        reports,
        example_written,
    })
}
