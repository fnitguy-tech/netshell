//! `mw init` makes a folder ready for captures without a source tree.
//!
//! A downloaded binary is all a new user has, so the example inventory
//! comes out of the binary. Two behaviours matter: a second run must
//! change nothing, and a real `inventory/devices.yml` must never be
//! touched.

use std::fs;

use mw_check::commands::init;
use mw_check::inventory::{EXAMPLE_INVENTORY_TEXT, load_inventory};

#[test]
fn init_writes_the_example_and_the_folders() {
    let root = tempfile::tempdir().unwrap();
    let report = init::run_in(root.path()).unwrap();

    assert!(report.example_written);
    assert!(!report.inventory_exists);
    assert!(report.reports.is_dir());
    assert_eq!(fs::read_to_string(&report.example).unwrap(), EXAMPLE_INVENTORY_TEXT);
    // The example the binary writes is a valid inventory as it stands.
    load_inventory(&report.example).unwrap();
}

#[test]
fn a_second_run_changes_nothing() {
    let root = tempfile::tempdir().unwrap();
    init::run_in(root.path()).unwrap();
    let example = root.path().join("inventory/devices.example.yml");
    fs::write(&example, "# edited by hand\n").unwrap();

    let report = init::run_in(root.path()).unwrap();

    assert!(!report.example_written);
    assert_eq!(fs::read_to_string(&example).unwrap(), "# edited by hand\n");
}

#[test]
fn a_real_inventory_is_never_touched() {
    let root = tempfile::tempdir().unwrap();
    let inventory = root.path().join("inventory/devices.yml");
    fs::create_dir_all(inventory.parent().unwrap()).unwrap();
    fs::write(&inventory, "platforms: []\n").unwrap();

    let report = init::run_in(root.path()).unwrap();

    assert!(report.inventory_exists);
    assert_eq!(fs::read_to_string(&inventory).unwrap(), "platforms: []\n");
}

#[test]
fn a_missing_inventory_points_at_init() {
    let root = tempfile::tempdir().unwrap();
    let message = load_inventory(&root.path().join("inventory/devices.yml"))
        .unwrap_err()
        .to_string();

    assert!(message.contains("mw init"), "{message}");
    assert!(message.contains("devices.example.yml"), "{message}");
    assert!(!message.contains("mw source"), "{message}");
}
