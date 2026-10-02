//! Port of the Python `tests/test_inventory.py`.

use std::fs;
use std::path::{Path, PathBuf};

use prepost::inventory::{Inventory, InventoryError, build_jobs, load_inventory, load_pairs};

fn example_inventory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/devices.example.yml")
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn example_inventory_loads() {
    let inventory: Inventory = load_inventory(&example_inventory()).unwrap();
    let platforms = &inventory.platforms;

    assert_eq!(
        platforms.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        ["arista", "paloalto"]
    );
    assert_eq!(platforms[0].device_type, "arista_eos");
    assert!(platforms[0].commands.iter().any(|c| c == "show running-config"));
    assert!(platforms[1].commands.iter().any(|c| c == "show config running"));
    assert_eq!(platforms[0].hosts, ["192.0.2.11", "192.0.2.12", "192.0.2.13"]);
    assert!(inventory.pairs.is_empty());
}

#[test]
fn build_jobs_one_per_host() {
    let inventory = load_inventory(&example_inventory()).unwrap();
    let jobs = build_jobs(&inventory, "admin", "secret");

    let total_hosts: usize = inventory.platforms.iter().map(|p| p.hosts.len()).sum();
    assert_eq!(jobs.len(), total_hosts);

    let first = &jobs[0];
    assert_eq!(first.device.username, "admin");
    assert_eq!(first.device.password, "secret");
    assert_eq!(first.device.device_type, "arista_eos");
    assert_eq!(first.device.host, "192.0.2.11");
    assert_eq!(first.commands, inventory.platforms[0].commands);

    let last = jobs.last().unwrap();
    assert_eq!(last.device.device_type, "paloalto_panos");
    assert_eq!(last.device.host, "192.0.2.22");
}

#[test]
fn missing_inventory_points_at_example() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope.yml");

    let error: InventoryError = load_inventory(&missing).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("devices.example.yml"), "{message}");
    assert!(
        message.starts_with(&format!("Inventory not found: {}", missing.display())),
        "{message}"
    );
}

#[test]
fn malformed_inventory_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = write(
        tmp.path(),
        "bad.yml",
        "platforms:\n  - name: arista\n    hosts: [192.0.2.1]\n",
    );

    let error = load_inventory(&bad).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("{}: platform 'arista' is missing 'device_type'.", bad.display())
    );
}

#[test]
fn validation_messages_match_the_python() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let no_list = write(dir, "no_list.yml", "platforms: {a: b}\n");
    assert_eq!(
        load_inventory(&no_list).unwrap_err().to_string(),
        format!("{}: expected a top-level 'platforms' list.", no_list.display())
    );

    let empty = write(dir, "empty.yml", "");
    assert_eq!(
        load_inventory(&empty).unwrap_err().to_string(),
        format!("{}: expected a top-level 'platforms' list.", empty.display())
    );

    let unnamed = write(dir, "unnamed.yml", "platforms:\n  - device_type: arista_eos\n");
    assert_eq!(
        load_inventory(&unnamed).unwrap_err().to_string(),
        format!("{}: platform 'platforms[0]' is missing 'name'.", unnamed.display())
    );

    let empty_hosts = write(
        dir,
        "empty_hosts.yml",
        "platforms:\n  - name: arista\n    device_type: arista_eos\n    hosts: []\n    commands: [show version]\n",
    );
    assert_eq!(
        load_inventory(&empty_hosts).unwrap_err().to_string(),
        format!("{}: platform 'arista' is missing 'hosts'.", empty_hosts.display())
    );

    let not_lists = write(
        dir,
        "not_lists.yml",
        "platforms:\n  - name: arista\n    device_type: arista_eos\n    hosts: 192.0.2.1\n    commands: [show version]\n",
    );
    assert_eq!(
        load_inventory(&not_lists).unwrap_err().to_string(),
        format!(
            "{}: platform 'arista': 'hosts' and 'commands' must be lists.",
            not_lists.display()
        )
    );
}

#[test]
fn load_pairs_is_optional() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load_pairs(&tmp.path().join("missing.yml")).unwrap(), Vec::new());

    let plain = write(
        tmp.path(),
        "plain.yml",
        "platforms:\n  - name: arista\n    device_type: arista_eos\n    hosts: [a]\n    commands: [show version]\n",
    );
    assert_eq!(load_pairs(&plain).unwrap(), Vec::new());
    assert_eq!(load_inventory(&plain).unwrap().pairs, Vec::new());
}

#[test]
fn load_pairs_reads_and_validates() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    let good = write(
        dir,
        "good.yml",
        "pairs:\n  - [CORE-EAST, CORE-WEST]\n  - [FW-A, FW-B]\n",
    );
    assert_eq!(
        load_pairs(&good).unwrap(),
        vec![
            ("CORE-EAST".to_string(), "CORE-WEST".to_string()),
            ("FW-A".to_string(), "FW-B".to_string()),
        ]
    );

    let bad = write(dir, "bad.yml", "pairs:\n  - [ONLY-ONE]\n");
    assert_eq!(
        load_pairs(&bad).unwrap_err().to_string(),
        format!(
            "{}: each entry in 'pairs' must be a list of exactly two hostnames, got ['ONLY-ONE'].",
            bad.display()
        )
    );

    // load_inventory applies the same check so a typo fails before collection.
    let bad_inventory = write(
        dir,
        "bad_inventory.yml",
        "pairs: CORE-EAST\nplatforms:\n  - name: arista\n    device_type: arista_eos\n    hosts: [a]\n    commands: [show version]\n",
    );
    assert_eq!(
        load_inventory(&bad_inventory).unwrap_err().to_string(),
        format!(
            "{}: 'pairs' must be a list of two-hostname lists.",
            bad_inventory.display()
        )
    );

    let good_inventory = write(
        dir,
        "good_inventory.yml",
        "pairs:\n  - [FW-A, FW-B]\nplatforms:\n  - name: arista\n    device_type: arista_eos\n    hosts: [a]\n    commands: [show version]\n",
    );
    assert_eq!(
        load_inventory(&good_inventory).unwrap().pairs,
        vec![("FW-A".to_string(), "FW-B".to_string())]
    );

    let not_mapping = write(dir, "list.yml", "- a\n- b\n");
    assert_eq!(
        load_pairs(&not_mapping).unwrap_err().to_string(),
        format!("{}: expected a YAML mapping.", not_mapping.display())
    );
}
