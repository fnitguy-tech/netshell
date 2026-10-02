//! Device inventory loading.
//!
//! `inventory/devices.yml` groups devices by platform; each platform
//! carries the netmiko `device_type` and the command list captured for
//! it. An optional top-level `pairs:` list names redundant pairs
//! explicitly (otherwise they are inferred from hostnames).

use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    pub name: String,
    pub device_type: String,
    pub hosts: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    pub platforms: Vec<Platform>,
    pub pairs: Vec<(String, String)>,
}

/// One device to reach, with credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSpec {
    pub device_type: String,
    pub host: String,
    pub username: String,
    pub password: String,
}

/// One collection job: a device and the commands to run on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub device: DeviceSpec,
    pub commands: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InventoryError(pub String);

/// Parse and validate the inventory.
pub fn load_inventory(path: &Path) -> Result<Inventory, InventoryError> {
    let _ = path;
    todo!("port of inventory.load_inventory()")
}

/// Flatten platforms into one job per device.
pub fn build_jobs(inventory: &Inventory, username: &str, password: &str) -> Vec<Job> {
    let _ = (inventory, username, password);
    todo!("port of inventory.build_jobs()")
}

/// Ask for SSH credentials; the password is never echoed or stored.
pub fn prompt_credentials(username: Option<&str>) -> anyhow::Result<(String, String)> {
    let _ = username;
    todo!("port of inventory.prompt_credentials()")
}
