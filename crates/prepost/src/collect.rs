//! State collection over SSH: every device in parallel (five at a time)
//! with a progress bar, one capture file per device, zipped per run.
//! An unreachable device gets a `<host>_FAILED.txt` marker instead of
//! aborting the run.

use std::path::{Path, PathBuf};

use crate::inventory::{DeviceSpec, Job};

/// How many devices are collected at once.
pub const MAX_WORKERS: usize = 5;

/// Seconds to wait for one command; `show ip bgp` on a full table is slow.
pub const COMMAND_READ_TIMEOUT_SECS: u64 = 180;

/// An open session on one device. The real one wraps netshell; the
/// demo replays bundled captures.
pub trait Session: Send {
    /// The device's own hostname, so capture files are named after it
    /// and not its management IP.
    fn hostname(&mut self) -> anyhow::Result<String>;
    fn send_command(&mut self, command: &str) -> anyhow::Result<String>;
    fn disconnect(self: Box<Self>) -> anyhow::Result<()>;
}

/// Opens sessions. Swapped for a replaying stub by `prepost demo`.
pub trait Connector: Sync {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>>;
}

/// The real connector: netshell over SSH.
pub struct SshConnector;

impl Connector for SshConnector {
    fn connect(&self, device: &DeviceSpec) -> anyhow::Result<Box<dyn Session>> {
        let _ = device;
        todo!("netshell-backed session")
    }
}

/// Collect all devices for one phase ("precheck" or "postcheck") into
/// `<phase_dir>/<phase>_<run_timestamp>/` and zip it next to it.
/// Returns `(folder, zip)`.
pub fn run_collection(
    jobs: &[Job],
    phase: &str,
    phase_dir: &Path,
    run_timestamp: &str,
    redact_secrets: bool,
    connector: &dyn Connector,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let _ = (jobs, phase, phase_dir, run_timestamp, redact_secrets, connector);
    todo!("port of collect.run_collection()")
}
