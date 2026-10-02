//! Expected BGP prefix deltas for one change.
//!
//! File: `reports/<TICKET>/expectations.yml` by default, or
//! `--expectations` on `prepost compare`. Schema:
//!
//! ```yaml
//! ticket: NET-123                 # optional; must match when present
//! expectations:
//!   - device: SITE-A-SW-2         # capture hostname, case-insensitive
//!     peer: 10.0.0.1              # neighbor IP or description column
//!     expected_delta: +3          # change in prefixes received, or
//!   - device: SITE-A-SW-1
//!     peer: ISP-B
//!     expected_prefixes: 815      # absolute prefixes received after
//!     note: full table minus bogons   # optional, shown in the finding
//! ```

use std::path::Path;

use crate::analysis::BgpPeer;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    /// Change in prefixes received.
    Delta(i64),
    /// Absolute prefixes received after the change.
    Prefixes(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    pub device: String,
    pub peer: String,
    pub expected: Expected,
    pub note: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ExpectationsError(pub String);

/// Parse and validate an expectations file.
pub fn load_expectations(path: &Path, ticket: Option<&str>) -> Result<Vec<Expectation>, ExpectationsError> {
    let _ = (path, ticket);
    todo!("port of expectations.load_expectations()")
}

/// The entries for one capture hostname (case-insensitive).
pub fn for_device<'a>(expectations: &'a [Expectation], hostname: &str) -> Vec<&'a Expectation> {
    expectations
        .iter()
        .filter(|e| e.device.eq_ignore_ascii_case(hostname))
        .collect()
}

/// The first entry naming this peer by description or IP.
pub fn match_peer<'a>(expectations: &'a [Expectation], peer: &BgpPeer) -> Option<&'a Expectation> {
    expectations
        .iter()
        .find(|e| e.peer.eq_ignore_ascii_case(&peer.name) || e.peer.eq_ignore_ascii_case(&peer.ip))
}

/// Human form of what an entry expects: "a change of +3" or "815 prefixes received".
pub fn describe(entry: &Expectation) -> String {
    match entry.expected {
        Expected::Delta(delta) => format!("a change of {delta:+}"),
        Expected::Prefixes(total) => format!("{total} prefixes received"),
    }
}
