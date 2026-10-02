//! Pre/post change validation for network maintenance windows.
//!
//! A port of the Python `prepost-check` tool. Captures device state over
//! SSH before a change and again after, diffs the two command by
//! command with expected churn stripped, and turns the difference into
//! evidence: a quick text diff for the on-call view and an interpreted
//! HTML report with impact-rated findings.
//!
//! Module map (mirrors the Python package):
//!
//! | module          | role                                                        |
//! |-----------------|-------------------------------------------------------------|
//! | `inventory`     | loads + validates `inventory/devices.yml` (platforms, pairs) |
//! | `collect`       | parallel SSH capture via netshell, zip packaging            |
//! | `redact`        | `--redact-secrets`: strips passwords/hashes/keys            |
//! | `capture`       | the `### command ###` capture file format                   |
//! | `textcompare`   | normalization rules + the quick .txt diff report            |
//! | `analysis`      | parsers, findings, pair symmetry, impact scoring            |
//! | `expectations`  | expected BGP prefix deltas for one change                   |
//! | `report`        | the self-contained HTML report                              |
//! | `layout`        | `reports/<TICKET>/` directory conventions                   |
//! | `vpn`           | IPsec/IKE/LSVPN churn rule shared by both compare views     |
//!
//! Capture files written by this crate and by the Python tool are
//! interchangeable: either side's captures can be compared by the other.

pub mod analysis;
pub mod capture;
pub mod collect;
pub mod commands;
pub mod expectations;
pub mod inventory;
pub mod layout;
pub mod redact;
pub mod report;
pub mod textcompare;
pub mod vpn;
