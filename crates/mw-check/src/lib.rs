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
//! | `redact`        | `-r`: strips passwords, hashes and keys from captures        |
//! | `capture`       | the capture file format; failed, missing, and stale captures |
//! | `textcompare`   | normalization rules + the quick .txt diff report            |
//! | `difflib`       | port of Python's ndiff, so every diff orders lines the same |
//! | `analysis`      | parsers, findings, pair symmetry, impact scoring            |
//! | `notes`         | your write-up of the window, rendered into the report       |
//! | `report`        | the self-contained HTML report                              |
//! | `layout`        | `reports/<TICKET>/` directory conventions, safe file names  |
//! | `hostkeys`      | which known-hosts file and host-key policy netshell is given |
//! | `vpn`           | IPsec/IKE/LSVPN churn rule shared by both compare views     |
//!
//! Capture files written by this crate and by the Python tool are
//! interchangeable: either side's captures can be compared by the other.

pub mod analysis;
pub mod capture;
pub mod collect;
pub mod commands;
pub mod difflib;
pub mod hostkeys;
pub mod inventory;
pub mod layout;
pub mod notes;
pub mod redact;
pub mod report;
pub mod textcompare;
pub mod vpn;
