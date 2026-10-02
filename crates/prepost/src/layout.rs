//! On-disk layout for check output.
//!
//! Everything a maintenance window produces lands under `reports/`,
//! keyed by ticket number, so evidence for one change never mixes with
//! another:
//!
//! ```text
//! reports/
//!   <TICKET>/
//!     Precheck/precheck_<timestamp>/<hostname>.txt   (+ .zip)
//!     Postcheck/postcheck_<timestamp>/<hostname>.txt (+ .zip)
//!     Compare/compare_<timestamp>.txt / .html
//!     expectations.yml   (optional, written by hand: expected BGP deltas)
//! ```
//!
//! The Python tool anchors `reports/` to its repository root. A binary
//! has no repository, so the root is `$PREPOST_HOME` when set, else the
//! current directory.

use std::fs;
use std::path::{Path, PathBuf};

/// Where `reports/` and `inventory/` live.
pub fn root() -> PathBuf {
    match std::env::var_os("PREPOST_HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home),
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

pub fn reports_dir() -> PathBuf {
    root().join("reports")
}

/// Default inventory path: `<root>/inventory/devices.yml`.
pub fn default_inventory() -> PathBuf {
    root().join("inventory").join("devices.yml")
}

/// The per-ticket directory paths (not created).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketDirs {
    pub base: PathBuf,
    pub precheck: PathBuf,
    pub postcheck: PathBuf,
    pub compare: PathBuf,
    pub expectations: PathBuf,
}

pub fn ticket_dirs(ticket: &str) -> TicketDirs {
    ticket_dirs_under(&reports_dir(), ticket)
}

/// [`ticket_dirs`] under an explicit reports directory (tests, demo).
pub fn ticket_dirs_under(reports: &Path, ticket: &str) -> TicketDirs {
    let base = reports.join(ticket);
    TicketDirs {
        precheck: base.join("Precheck"),
        postcheck: base.join("Postcheck"),
        compare: base.join("Compare"),
        expectations: base.join("expectations.yml"),
        base,
    }
}

/// Root-relative form of a path for console output and report headers.
pub fn display_path(path: &Path) -> String {
    let shown = path.strip_prefix(root()).unwrap_or(path);
    shown.display().to_string()
}

/// One timestamp format everywhere, sortable as a plain string.
pub fn timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d_%H-%M").to_string()
}

/// Newest run folder under `parent` whose name starts with `prefix`.
/// Relies on the timestamp format sorting lexicographically.
pub fn find_latest_folder(parent: &Path, prefix: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(parent).ok()?;
    let mut folders: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    folders.sort();
    folders.pop()
}

/// Normalize a ticket the way the Python CLI does: trimmed, upper case,
/// so `reports/<TICKET>/` is the same folder however it was typed.
pub fn normalize_ticket(ticket: &str) -> String {
    ticket.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_dirs_shape() {
        let dirs = ticket_dirs_under(Path::new("/r"), "NET-1");
        assert_eq!(dirs.base, Path::new("/r/NET-1"));
        assert_eq!(dirs.precheck, Path::new("/r/NET-1/Precheck"));
        assert_eq!(dirs.postcheck, Path::new("/r/NET-1/Postcheck"));
        assert_eq!(dirs.compare, Path::new("/r/NET-1/Compare"));
        assert_eq!(dirs.expectations, Path::new("/r/NET-1/expectations.yml"));
    }

    #[test]
    fn latest_folder_sorts_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "precheck_2026-04-14_08-48",
            "precheck_2026-04-15_09-00",
            "postcheck_2026-04-16_00-00",
        ] {
            fs::create_dir(tmp.path().join(name)).unwrap();
        }
        fs::write(tmp.path().join("precheck_2026-04-17_00-00.zip"), b"").unwrap();
        let latest = find_latest_folder(tmp.path(), "precheck_").unwrap();
        assert_eq!(latest.file_name().unwrap(), "precheck_2026-04-15_09-00");
        assert!(find_latest_folder(tmp.path(), "compare_").is_none());
        assert!(find_latest_folder(&tmp.path().join("missing"), "x").is_none());
    }

    #[test]
    fn timestamp_format() {
        let stamp = timestamp();
        assert_eq!(stamp.len(), 16, "{stamp}");
        assert_eq!(&stamp[10..11], "_");
    }

    #[test]
    fn tickets_are_normalized() {
        assert_eq!(normalize_ticket("  net-123 "), "NET-123");
    }
}
