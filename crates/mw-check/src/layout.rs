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
//!     notes.md           (optional: the engineer's account of the window)
//! ```
//!
//! The Python tool anchors `reports/` to its repository root. A binary
//! has no repository, so the root is `$MW_HOME` when set, else the
//! current directory.

use std::fs;
use std::path::{Path, PathBuf};

/// The longest device or ticket name we'll put on disk. Windows caps a
/// whole path near 260 characters, and
/// `reports/<TICKET>/Precheck/precheck_<stamp>/<name>_<host>_FAILED.txt`
/// has to fit inside that.
pub const MAX_NAME_LENGTH: usize = 64;

/// Names Windows reserves in every folder, with or without an
/// extension. `NUL.txt` can't be created there, so a device called NUL
/// needs a nudge.
fn is_windows_reserved(stem: &str) -> bool {
    let upper = stem.to_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    ["COM", "LPT"].iter().any(|port| {
        upper
            .strip_prefix(port)
            .is_some_and(|rest| matches!(rest, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
    })
}

/// [`safe_name`] without the fallback: may come back empty.
fn clean_name(value: &str) -> String {
    let replaced: String = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect();

    // A leading dot hides the file on Linux and macOS, and "." / ".."
    // are folders. Windows drops a trailing dot without telling you.
    // Every character is ASCII by now, so cutting at a byte is safe.
    let trimmed = replaced.trim_start_matches('.');
    let capped = &trimmed[..trimmed.len().min(MAX_NAME_LENGTH)];
    let mut name = capped.trim_end_matches('.').to_string();

    if is_windows_reserved(name.split('.').next().unwrap_or("")) {
        name.insert(0, '_');
        name.truncate(MAX_NAME_LENGTH);
    }

    name
}

/// Turn any text into a file name that's safe on Linux, macOS, and
/// Windows.
///
/// You get back only letters, digits, dot, underscore, and hyphen. It's
/// never empty, never starts with a dot, and is never longer than
/// [`MAX_NAME_LENGTH`]. That matters because the text comes from the
/// device itself: a hostname of `../../x` must not write outside the
/// run folder.
///
/// ```
/// use mw_check::layout::safe_name;
///
/// assert_eq!(safe_name("SITE-A-SW-1", "device"), "SITE-A-SW-1"); // already safe
/// assert_eq!(safe_name("../../x", "device"), "_.._x");
/// assert_eq!(safe_name("2001:db8::1", "device"), "2001_db8__1"); // ":" isn't allowed on Windows
/// assert_eq!(safe_name("", "192.0.2.1"), "192.0.2.1"); // the fallback, cleaned the same way
/// ```
pub fn safe_name(value: &str, fallback: &str) -> String {
    let name = clean_name(value);
    if !name.is_empty() {
        return name;
    }
    let name = clean_name(fallback);
    if !name.is_empty() {
        return name;
    }
    "device".to_string()
}

/// A ticket ID that can't be used as a folder name.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct TicketError(pub String);

/// Python's `repr()` of a string, for messages shared with the Python tool.
fn python_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == quote => {
                out.push('\\');
                out.push(ch);
            }
            ch => out.push(ch),
        }
    }
    out.push(quote);
    out
}

/// The ticket ID, or a [`TicketError`] if it can't name a folder.
///
/// The ticket becomes `reports/<TICKET>/`, so it has to be a plain
/// name. A bad one is refused, not quietly changed: you'd go looking
/// for `reports/NET-123/` and never find the folder mw made up.
///
/// ```
/// use mw_check::layout::check_ticket;
///
/// assert_eq!(check_ticket("NET-123").unwrap(), "NET-123");
/// assert!(check_ticket("../..").is_err()); // it would write outside reports/
/// assert!(check_ticket("").is_err());
/// ```
pub fn check_ticket(ticket: &str) -> Result<String, TicketError> {
    let ticket = ticket.trim();

    if ticket.is_empty() || ticket != clean_name(ticket) {
        return Err(TicketError(format!(
            "Ticket {} can't be used as a folder name. Use 1 to {MAX_NAME_LENGTH} letters, digits, dots, \
             underscores, or hyphens, starting with a letter or digit. Example: NET-123.",
            python_repr(ticket)
        )));
    }

    Ok(ticket.to_string())
}

/// Where `reports/` and `inventory/` live: `$MW_HOME` when set, else
/// the current directory. Read once per command and passed down, so
/// nothing deeper in the crate depends on the environment.
pub fn root() -> PathBuf {
    match std::env::var_os("MW_HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home),
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

/// Default inventory path: `<root>/inventory/devices.yml`.
pub fn default_inventory() -> PathBuf {
    default_inventory_in(&root())
}

/// [`default_inventory`] under an explicit root.
pub fn default_inventory_in(root: &Path) -> PathBuf {
    root.join("inventory").join("devices.yml")
}

/// The per-ticket directory paths (not created), and the root that
/// console output and report headers show them relative to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketDirs {
    pub root: PathBuf,
    pub base: PathBuf,
    pub precheck: PathBuf,
    pub postcheck: PathBuf,
    pub compare: PathBuf,
    pub notes: PathBuf,
}

impl TicketDirs {
    /// Root-relative form of a path, for console output and report headers.
    pub fn display(&self, path: &Path) -> String {
        display_path_from(&self.root, path)
    }
}

/// The directories for a ticket under [`root`]. A ticket that can't
/// name a folder is refused (see [`check_ticket`]).
pub fn ticket_dirs(ticket: &str) -> Result<TicketDirs, TicketError> {
    ticket_dirs_in(&root(), ticket)
}

/// [`ticket_dirs`] under an explicit root: `<root>/reports/<TICKET>/`.
pub fn ticket_dirs_in(root: &Path, ticket: &str) -> Result<TicketDirs, TicketError> {
    let ticket = check_ticket(ticket)?;
    let base = root.join("reports").join(ticket);
    Ok(TicketDirs {
        root: root.to_path_buf(),
        precheck: base.join("Precheck"),
        postcheck: base.join("Postcheck"),
        compare: base.join("Compare"),
        notes: base.join("notes.md"),
        base,
    })
}

/// Path of `path` relative to `root`, for console output and report
/// headers. Always forward slashes, so reports read the same on every
/// platform. A path outside `root` is shown whole.
pub fn display_path_from(root: &Path, path: &Path) -> String {
    let shown = path.strip_prefix(root).unwrap_or(path);
    shown.display().to_string().replace('\\', "/")
}

/// One timestamp format everywhere, sortable as a plain string.
///
/// It goes down to the second. Two runs in the same minute used to get
/// the same folder name, and the second run's files landed on top of
/// the first. Older folders end at the minute
/// (`precheck_2026-04-14_08-48`); they still sort correctly next to the
/// new ones, because a name sorts before any longer name that starts
/// with it.
pub fn timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string()
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
        let dirs = ticket_dirs_in(Path::new("/r"), "NET-1").unwrap();
        assert_eq!(dirs.root, Path::new("/r"));
        assert_eq!(dirs.base, Path::new("/r/reports/NET-1"));
        assert_eq!(dirs.precheck, Path::new("/r/reports/NET-1/Precheck"));
        assert_eq!(dirs.postcheck, Path::new("/r/reports/NET-1/Postcheck"));
        assert_eq!(dirs.compare, Path::new("/r/reports/NET-1/Compare"));
        assert_eq!(dirs.display(&dirs.compare), "reports/NET-1/Compare");
        assert_eq!(dirs.display(Path::new("/elsewhere/x")), "/elsewhere/x");
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
    fn timestamp_has_seconds_and_sorts_after_the_old_minute_format() {
        let stamp = timestamp();
        let shape = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$").unwrap();
        assert!(shape.is_match(&stamp), "{stamp}");

        // An old minute-resolution folder and two new runs in that same minute.
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "precheck_2026-04-14_08-48",
            "precheck_2026-04-14_08-48-05",
            "precheck_2026-04-14_08-48-41",
        ] {
            fs::create_dir(tmp.path().join(name)).unwrap();
        }
        let latest = find_latest_folder(tmp.path(), "precheck_").unwrap();
        assert_eq!(latest.file_name().unwrap(), "precheck_2026-04-14_08-48-41");
    }

    #[test]
    fn tickets_are_normalized() {
        assert_eq!(normalize_ticket("  net-123 "), "NET-123");
    }

    #[test]
    fn safe_name_cases() {
        for (value, expected) in [
            ("SITE-A-SW-1", "SITE-A-SW-1"),
            ("localhost", "localhost"),
            ("../../x", "_.._x"),
            ("2001:db8::1", "2001_db8__1"),
            (".hidden", "hidden"),
            ("NUL", "_NUL"),
            ("com1.txt", "_com1.txt"),
            ("", "192.0.2.1"),
            ("...", "192.0.2.1"),
            ("core sw/1", "core_sw_1"),
        ] {
            assert_eq!(safe_name(value, "192.0.2.1"), expected, "{value:?}");
        }
    }

    #[test]
    fn safe_name_is_never_empty_dotted_or_too_long() {
        let long = "a".repeat(500);
        let long_ext = format!("{}.txt", "x".repeat(63));
        let shape = regex::Regex::new(r"^[A-Za-z0-9._-]+$").unwrap();

        for value in [
            "",
            ".",
            "..",
            "/",
            long.as_str(),
            long_ext.as_str(),
            "é".repeat(80).as_str(),
        ] {
            let name = safe_name(value, "");
            assert!(!name.is_empty(), "{value:?}");
            assert!(!name.starts_with('.'), "{value:?}");
            assert!(name.len() <= MAX_NAME_LENGTH, "{value:?}");
            assert!(shape.is_match(&name), "{value:?} -> {name:?}");
        }
        assert_eq!(safe_name("", ""), "device");
    }

    #[test]
    fn a_ticket_that_cannot_name_a_folder_is_rejected() {
        let too_long = "x".repeat(65);
        for ticket in [
            "../..",
            "..",
            "",
            "a/b",
            "a\\b",
            ".hidden",
            "NET 123",
            too_long.as_str(),
        ] {
            assert!(check_ticket(ticket).is_err(), "{ticket:?}");
            assert!(ticket_dirs_in(Path::new("/r"), ticket).is_err(), "{ticket:?}");
        }
    }

    #[test]
    fn the_ticket_error_reads_like_the_python_one() {
        assert_eq!(
            check_ticket("../..").unwrap_err().to_string(),
            "Ticket '../..' can't be used as a folder name. Use 1 to 64 letters, digits, dots, underscores, \
             or hyphens, starting with a letter or digit. Example: NET-123."
        );
    }

    #[test]
    fn an_ordinary_ticket_is_unchanged() {
        assert_eq!(check_ticket("NET-123").unwrap(), "NET-123");
        assert_eq!(check_ticket("CHG0012345_v2.1").unwrap(), "CHG0012345_v2.1");
    }
}
