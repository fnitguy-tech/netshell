//! The known-hosts file: remember each device's host key the first
//! time, and refuse to connect if it ever changes.
//!
//! One device per line, three fields:
//!
//! ```text
//! 192.0.2.11:22 ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
//! [2001:db8::11]:22 ssh-rsa SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
//! ```
//!
//! Blank lines and lines that start with `#` are ignored, so the file
//! can carry comments. It isn't OpenSSH's format on purpose: a line
//! holds a fingerprint, not a whole key, so it's short enough to read
//! and compare by eye.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Environment variable that names the known-hosts file. It wins over
/// the default path and loses to [`crate::ConnectOptions::known_hosts`].
pub const KNOWN_HOSTS_ENV: &str = "NETSHELL_KNOWN_HOSTS";

/// Where the known-hosts file lives when nothing else is set:
/// `~/.config/netshell/known_hosts` on Linux and macOS
/// (`$XDG_CONFIG_HOME` is honoured), `%APPDATA%\netshell\known_hosts`
/// on Windows. `None` when the home directory can't be found, which
/// happens in some containers and services.
pub fn default_known_hosts_path() -> Option<PathBuf> {
    let non_empty = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let config_dir = if cfg!(windows) {
        non_empty("APPDATA").map(PathBuf::from)
    } else {
        non_empty("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| non_empty("HOME").map(|home| PathBuf::from(home).join(".config")))
    };
    config_dir.map(|dir| dir.join("netshell").join("known_hosts"))
}

/// The file to use: the caller's path, else the environment variable,
/// else the default.
pub(crate) fn resolve_path(explicit: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os(KNOWN_HOSTS_ENV).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    default_known_hosts_path()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no home directory to keep the default file in"))
}

/// `192.0.2.11:22`, or `[2001:db8::11]:22` so an IPv6 address and the
/// port can't be confused.
pub(crate) fn host_id(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// What the file says about one device.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// First contact: the key was written to the file.
    Recorded,
    /// The stored key matches.
    Known,
    /// The stored key was different and was replaced, because the
    /// caller asked for that.
    Replaced,
    /// The stored key is different. `stored` is `algorithm fingerprint`.
    Changed { stored: String, line: usize },
}

/// Look `id` up and record its key if it's new. With `replace`, a
/// different stored key is overwritten instead of reported.
///
/// The whole read-check-write runs under an exclusive lock on a
/// sidecar file (`known_hosts.lock`), so five collector threads, or
/// five separate `netshell` processes, meeting five new devices at the
/// same moment each add their line and none is lost. The lock is on a
/// sidecar rather than the file itself because a replace swaps the
/// file by rename, and a lock on the old file wouldn't cover the new
/// one.
///
/// This blocks on file I/O. Call it from `spawn_blocking` in async
/// code.
pub(crate) fn check_and_record(
    path: &Path,
    id: &str,
    algorithm: &str,
    fingerprint: &str,
    replace: bool,
) -> io::Result<Verdict> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }

    let mut lock_name = path.as_os_str().to_owned();
    lock_name.push(".lock");
    // Read and write, not append. Windows only grants a file lock on a
    // handle opened for reading or writing; an append-only handle gets
    // "Access is denied" from the lock call. Nothing is ever written
    // to this file.
    let lock = private_file().read(true).write(true).open(PathBuf::from(lock_name))?;
    lock.lock()?;
    let verdict = locked_check_and_record(path, id, algorithm, fingerprint, replace);
    let _ = lock.unlock();
    verdict
}

fn locked_check_and_record(
    path: &Path,
    id: &str,
    algorithm: &str,
    fingerprint: &str,
    replace: bool,
) -> io::Result<Verdict> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let new_line = format!("{id} {algorithm} {fingerprint}\n");

    // The first entry for a host is the one that counts.
    let stored = content.lines().enumerate().find_map(|(index, line)| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next(), fields.next()) {
            (Some(host), Some(algorithm), Some(fingerprint)) if host == id => {
                Some((index + 1, algorithm.to_string(), fingerprint.to_string()))
            }
            _ => None,
        }
    });

    let Some((line, stored_algorithm, stored_fingerprint)) = stored else {
        // Append in one write so a reader never sees half a line. A
        // file someone edited by hand may lack a final newline; add
        // it so the new entry doesn't glue onto the last one.
        let mut file = private_file().append(true).open(path)?;
        let prefix = if content.is_empty() || content.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        file.write_all(format!("{prefix}{new_line}").as_bytes())?;
        file.sync_all()?;
        return Ok(Verdict::Recorded);
    };

    if stored_algorithm == algorithm && same_fingerprint(&stored_fingerprint, fingerprint) {
        return Ok(Verdict::Known);
    }
    if !replace {
        return Ok(Verdict::Changed {
            stored: format!("{stored_algorithm} {stored_fingerprint}"),
            line,
        });
    }

    // Replace in place, keeping comments and every other host. Write a
    // temporary file and rename it over the old one, so a crash
    // halfway leaves the old file whole.
    let mut rewritten = String::with_capacity(content.len() + new_line.len());
    for (index, old) in content.lines().enumerate() {
        if index + 1 == line {
            rewritten.push_str(&new_line);
        } else if old.split_whitespace().next() != Some(id) {
            rewritten.push_str(old);
            rewritten.push('\n');
        }
    }
    let mut temp_name = path.as_os_str().to_owned();
    temp_name.push(".tmp");
    let temp = PathBuf::from(temp_name);
    let mut file = private_file().write(true).truncate(true).open(&temp)?;
    file.write_all(rewritten.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, path)?;
    Ok(Verdict::Replaced)
}

/// Fingerprints are equal when they match without the `SHA256:` prefix
/// and base64 padding, which tools print inconsistently.
pub(crate) fn same_fingerprint(left: &str, right: &str) -> bool {
    normalize_fingerprint(left) == normalize_fingerprint(right)
}

fn normalize_fingerprint(text: &str) -> &str {
    text.trim().trim_start_matches("SHA256:").trim_end_matches('=')
}

/// Open options for a file only the user can read: mode 0600 on Unix.
/// On Windows the file inherits the profile directory's ACL, which is
/// already private to the user.
fn private_file() -> OpenOptions {
    let mut options = File::options();
    options.create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Create the directory (and parents) if needed, mode 0700 on Unix.
/// An existing directory is left alone: `~/.config` isn't ours to
/// re-permission.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "ssh-ed25519";
    const FIRST: &str = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";
    const SECOND: &str = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";

    #[test]
    fn ipv6_hosts_are_bracketed() {
        assert_eq!(host_id("192.0.2.11", 22), "192.0.2.11:22");
        assert_eq!(host_id("2001:db8::11", 22), "[2001:db8::11]:22");
    }

    #[test]
    fn records_then_knows_then_reports_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("known_hosts");

        assert_eq!(
            check_and_record(&path, "192.0.2.11:22", ED, FIRST, false).unwrap(),
            Verdict::Recorded
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("192.0.2.11:22 {ED} {FIRST}\n")
        );
        assert_eq!(
            check_and_record(&path, "192.0.2.11:22", ED, FIRST, false).unwrap(),
            Verdict::Known
        );
        assert_eq!(
            check_and_record(&path, "192.0.2.11:22", ED, SECOND, false).unwrap(),
            Verdict::Changed {
                stored: format!("{ED} {FIRST}"),
                line: 1
            }
        );
        // A refused key leaves the file as it was.
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("192.0.2.11:22 {ED} {FIRST}\n")
        );
    }

    #[test]
    fn replace_keeps_comments_and_other_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        // No final newline, as a hand-edited file might have.
        fs::write(
            &path,
            format!("# lab switches\n192.0.2.11:22 {ED} {FIRST}\n192.0.2.12:22 {ED} {FIRST}"),
        )
        .unwrap();

        assert_eq!(
            check_and_record(&path, "192.0.2.12:22", ED, SECOND, false).unwrap(),
            Verdict::Changed {
                stored: format!("{ED} {FIRST}"),
                line: 3
            }
        );
        assert_eq!(
            check_and_record(&path, "192.0.2.12:22", ED, SECOND, true).unwrap(),
            Verdict::Replaced
        );
        assert_eq!(
            check_and_record(&path, "192.0.2.13:22", ED, FIRST, false).unwrap(),
            Verdict::Recorded
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!(
                "# lab switches\n192.0.2.11:22 {ED} {FIRST}\n192.0.2.12:22 {ED} {SECOND}\n192.0.2.13:22 {ED} {FIRST}\n"
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netshell").join("known_hosts");
        check_and_record(&path, "192.0.2.11:22", ED, FIRST, false).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn fingerprints_compare_without_prefix_or_padding() {
        assert!(same_fingerprint("SHA256:abc=", " abc"));
        assert!(!same_fingerprint("SHA256:abc", "SHA256:abd"));
    }
}
