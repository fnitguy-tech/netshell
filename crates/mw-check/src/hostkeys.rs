//! SSH host-key checking: trust on first use, refuse on change.
//!
//! Why it matters: you type your password into whatever answers at the
//! device's address. If something else answers (a mis-patched cable, a
//! reused IP, an attacker), a host-key check is the only thing that
//! notices before the password is sent.
//!
//! What `mw` does, the way `ssh` itself does:
//!
//! 1. First connection to a device: its key is written to a known-hosts
//!    file that belongs to this tool. One line per device:
//!
//!    ```text
//!    192.0.2.11:22 ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
//!    ```
//!
//! 2. Every later connection: the key must match that line. If it
//!    doesn't, the connection is refused before any password is sent,
//!    with an error that names the device, both fingerprints, the file,
//!    and the fix (see [`changed_key_message`]).
//!
//! The file lives at `~/.config/mw/known_hosts` (`$XDG_CONFIG_HOME` is
//! honoured; on Windows, `%APPDATA%\mw\known_hosts`). Set
//! `MW_KNOWN_HOSTS` or pass `--known-hosts` to use another one.
//!
//! netshell does the checking and the file handling (the line format,
//! the locking, the private permissions). This module only decides
//! which file and which policy `mw` asks it for. The Python tool keeps
//! its own file in OpenSSH's format, so the two tools don't share one.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use netshell::HostKeyPolicy;

/// Environment variable that names the known-hosts file. It loses to
/// `--known-hosts` and wins over the default path.
pub const KNOWN_HOSTS_ENV: &str = "MW_KNOWN_HOSTS";

/// How `mw before` and `mw after` treat the key each device presents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeys {
    /// Check every device against this file. A new device's key is
    /// recorded on first connect, and a changed key is refused.
    ///
    /// `accept_new` lists the devices whose changed key should replace
    /// the stored one (`--accept-new-host-key HOST`). It's a list of
    /// hosts, not a switch for the whole run, so replacing one switch
    /// can't wave through a changed key on another.
    KnownHosts { path: PathBuf, accept_new: Vec<String> },
    /// Accept any key and remember nothing
    /// (`--insecure-accept-any-host-key`). Lab use only.
    AcceptAny,
}

impl HostKeys {
    /// The netshell policy for one device.
    pub fn policy_for(&self, host: &str) -> HostKeyPolicy {
        match self {
            HostKeys::AcceptAny => HostKeyPolicy::AcceptAny,
            HostKeys::KnownHosts { accept_new, .. } if accept_new.iter().any(|name| name == host) => {
                HostKeyPolicy::ReplaceKnownHost
            }
            HostKeys::KnownHosts { .. } => HostKeyPolicy::KnownHosts,
        }
    }

    /// The known-hosts file, when one is in use.
    pub fn path(&self) -> Option<&Path> {
        match self {
            HostKeys::KnownHosts { path, .. } => Some(path),
            HostKeys::AcceptAny => None,
        }
    }
}

/// The user's config directory: `$XDG_CONFIG_HOME` or `~/.config` on
/// Linux and macOS, `%APPDATA%` on Windows. `None` when no home
/// directory can be found, which happens in some containers.
fn config_dir() -> Option<PathBuf> {
    let non_empty = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());

    if cfg!(windows) {
        non_empty("APPDATA").map(PathBuf::from)
    } else {
        non_empty("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| non_empty("HOME").map(|home| PathBuf::from(home).join(".config")))
    }
}

/// Where the known-hosts file lives unless you say otherwise:
/// `<config dir>/mw/known_hosts`.
pub fn default_known_hosts_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("mw").join("known_hosts"))
}

/// The known-hosts file to use: `--known-hosts`, else
/// `$MW_KNOWN_HOSTS`, else the default.
pub fn resolve_known_hosts(flag: Option<&Path>) -> anyhow::Result<PathBuf> {
    let from_env = std::env::var_os(KNOWN_HOSTS_ENV);
    resolve_known_hosts_from(flag, from_env, default_known_hosts_path())
}

/// [`resolve_known_hosts`] with the environment passed in, so the
/// order can be tested without touching the real environment.
pub fn resolve_known_hosts_from(
    flag: Option<&Path>,
    from_env: Option<OsString>,
    default: Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path.to_path_buf());
    }

    if let Some(path) = from_env.filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    default.ok_or_else(|| {
        anyhow::anyhow!(
            "There's no home directory to keep the known-hosts file in. \
             Pass --known-hosts FILE or set {KNOWN_HOSTS_ENV} to a file you can write."
        )
    })
}

/// What goes in the `_FAILED.txt` file and on the console when a
/// device offers a different key than the one on file.
///
/// ```text
/// The SSH host key for 192.0.2.11 has changed, so the connection was refused before any password was sent.
///   Key on file:  ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
///   Key offered:  ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
///   File:         /home/you/.config/mw/known_hosts (line 3)
/// If this device was replaced or re-imaged, that's expected. To accept the new key, run again with:
///   --accept-new-host-key 192.0.2.11
/// The new key then replaces line 3. If nothing was replaced, stop and find out what's answering at that address.
/// ```
pub fn changed_key_message(host: &str, stored: &str, offered: &str, file: &Path, line: usize) -> String {
    format!(
        "The SSH host key for {host} has changed, so the connection was refused before any password was sent.\n\
         \x20 Key on file:  {stored}\n\
         \x20 Key offered:  {offered}\n\
         \x20 File:         {} (line {line})\n\
         If this device was replaced or re-imaged, that's expected. To accept the new key, run again with:\n\
         \x20 --accept-new-host-key {host}\n\
         The new key then replaces line {line}. If nothing was replaced, stop and find out what's answering at \
         that address.",
        file.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_wins_then_the_environment_then_the_default() {
        let default = Some(PathBuf::from("/home/you/.config/mw/known_hosts"));
        let env = Some(OsString::from("/from/env"));

        assert_eq!(
            resolve_known_hosts_from(Some(Path::new("/from/flag")), env.clone(), default.clone()).unwrap(),
            Path::new("/from/flag")
        );
        assert_eq!(
            resolve_known_hosts_from(None, env, default.clone()).unwrap(),
            Path::new("/from/env")
        );
        assert_eq!(
            resolve_known_hosts_from(None, Some(OsString::new()), default.clone()).unwrap(),
            Path::new("/home/you/.config/mw/known_hosts")
        );
        assert_eq!(
            resolve_known_hosts_from(None, None, default).unwrap(),
            Path::new("/home/you/.config/mw/known_hosts")
        );
    }

    #[test]
    fn no_home_directory_says_how_to_fix_it() {
        let error = resolve_known_hosts_from(None, None, None).unwrap_err().to_string();
        assert!(error.contains("--known-hosts FILE"), "{error}");
        assert!(error.contains("MW_KNOWN_HOSTS"), "{error}");
    }

    #[test]
    fn the_default_file_sits_in_an_mw_folder() {
        if let Some(path) = default_known_hosts_path() {
            assert!(path.ends_with("mw/known_hosts"), "{}", path.display());
        }
    }

    #[test]
    fn host_keys_are_checked_unless_you_opt_out() {
        let checked = HostKeys::KnownHosts {
            path: PathBuf::from("/kh"),
            accept_new: vec!["192.0.2.11".to_string()],
        };
        assert_eq!(checked.policy_for("192.0.2.1"), HostKeyPolicy::KnownHosts);
        // Only the named device gets its changed key replaced.
        assert_eq!(checked.policy_for("192.0.2.11"), HostKeyPolicy::ReplaceKnownHost);
        assert_eq!(checked.path(), Some(Path::new("/kh")));

        assert_eq!(HostKeys::AcceptAny.policy_for("192.0.2.1"), HostKeyPolicy::AcceptAny);
        assert_eq!(HostKeys::AcceptAny.path(), None);
    }

    #[test]
    fn the_changed_key_message_names_the_device_both_keys_the_file_and_the_fix() {
        let message = changed_key_message(
            "192.0.2.11",
            "ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
            "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
            Path::new("/home/you/.config/mw/known_hosts"),
            3,
        );
        assert_eq!(
            message,
            "The SSH host key for 192.0.2.11 has changed, so the connection was refused before any password was sent.\n  \
             Key on file:  ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8\n  \
             Key offered:  ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s\n  \
             File:         /home/you/.config/mw/known_hosts (line 3)\n\
             If this device was replaced or re-imaged, that's expected. To accept the new key, run again with:\n  \
             --accept-new-host-key 192.0.2.11\n\
             The new key then replaces line 3. If nothing was replaced, stop and find out what's answering at that address."
        );
    }
}
