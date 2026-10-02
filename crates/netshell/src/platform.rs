//! Per-platform knowledge: what a prompt looks like, how to turn paging
//! off, and the odd login quirk. This is the whole difference between
//! the platforms as far as a read-only shell driver is concerned.

use std::time::Duration;

use crate::Error;

/// Some platforms drop certain users into an OS shell rather than the
/// network CLI (Junos `root` lands in a FreeBSD `%` / `#` shell). When
/// the first prompt matches `shell_prompt`, the driver sends `command`
/// and waits for a real CLI prompt before continuing.
#[derive(Clone, Debug)]
pub struct ShellEscape {
    /// Regex matched against the last line after login.
    pub shell_prompt: &'static str,
    /// Command that enters the network CLI.
    pub command: &'static str,
}

/// Everything the driver needs to know about one platform.
///
/// The built-in profiles are constructed by [`Platform::by_name`];
/// build your own for a platform that is not covered.
#[derive(Clone, Debug)]
pub struct Platform {
    /// netmiko-compatible device_type, e.g. `arista_eos`.
    pub name: &'static str,
    /// Regex character class for the characters that end a prompt.
    pub prompt_terminators: &'static str,
    /// Commands sent once after login: paging off, wide terminal, etc.
    pub preparation: &'static [&'static str],
    /// See [`ShellEscape`].
    pub shell_escape: Option<ShellEscape>,
    /// Regex for status lines the CLI prints just before each prompt
    /// (`{master:0}` on Junos); they are stripped from output.
    pub prompt_preamble: Option<&'static str>,
    /// How long to wait for the first prompt after the shell opens.
    /// PAN-OS can take a while to produce one.
    pub login_timeout: Duration,
}

const NAMES: &[&str] = &[
    "arista_eos",
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "cisco_xr",
    "juniper_junos",
    "paloalto_panos",
];

impl Platform {
    /// Look a profile up by netmiko device_type. `cisco_xe` is an alias
    /// of `cisco_ios`; `cisco_iosxr`, `juniper` and `panos` are accepted
    /// too.
    pub fn by_name(name: &str) -> Result<Platform, Error> {
        match name.trim().to_ascii_lowercase().as_str() {
            "arista_eos" => Ok(Self::arista_eos()),
            "cisco_ios" | "cisco_xe" | "cisco_ios_xe" => Ok(Self::cisco_ios()),
            "cisco_nxos" => Ok(Self::cisco_nxos()),
            "cisco_xr" | "cisco_iosxr" => Ok(Self::cisco_xr()),
            "juniper_junos" | "juniper" => Ok(Self::juniper_junos()),
            "paloalto_panos" | "panos" => Ok(Self::paloalto_panos()),
            other => Err(Error::UnknownPlatform(other.to_string())),
        }
    }

    /// The device_type names [`Platform::by_name`] accepts (aliases
    /// aside).
    pub fn names() -> &'static [&'static str] {
        NAMES
    }

    /// Arista EOS. `hostname>` / `hostname#`.
    pub fn arista_eos() -> Platform {
        Platform {
            name: "arista_eos",
            prompt_terminators: "[>#]",
            preparation: &["terminal length 0", "terminal width 511"],
            shell_escape: None,
            prompt_preamble: None,
            login_timeout: Duration::from_secs(15),
        }
    }

    /// Cisco IOS and IOS-XE. `hostname>` / `hostname#`.
    pub fn cisco_ios() -> Platform {
        Platform {
            name: "cisco_ios",
            prompt_terminators: "[>#]",
            preparation: &["terminal length 0", "terminal width 511"],
            shell_escape: None,
            prompt_preamble: None,
            login_timeout: Duration::from_secs(15),
        }
    }

    /// Cisco NX-OS. Same prompt shape as IOS.
    pub fn cisco_nxos() -> Platform {
        Platform {
            name: "cisco_nxos",
            prompt_terminators: "[>#]",
            preparation: &["terminal length 0", "terminal width 511"],
            shell_escape: None,
            prompt_preamble: None,
            login_timeout: Duration::from_secs(15),
        }
    }

    /// Cisco IOS-XR. `RP/0/RP0/CPU0:hostname#`. Timestamps above each
    /// command's output are turned off so captures diff cleanly.
    pub fn cisco_xr() -> Platform {
        Platform {
            name: "cisco_xr",
            prompt_terminators: "[>#]",
            preparation: &[
                "terminal length 0",
                "terminal width 512",
                "terminal exec prompt no-timestamp",
            ],
            shell_escape: None,
            prompt_preamble: None,
            login_timeout: Duration::from_secs(15),
        }
    }

    /// Juniper Junos. `user@hostname>`. A root login lands in the
    /// FreeBSD shell (`root@hostname:~ #` or `%`); the driver sends
    /// `cli` to get to the operational prompt.
    pub fn juniper_junos() -> Platform {
        Platform {
            name: "juniper_junos",
            prompt_terminators: "[>#]",
            preparation: &[
                "set cli screen-length 0",
                "set cli screen-width 511",
                "set cli complete-on-space off",
            ],
            shell_escape: Some(ShellEscape {
                shell_prompt: r"[%$]\s*$|:~ #\s*$",
                command: "cli",
            }),
            prompt_preamble: Some(r"^\{(?:master|backup|line|primary|secondary)(?::\d+)?\}\s*$"),
            login_timeout: Duration::from_secs(15),
        }
    }

    /// Palo Alto PAN-OS. `user@hostname>` or `user@hostname(active)>`
    /// on an HA pair. Scripting mode stops the CLI from mangling long
    /// commands; the pager is turned off; the terminal is widened so
    /// `show config running` lines are not wrapped.
    pub fn paloalto_panos() -> Platform {
        Platform {
            name: "paloalto_panos",
            prompt_terminators: "[>#]",
            preparation: &[
                "set cli scripting-mode on",
                "set cli pager off",
                "set cli terminal width 500",
            ],
            shell_escape: None,
            prompt_preamble: None,
            login_timeout: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_name_resolves() {
        for name in Platform::names() {
            let platform = Platform::by_name(name).unwrap();
            assert!(!platform.preparation.is_empty(), "{name} has no preparation commands");
        }
    }

    #[test]
    fn aliases_and_case() {
        assert_eq!(Platform::by_name("Cisco_XE").unwrap().name, "cisco_ios");
        assert_eq!(Platform::by_name("cisco_iosxr").unwrap().name, "cisco_xr");
        assert_eq!(Platform::by_name("panos").unwrap().name, "paloalto_panos");
        assert_eq!(Platform::by_name(" juniper ").unwrap().name, "juniper_junos");
    }

    #[test]
    fn unknown_name_lists_known_ones() {
        let err = Platform::by_name("cisco_asa").unwrap_err().to_string();
        assert!(err.contains("cisco_asa"));
        assert!(err.contains("arista_eos"));
    }
}
