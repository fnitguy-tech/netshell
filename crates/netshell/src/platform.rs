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

/// One command sent right after login to set the session up.
///
/// `required` decides what a rejection means. Paging off is required:
/// with the pager on, `show running-config` stops at ` --More-- ` and
/// never returns, so the connect fails with
/// [`Error::PreparationFailed`] instead. A wider terminal is not:
/// output still arrives, only wrapped, so the connect goes on and the
/// rejection is listed in `Device::warnings`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preparation {
    pub command: &'static str,
    pub required: bool,
}

impl Preparation {
    /// A command the session can't work without.
    pub const fn required(command: &'static str) -> Preparation {
        Preparation {
            command,
            required: true,
        }
    }

    /// A command that's nice to have.
    pub const fn optional(command: &'static str) -> Preparation {
        Preparation {
            command,
            required: false,
        }
    }
}

/// How to get from user mode (`RTR-1>`) to privileged mode (`RTR-1#`)
/// on platforms that have the split.
#[derive(Clone, Debug)]
pub struct Enable {
    /// Command that asks for privileged mode, `enable`.
    pub command: &'static str,
    /// Regex for the secret prompt, matched against the last line.
    pub password_prompt: &'static str,
    /// Regex that matches a user-mode prompt.
    pub user_prompt: &'static str,
}

/// Everything the driver needs to know about one platform.
///
/// The built-in profiles are constructed by [`Platform::by_name`].
/// For a platform that isn't covered, start from the closest profile
/// and change what differs, so a field added in a later release
/// doesn't break your build:
///
/// ```
/// use netshell::{Platform, Preparation};
///
/// const ASA_PREPARATION: &[Preparation] = &[Preparation::required("terminal pager 0")];
///
/// let asa = Platform {
///     name: "cisco_asa",
///     preparation: ASA_PREPARATION,
///     ..Platform::cisco_ios()
/// };
/// assert_eq!(asa.prompt_terminators, "[>#]");
/// ```
#[derive(Clone, Debug)]
pub struct Platform {
    /// netmiko-compatible device_type, e.g. `arista_eos`.
    pub name: &'static str,
    /// Regex character class for the characters that end a prompt.
    pub prompt_terminators: &'static str,
    /// Commands sent once after login: paging off, wide terminal, etc.
    pub preparation: &'static [Preparation],
    /// What this platform prints when it rejects a command, e.g.
    /// `% Invalid input`. Matched without regard to case. Only the
    /// preparation commands are checked against these: the output of
    /// your own commands is returned as it is.
    pub error_markers: &'static [&'static str],
    /// See [`Enable`]. `None` on platforms with no enable mode.
    pub enable: Option<Enable>,
    /// See [`ShellEscape`].
    pub shell_escape: Option<ShellEscape>,
    /// Regex for status lines the CLI prints just before each prompt
    /// (`{master:0}` on Junos); they are stripped from output.
    pub prompt_preamble: Option<&'static str>,
    /// How long to wait for the first prompt after the shell opens.
    /// PAN-OS can take a while to produce one.
    pub login_timeout: Duration,
}

/// Cisco-style rejections, shared by EOS, IOS, NX-OS, and IOS-XR.
const CISCO_ERRORS: &[&str] = &[
    "% Invalid input",
    "% Invalid command",
    "% Unknown command",
    "% Incomplete command",
    "% Ambiguous command",
    "% Authorization denied",
    "% Permission denied",
    "% Bad command",
    "Syntax error while parsing",
];

const CISCO_PREPARATION: &[Preparation] = &[
    Preparation::required("terminal length 0"),
    Preparation::optional("terminal width 511"),
];

/// `enable`, then `Password:`. The same on IOS, IOS-XE, and EOS.
const CISCO_ENABLE: Enable = Enable {
    command: "enable",
    password_prompt: r"(?i)password:\s*$",
    user_prompt: r">\s*$",
};

const XR_PREPARATION: &[Preparation] = &[
    Preparation::required("terminal length 0"),
    Preparation::optional("terminal width 512"),
    Preparation::optional("terminal exec prompt no-timestamp"),
];

const JUNOS_PREPARATION: &[Preparation] = &[
    Preparation::required("set cli screen-length 0"),
    Preparation::optional("set cli screen-width 511"),
    Preparation::optional("set cli complete-on-space off"),
];

const PANOS_PREPARATION: &[Preparation] = &[
    Preparation::optional("set cli scripting-mode on"),
    Preparation::required("set cli pager off"),
    Preparation::optional("set cli terminal width 500"),
];

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

    /// The first error marker found in `output`, if any.
    pub fn error_in<'a>(&self, output: &'a str) -> Option<&'a str> {
        output.lines().find(|line| {
            let line = line.to_ascii_lowercase();
            self.error_markers
                .iter()
                .any(|marker| line.contains(&marker.to_ascii_lowercase()))
        })
    }

    /// Arista EOS. `hostname>` / `hostname#`.
    pub fn arista_eos() -> Platform {
        Platform {
            name: "arista_eos",
            prompt_terminators: "[>#]",
            preparation: CISCO_PREPARATION,
            error_markers: CISCO_ERRORS,
            enable: Some(CISCO_ENABLE),
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
            preparation: CISCO_PREPARATION,
            error_markers: CISCO_ERRORS,
            enable: Some(CISCO_ENABLE),
            shell_escape: None,
            prompt_preamble: None,
            login_timeout: Duration::from_secs(15),
        }
    }

    /// Cisco NX-OS. Same prompt shape as IOS, but a login always lands
    /// at `#`, so there's no enable step.
    pub fn cisco_nxos() -> Platform {
        Platform {
            name: "cisco_nxos",
            prompt_terminators: "[>#]",
            preparation: CISCO_PREPARATION,
            error_markers: CISCO_ERRORS,
            enable: None,
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
            preparation: XR_PREPARATION,
            error_markers: CISCO_ERRORS,
            enable: None,
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
            preparation: JUNOS_PREPARATION,
            error_markers: &["syntax error", "unknown command", "error: "],
            enable: None,
            shell_escape: Some(ShellEscape {
                shell_prompt: r"[%$]\s*$|:~ #\s*$",
                command: "cli",
            }),
            // `{master:0}` on a virtual chassis, `{primary:node0}` on an
            // SRX chassis cluster, `{linecard:2}` on a line-card member.
            prompt_preamble: Some(r"^\{(?:master|backup|linecard|line|primary|secondary)(?::(?:node)?\d+)?\}\s*$"),
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
            preparation: PANOS_PREPARATION,
            error_markers: &["Invalid syntax", "Unknown command", "Server error"],
            enable: None,
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
    fn every_platform_requires_exactly_one_paging_off_command() {
        for name in Platform::names() {
            let platform = Platform::by_name(name).unwrap();
            let required = platform.preparation.iter().filter(|step| step.required).count();
            assert_eq!(required, 1, "{name}");
        }
    }

    #[test]
    fn rejections_are_spotted_per_platform() {
        let ios = Platform::cisco_ios();
        assert_eq!(
            ios.error_in("            ^\n% Invalid input detected at '^' marker."),
            Some("% Invalid input detected at '^' marker.")
        );
        assert_eq!(ios.error_in(""), None);
        assert_eq!(ios.error_in("Pagination disabled."), None);

        let junos = Platform::juniper_junos();
        assert!(junos.error_in("syntax error, expecting <command>.").is_some());
        assert!(junos.error_in("Screen length set to 0").is_none());

        let panos = Platform::paloalto_panos();
        assert!(panos.error_in("Invalid syntax.").is_some());
        assert!(panos.error_in("Unknown command: set").is_some());
    }

    #[test]
    fn junos_status_lines_match_the_preamble() {
        let preamble = regex::Regex::new(Platform::juniper_junos().prompt_preamble.unwrap()).unwrap();
        for line in [
            "{master:0}",
            "{backup:1}",
            "{linecard:2}",
            "{primary:node0}",
            "{secondary:node1}",
            "{master}",
        ] {
            assert!(preamble.is_match(line), "{line}");
        }
        // Real output that only looks similar stays in the capture.
        for line in ["{", "}", "{master:0} extra", "set groups {primary:node0}", "{node0}"] {
            assert!(!preamble.is_match(line), "{line}");
        }
    }

    #[test]
    fn only_ios_and_eos_have_an_enable_step() {
        for name in Platform::names() {
            let platform = Platform::by_name(name).unwrap();
            let expected = matches!(platform.name, "cisco_ios" | "arista_eos");
            assert_eq!(platform.enable.is_some(), expected, "{name}");
        }
    }

    #[test]
    fn unknown_name_lists_known_ones() {
        let err = Platform::by_name("cisco_asa").unwrap_err().to_string();
        assert!(err.contains("cisco_asa"));
        assert!(err.contains("arista_eos"));
    }
}
