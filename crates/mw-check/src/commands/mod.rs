//! The five subcommands: before, after, report, notes, demo. Each has a
//! clap `Args` struct and a `run`.

pub mod compare;
pub mod demo;
pub mod notes;
pub mod postcheck;
pub mod precheck;

use std::path::PathBuf;

use crate::collect::SshConnector;
use crate::hostkeys::{self, HostKeys};
use crate::inventory;

/// Shared arguments for `before` and `after`.
#[derive(Clone, Debug, clap::Args)]
pub struct CaptureArgs {
    /// Change/Jira ticket number, e.g. NET-123 (prompted if omitted)
    #[arg(value_name = "TICKET")]
    pub ticket: Option<String>,

    /// SSH username (prompted if omitted)
    #[arg(short, long, value_name = "USER")]
    pub username: Option<String>,

    /// Inventory YAML (default: inventory/devices.yml)
    #[arg(short, long, value_name = "FILE")]
    pub inventory: Option<PathBuf>,

    /// Replace passwords, password hashes, SNMP communities,
    /// TACACS/RADIUS/BGP/OSPF keys, private keys, and PAN-OS encrypted
    /// values with <REDACTED> before anything is written to disk
    #[arg(short, long, alias = "redact-secrets")]
    pub redact: bool,

    /// File of SSH host keys to check each device against. A new
    /// device's key is recorded on first connect; a changed key is
    /// refused. (default: $MW_KNOWN_HOSTS if set, else
    /// ~/.config/mw/known_hosts; on Windows, %APPDATA%\mw\known_hosts)
    #[arg(long, value_name = "FILE")]
    pub known_hosts: Option<PathBuf>,

    /// Accept a changed host key from this one device and store the new
    /// key. Use it once, after you replaced or re-imaged the device.
    /// Name the host the way the inventory does. Repeat for more devices
    #[arg(long, value_name = "HOST", conflicts_with = "insecure_accept_any_host_key")]
    pub accept_new_host_key: Vec<String>,

    /// Skip the SSH host-key check and accept whatever key each device
    /// offers. Your password is then sent to anything that answers at
    /// the device's address, so use it only on a lab you trust
    #[arg(long, conflicts_with = "known_hosts")]
    pub insecure_accept_any_host_key: bool,

    /// Also offer old SSH algorithms (SHA-1 key exchange, CBC ciphers,
    /// hmac-sha1) for devices that offer nothing newer
    #[arg(long)]
    pub legacy_algorithms: bool,

    /// Enter enable mode on devices that log in at `>` (Cisco IOS/IOS-XE,
    /// Arista EOS). The enable secret is prompted for, never a flag
    #[arg(long)]
    pub enable: bool,

    /// Stay in user mode when a login lands at `>`. Commands like
    /// `show running-config` then fail, and the capture says so
    #[arg(long, conflicts_with = "enable")]
    pub user_mode: bool,
}

impl CaptureArgs {
    /// The host-key settings these flags ask for.
    pub fn host_keys(&self) -> anyhow::Result<HostKeys> {
        if self.insecure_accept_any_host_key {
            return Ok(HostKeys::AcceptAny);
        }

        Ok(HostKeys::KnownHosts {
            path: hostkeys::resolve_known_hosts(self.known_hosts.as_deref())?,
            accept_new: self.accept_new_host_key.clone(),
        })
    }

    /// The SSH connector these flags ask for. Prompts for the enable
    /// secret when `--enable` is given, and says so when host keys
    /// aren't being checked.
    pub fn connector(&self) -> anyhow::Result<SshConnector> {
        let mut connector = SshConnector::new(self.host_keys()?);
        connector.legacy_algorithms = self.legacy_algorithms;
        connector.allow_user_mode = self.user_mode;

        if self.enable {
            connector.enable_secret = Some(inventory::prompt_enable_secret()?);
        }

        if connector.host_keys == HostKeys::AcceptAny {
            println!("SSH host keys are not being checked (--insecure-accept-any-host-key).");
        }

        Ok(connector)
    }
}

/// The ticket from the flag or a prompt: trimmed, upper-cased, and
/// checked, because it becomes a folder name. A ticket of `../..` would
/// write outside `reports/`.
pub fn resolve_ticket(ticket: Option<&str>) -> anyhow::Result<String> {
    let raw = match ticket {
        Some(value) => value.to_string(),
        None => {
            eprint!("Ticket: ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };

    Ok(crate::layout::check_ticket(&crate::layout::normalize_ticket(&raw))?)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        capture: CaptureArgs,
    }

    fn parse(args: &[&str]) -> Result<CaptureArgs, clap::Error> {
        Cli::try_parse_from(std::iter::once("mw").chain(args.iter().copied())).map(|cli| cli.capture)
    }

    #[test]
    fn a_ticket_that_would_escape_reports_is_rejected() {
        let error = resolve_ticket(Some("../..")).unwrap_err().to_string();
        assert!(error.contains("can't be used as a folder name"), "{error}");
    }

    #[test]
    fn a_normal_ticket_is_upper_cased_as_before() {
        assert_eq!(resolve_ticket(Some(" net-123 ")).unwrap(), "NET-123");
    }

    #[test]
    fn host_keys_are_checked_unless_you_opt_out() {
        let chosen = parse(&[
            "NET-1",
            "--known-hosts",
            "/tmp/flag",
            "--accept-new-host-key",
            "192.0.2.11",
        ])
        .unwrap()
        .host_keys()
        .unwrap();
        assert_eq!(
            chosen,
            HostKeys::KnownHosts {
                path: PathBuf::from("/tmp/flag"),
                accept_new: vec!["192.0.2.11".to_string()],
            }
        );

        let open = parse(&["NET-1", "--insecure-accept-any-host-key"]).unwrap();
        assert_eq!(open.host_keys().unwrap(), HostKeys::AcceptAny);
    }

    #[test]
    fn flags_that_contradict_each_other_are_refused() {
        assert!(parse(&["NET-1", "--insecure-accept-any-host-key", "--known-hosts", "/tmp/x"]).is_err());
        assert!(
            parse(&[
                "NET-1",
                "--insecure-accept-any-host-key",
                "--accept-new-host-key",
                "192.0.2.11"
            ])
            .is_err()
        );
        assert!(parse(&["NET-1", "--enable", "--user-mode"]).is_err());
    }

    #[test]
    fn the_connection_flags_reach_the_connector() {
        let args = parse(&[
            "NET-1",
            "--known-hosts",
            "/tmp/kh",
            "--legacy-algorithms",
            "--user-mode",
        ])
        .unwrap();
        let connector = args.connector().unwrap();
        assert!(connector.legacy_algorithms);
        assert!(connector.allow_user_mode);
        assert!(connector.enable_secret.is_none());
        // No flag takes a password or an enable secret as its value.
        assert!(parse(&["NET-1", "--enable", "hunter2"]).is_err());
        assert!(parse(&["NET-1", "--password", "hunter2"]).is_err());
    }
}
