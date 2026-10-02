//! The four subcommands. Each has a clap `Args` struct and a `run`.

pub mod compare;
pub mod demo;
pub mod postcheck;
pub mod precheck;

/// Shared capture flags for precheck and postcheck.
#[derive(Clone, Debug, clap::Args)]
pub struct CaptureArgs {
    /// Change/Jira ticket number (prompted if omitted)
    #[arg(long)]
    pub ticket: Option<String>,

    /// Path to inventory YAML (default: inventory/devices.yml)
    #[arg(long)]
    pub inventory: Option<std::path::PathBuf>,

    /// SSH username (prompted if omitted)
    #[arg(long)]
    pub username: Option<String>,

    /// Replace passwords, hashes, SNMP communities, TACACS/RADIUS/BGP/OSPF
    /// keys and PAN-OS encrypted values with <REDACTED> before writing
    #[arg(long)]
    pub redact_secrets: bool,
}

/// The ticket from the flag or a prompt, normalized.
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
    let ticket = crate::layout::normalize_ticket(&raw);
    anyhow::ensure!(!ticket.is_empty(), "a ticket number is required");
    Ok(ticket)
}
