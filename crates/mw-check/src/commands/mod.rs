//! The four subcommands: before, after, report, demo. Each has a clap
//! `Args` struct and a `run`.

pub mod compare;
pub mod demo;
pub mod postcheck;
pub mod precheck;

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
    pub inventory: Option<std::path::PathBuf>,

    /// Strip passwords, hashes, SNMP communities, and keys from the capture
    #[arg(short, long, alias = "redact-secrets")]
    pub redact: bool,
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
