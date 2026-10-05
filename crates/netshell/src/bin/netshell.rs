//! Command-line front end: run show commands on one device and print
//! the output, either as a capture file (the `### command ###` section
//! format prepost-check reads) or as JSON.
//!
//! The password is never a flag. It is read from the environment
//! variable named by `--password-env`, or prompted for. The enable
//! secret works the same way.
//!
//! Exit codes, so a script can tell the cases apart:
//!
//! | code | meaning                                                  |
//! |------|----------------------------------------------------------|
//! | 0    | every command ran                                        |
//! | 1    | couldn't connect or log in; nothing was collected        |
//! | 2    | bad arguments (clap's own code)                          |
//! | 3    | connected, but at least one command failed; the output   |
//! |      | of the others is still printed                           |

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use netshell::{ConnectOptions, Device, HostKeyPolicy, Platform, Secret};

/// One or more commands failed after a good connect.
const EXIT_COMMAND_FAILED: u8 = 3;

#[derive(Parser)]
#[command(
    name = "netshell",
    version,
    about = "Run show commands on a network device over SSH",
    after_help = "Platforms: arista_eos, cisco_ios (cisco_xe), cisco_nxos, cisco_xr, juniper_junos, paloalto_panos\n\n\
Exit codes: 0 every command ran, 1 couldn't connect or log in, 2 bad arguments, 3 a command failed (the rest is still printed)"
)]
struct Cli {
    /// Device type (netmiko name), e.g. arista_eos
    #[arg(short, long)]
    platform: String,

    /// Management IP or hostname
    #[arg(short = 'H', long)]
    host: String,

    #[arg(short = 'P', long, default_value_t = 22)]
    port: u16,

    #[arg(short, long)]
    username: String,

    /// Read the password from this environment variable instead of prompting
    #[arg(long, value_name = "VAR")]
    password_env: Option<String>,

    /// Enter enable mode (Cisco IOS/IOS-XE, Arista EOS). Prompts for the enable secret
    #[arg(long)]
    enable: bool,

    /// Enter enable mode with the secret from this environment variable, without a prompt
    #[arg(long, value_name = "VAR", conflicts_with = "enable")]
    enable_env: Option<String>,

    /// Stay in user mode (the `>` prompt) when the login lands there
    #[arg(long, conflicts_with_all = ["enable", "enable_env"])]
    user_mode: bool,

    /// Seconds to wait for each command's output
    #[arg(long, default_value_t = 60)]
    read_timeout: u64,

    /// Seconds to wait for each connect step: TCP and handshake, login, opening the shell
    #[arg(long, default_value_t = 15)]
    connect_timeout: u64,

    /// Where host keys are remembered [default: NETSHELL_KNOWN_HOSTS, or ~/.config/netshell/known_hosts]
    #[arg(long, value_name = "FILE")]
    known_hosts: Option<PathBuf>,

    /// The device's host key changed and you expected it: store the new key and connect
    #[arg(long)]
    accept_new_host_key: bool,

    /// Only connect if the host key has this SHA256 fingerprint. Skips the known-hosts file
    #[arg(long, value_name = "SHA256:...", conflicts_with = "accept_new_host_key")]
    fingerprint: Option<String>,

    /// Don't check the host key at all. Anyone on the path can read your password. Lab use only
    #[arg(long, conflicts_with_all = ["fingerprint", "accept_new_host_key"])]
    insecure_accept_any_host_key: bool,

    /// Also offer old algorithms (SHA-1 key exchange, CBC ciphers, 3DES, HMAC-SHA1) for devices with nothing newer
    #[arg(long)]
    legacy_algorithms: bool,

    /// Print {"host", "prompt", "commands": [{"command", "output"}]} instead of sections
    #[arg(long)]
    json: bool,

    /// Commands to run, in order
    #[arg(required = true, value_name = "COMMAND")]
    commands: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("netshell: {error}");
            ExitCode::FAILURE
        }
    }
}

/// A secret from the named environment variable.
fn secret_from_env(var: &str) -> Result<Secret, String> {
    std::env::var(var)
        .map(Secret::from)
        .map_err(|_| format!("environment variable {var} is not set"))
}

async fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let platform = Platform::by_name(&cli.platform)?;

    let password = match &cli.password_env {
        Some(var) => secret_from_env(var)?,
        None => Secret::from(rpassword::prompt_password(format!(
            "Password for {}@{}: ",
            cli.username, cli.host
        ))?),
    };
    let enable_secret = match &cli.enable_env {
        Some(var) => Some(secret_from_env(var)?),
        None if cli.enable => Some(Secret::from(rpassword::prompt_password(format!(
            "Enable secret for {}: ",
            cli.host
        ))?)),
        None => None,
    };

    let host_key = if cli.insecure_accept_any_host_key {
        HostKeyPolicy::AcceptAny
    } else if let Some(fingerprint) = cli.fingerprint {
        HostKeyPolicy::Sha256Fingerprint(fingerprint)
    } else if cli.accept_new_host_key {
        HostKeyPolicy::ReplaceKnownHost
    } else {
        HostKeyPolicy::KnownHosts
    };

    let mut options = ConnectOptions::new(&cli.host, &cli.username, password, platform)
        .port(cli.port)
        .connect_timeout(Duration::from_secs(cli.connect_timeout))
        .read_timeout(Duration::from_secs(cli.read_timeout))
        .host_key(host_key)
        .legacy_algorithms(cli.legacy_algorithms)
        .allow_user_mode(cli.user_mode);
    if let Some(path) = cli.known_hosts {
        options = options.known_hosts(path);
    }
    if let Some(secret) = enable_secret {
        options = options.enable_secret(secret);
    }

    let mut device = Device::connect(options).await?;
    for warning in device.warnings() {
        eprintln!("netshell: warning: {warning}");
    }

    let mut failed = 0;
    let mut results: Vec<(String, String)> = Vec::with_capacity(cli.commands.len());
    for command in &cli.commands {
        let output = match device.send_command(command).await {
            Ok(output) => output,
            Err(error) => {
                failed += 1;
                eprintln!("netshell: `{command}` failed: {error}");
                format!("COMMAND FAILED:\n{error}")
            }
        };
        results.push((command.clone(), output));
    }

    // Print before disconnecting. The output is the whole point of the
    // run, and a device that hangs up rudely mustn't cost it.
    let prompt = device.base_prompt().to_string();
    {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        if cli.json {
            write_json(&mut out, &cli.host, &prompt, &results)?;
        } else {
            for (command, output) in &results {
                writeln!(out, "\n\n### {command} ###")?;
                writeln!(out, "{}", "-".repeat(80))?;
                writeln!(out, "{output}")?;
            }
        }
        out.flush()?;
    }

    // Everything asked for is already printed, so a bad goodbye is
    // worth a note and nothing more.
    if let Err(error) = device.disconnect().await {
        eprintln!("netshell: warning: the disconnect wasn't clean: {error}");
    }

    if failed > 0 {
        eprintln!("netshell: {failed} of {} commands failed", results.len());
        return Ok(ExitCode::from(EXIT_COMMAND_FAILED));
    }
    Ok(ExitCode::SUCCESS)
}

fn json_string(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len() + 2);
    escaped.push('"');
    for ch in text.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

fn write_json(out: &mut impl Write, host: &str, prompt: &str, results: &[(String, String)]) -> io::Result<()> {
    writeln!(out, "{{")?;
    writeln!(out, "  \"host\": {},", json_string(host))?;
    writeln!(out, "  \"prompt\": {},", json_string(prompt))?;
    writeln!(out, "  \"commands\": [")?;
    for (index, (command, output)) in results.iter().enumerate() {
        let comma = if index + 1 < results.len() { "," } else { "" };
        writeln!(
            out,
            "    {{\"command\": {}, \"output\": {}}}{comma}",
            json_string(command),
            json_string(output)
        )?;
    }
    writeln!(out, "  ]")?;
    writeln!(out, "}}")
}
