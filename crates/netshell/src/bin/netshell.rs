//! Command-line front end: run show commands on one device and print
//! the output, either as a capture file (the `### command ###` section
//! format prepost-check reads) or as JSON.
//!
//! The password is never a flag. It is read from the environment
//! variable named by `--password-env`, or prompted for.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use netshell::{ConnectOptions, Device, HostKeyPolicy, Platform};

#[derive(Parser)]
#[command(
    name = "netshell",
    version,
    about = "Run show commands on a network device over SSH",
    after_help = "Platforms: arista_eos, cisco_ios (cisco_xe), cisco_nxos, cisco_xr, juniper_junos, paloalto_panos"
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

    /// Seconds to wait for each command's output
    #[arg(long, default_value_t = 60)]
    read_timeout: u64,

    /// Seconds to wait for the TCP connect and SSH handshake
    #[arg(long, default_value_t = 15)]
    connect_timeout: u64,

    /// Only connect if the host key has this SHA256 fingerprint
    #[arg(long, value_name = "SHA256:...")]
    fingerprint: Option<String>,

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
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("netshell: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let platform = Platform::by_name(&cli.platform)?;

    let password = match &cli.password_env {
        Some(var) => std::env::var(var).map_err(|_| format!("environment variable {var} is not set"))?,
        None => rpassword::prompt_password(format!("Password for {}@{}: ", cli.username, cli.host))?,
    };

    let mut options = ConnectOptions::new(&cli.host, &cli.username, password, platform)
        .port(cli.port)
        .connect_timeout(Duration::from_secs(cli.connect_timeout))
        .read_timeout(Duration::from_secs(cli.read_timeout));
    if let Some(fingerprint) = cli.fingerprint {
        options = options.host_key(HostKeyPolicy::Sha256Fingerprint(fingerprint));
    }

    let mut device = Device::connect(options).await?;

    let mut results: Vec<(String, String)> = Vec::with_capacity(cli.commands.len());
    for command in &cli.commands {
        let output = match device.send_command(command).await {
            Ok(output) => output,
            Err(error) => format!("COMMAND FAILED:\n{error}"),
        };
        results.push((command.clone(), output));
    }

    let prompt = device.base_prompt().to_string();
    device.disconnect().await?;

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
    Ok(())
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
