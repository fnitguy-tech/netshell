//! The driver: connect, authenticate, open a shell, find the prompt,
//! turn paging off, then send commands and read until the prompt
//! comes back.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use regex::Regex;
use russh::client::{self, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, Disconnect};

use crate::{Error, Platform, Result};

/// What to do with the host key the device presents.
///
/// `AcceptAny` is netmiko's default behaviour (paramiko's
/// `AutoAddPolicy`). Pin a fingerprint when the management network is
/// not trusted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum HostKeyPolicy {
    #[default]
    AcceptAny,
    /// `SHA256:` base64 fingerprint, as `ssh-keygen -l` prints it. The
    /// `SHA256:` prefix is optional.
    Sha256Fingerprint(String),
}

/// How to reach a device.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub platform: Platform,
    /// TCP connect plus SSH handshake.
    pub connect_timeout: Duration,
    /// Default wait for a command's prompt to come back. `show ip bgp`
    /// on a full table can take minutes; raise it per call with
    /// [`Device::send_command_timeout`].
    pub read_timeout: Duration,
    pub host_key: HostKeyPolicy,
}

impl ConnectOptions {
    /// Port 22, 15 s connect timeout, 30 s read timeout, any host key.
    pub fn new(
        host: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        platform: Platform,
    ) -> ConnectOptions {
        ConnectOptions {
            host: host.into(),
            port: 22,
            username: username.into(),
            password: password.into(),
            platform,
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(30),
            host_key: HostKeyPolicy::AcceptAny,
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn host_key(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key = policy;
        self
    }
}

struct Handler {
    host: String,
    policy: HostKeyPolicy,
}

fn fingerprint_of(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
        PublicKeyOrCertificate::Certificate(cert) => cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
    }
}

fn normalize_fingerprint(text: &str) -> String {
    text.trim()
        .trim_start_matches("SHA256:")
        .trim_end_matches('=')
        .to_string()
}

impl client::Handler for Handler {
    type Error = Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        match &self.policy {
            HostKeyPolicy::AcceptAny => Ok(true),
            HostKeyPolicy::Sha256Fingerprint(expected) => {
                let actual = fingerprint_of(key);
                if normalize_fingerprint(&actual) == normalize_fingerprint(expected) {
                    Ok(true)
                } else {
                    Err(Error::HostKeyMismatch {
                        host: self.host.clone(),
                        expected: expected.clone(),
                        actual,
                    })
                }
            }
        }
    }
}

static ANSI: LazyLock<Regex> = LazyLock::new(|| {
    // CSI sequences (colours, cursor moves), charset selection, keypad
    // modes and OSC title strings. Enough for what network CLIs emit.
    Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>]|\x1b\][^\x07]*\x07").unwrap()
});

/// Remove terminal escape sequences.
pub fn strip_ansi(text: &str) -> String {
    ANSI.replace_all(text, "").into_owned()
}

/// `\r\n` and stray `\r` become `\n`; escape sequences are removed.
fn normalize(text: &str) -> String {
    strip_ansi(text).replace("\r\n", "\n").replace('\r', "")
}

/// Turn raw channel output into what netmiko's `send_command` returns:
/// no echoed command, no trailing prompt or prompt preamble, no
/// trailing blank lines.
pub fn clean_output(raw: &str, command: &str, prompt: &Regex, preamble: Option<&Regex>) -> String {
    let text = normalize(raw);
    let mut lines: Vec<&str> = text.split('\n').collect();

    // The echo is normally the first line, sometimes preceded by a
    // blank one or a leftover prompt fragment; look at the first few.
    let command = command.trim();
    if !command.is_empty() {
        let echo_at = lines
            .iter()
            .take(3)
            .position(|line| line.trim() == command || line.trim_end().ends_with(command));
        if let Some(index) = echo_at {
            lines.drain(..=index);
        }
    }

    while let Some(last) = lines.last() {
        let is_preamble = preamble.is_some_and(|re| re.is_match(last.trim_end()));
        if last.trim().is_empty() || prompt.is_match(last) || is_preamble {
            lines.pop();
        } else {
            break;
        }
    }

    lines.join("\n")
}

/// Prompt regex for a base prompt: the base, anything non-blank
/// (`(config)`, `(active)`), a terminator, optional trailing blanks.
fn prompt_regex(base: &str, terminators: &str) -> Result<Regex> {
    Ok(Regex::new(&format!(r"^{}\S*{}\s*$", regex::escape(base), terminators))?)
}

/// `admin@PA-1(active)>` -> `admin@PA-1`; `SW-1#` -> `SW-1`.
fn base_prompt_of(prompt: &str, terminators: &Regex) -> String {
    let trimmed = prompt.trim_end();
    let without_terminator = terminators.replace(trimmed, "");
    let without_mode = Regex::new(r"\([^)]*\)$")
        .unwrap()
        .replace(without_terminator.trim_end(), "");
    without_mode.trim_end().to_string()
}

/// An open, prepared shell on one device.
pub struct Device {
    handle: client::Handle<Handler>,
    channel: Channel<Msg>,
    platform: Platform,
    base_prompt: String,
    prompt: Regex,
    preamble: Option<Regex>,
    read_timeout: Duration,
    pending: Vec<u8>,
}

impl Device {
    /// Connect, authenticate (password, then keyboard-interactive with
    /// the same password), open a shell, find the prompt and run the
    /// platform's preparation commands.
    pub async fn connect(options: ConnectOptions) -> Result<Device> {
        let ConnectOptions {
            host,
            port,
            username,
            password,
            platform,
            connect_timeout,
            read_timeout,
            host_key,
        } = options;

        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let handler = Handler {
            host: host.clone(),
            policy: host_key,
        };

        let connecting = client::connect(config, (host.as_str(), port), handler);
        let mut handle = match tokio::time::timeout(connect_timeout, connecting).await {
            Err(_) => {
                return Err(Error::ConnectTimeout {
                    host,
                    port,
                    timeout: connect_timeout,
                });
            }
            Ok(Err(Error::Ssh(russh::Error::IO(source)))) => return Err(Error::Connect { host, port, source }),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(handle)) => handle,
        };

        let mut authenticated = handle.authenticate_password(&username, &password).await?.success();
        if !authenticated {
            authenticated = keyboard_interactive(&mut handle, &username, &password).await?;
        }
        if !authenticated {
            return Err(Error::AuthFailed { user: username, host });
        }

        let channel = handle.channel_open_session().await?;
        channel.request_pty(false, "vt100", 511, 1000, 0, 0, &[]).await?;
        channel.request_shell(false).await?;

        let terminators = Regex::new(&format!(r"{}\s*$", platform.prompt_terminators))?;
        let preamble = platform.prompt_preamble.map(Regex::new).transpose()?;
        let mut device = Device {
            handle,
            channel,
            prompt: terminators.clone(),
            preamble,
            platform,
            base_prompt: String::new(),
            read_timeout,
            pending: Vec::new(),
        };

        device.login(&terminators).await?;
        device.find_prompt().await?;
        for command in device.platform.preparation {
            device.send_command(command).await?;
        }

        Ok(device)
    }

    /// Wait out the banner and the first prompt; escape an OS shell if
    /// the platform has one.
    async fn login(&mut self, terminators: &Regex) -> Result<()> {
        let login_timeout = self.platform.login_timeout;
        let first_prompt = match &self.platform.shell_escape {
            Some(escape) => Regex::new(&format!(r"(?:{})|(?:{})", terminators.as_str(), escape.shell_prompt))?,
            None => terminators.clone(),
        };

        if self
            .read_until("the login prompt", &first_prompt, login_timeout, true)
            .await
            .is_err()
        {
            // Some devices only print a prompt once they see a key.
            self.write("\n").await?;
            self.read_until("the login prompt", &first_prompt, login_timeout, true)
                .await?;
        }

        if let Some(escape) = self.platform.shell_escape.clone() {
            let shell = Regex::new(escape.shell_prompt)?;
            self.write("\n").await?;
            let text = self.read_until("a prompt", &first_prompt, login_timeout, true).await?;
            if shell.is_match(last_line(&text)) {
                self.write(&format!("{}\n", escape.command)).await?;
                self.read_until("the CLI prompt", terminators, login_timeout, true)
                    .await?;
            }
        }

        Ok(())
    }

    /// Send a bare newline and record the prompt the device answers
    /// with. Called once at connect; call again if you changed mode
    /// and the prompt no longer matches.
    pub async fn find_prompt(&mut self) -> Result<String> {
        let terminators = Regex::new(&format!(r"{}\s*$", self.platform.prompt_terminators))?;
        self.write("\n").await?;
        let text = self
            .read_until("the prompt", &terminators, self.read_timeout, true)
            .await?;

        let prompt = text
            .lines()
            .rev()
            .map(str::trim_end)
            .find(|line| !line.is_empty())
            .ok_or_else(|| Error::NoPrompt(text.clone()))?
            .to_string();

        self.base_prompt = base_prompt_of(&prompt, &terminators);
        if self.base_prompt.is_empty() {
            return Err(Error::NoPrompt(text));
        }
        self.prompt = prompt_regex(&self.base_prompt, self.platform.prompt_terminators)?;
        Ok(prompt)
    }

    /// The prompt minus its terminator and mode suffix, e.g. `SW-1`.
    pub fn base_prompt(&self) -> &str {
        &self.base_prompt
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    /// Send a command and return its output with the echo and the
    /// prompt stripped, using the connection's default read timeout.
    pub async fn send_command(&mut self, command: &str) -> Result<String> {
        self.send_command_timeout(command, self.read_timeout).await
    }

    /// [`Device::send_command`] with an explicit wait for the prompt.
    pub async fn send_command_timeout(&mut self, command: &str, timeout: Duration) -> Result<String> {
        let prompt = self.prompt.clone();
        self.write(&format!("{}\n", command.trim_end())).await?;
        let raw = self
            .read_until(&format!("the prompt after `{command}`"), &prompt, timeout, true)
            .await?;
        Ok(clean_output(&raw, command, &prompt, self.preamble.as_ref()))
    }

    /// Send a command and read until `pattern` matches anywhere in the
    /// output instead of waiting for the prompt (for confirmations and
    /// the like). The raw text is returned, prompt and echo included.
    pub async fn send_command_expect(&mut self, command: &str, pattern: &str, timeout: Duration) -> Result<String> {
        let pattern = Regex::new(pattern)?;
        self.write(&format!("{}\n", command.trim_end())).await?;
        self.read_until(&format!("`{}`", pattern.as_str()), &pattern, timeout, false)
            .await
    }

    /// Write raw text to the shell, no newline added.
    pub async fn write(&mut self, text: &str) -> Result<()> {
        self.channel.data(text.as_bytes()).await?;
        Ok(())
    }

    /// Read until `pattern` matches (the last line only when
    /// `last_line` is set, otherwise anywhere in the buffered text) or
    /// `timeout` elapses. Returns the normalized text consumed.
    pub async fn read_until(
        &mut self,
        what: &str,
        pattern: &Regex,
        timeout: Duration,
        last_line: bool,
    ) -> Result<String> {
        let deadline = Instant::now() + timeout;

        loop {
            if self.matches(pattern, last_line) {
                let raw = std::mem::take(&mut self.pending);
                return Ok(normalize(&String::from_utf8_lossy(&raw)));
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let timed_out = || Error::ReadTimeout {
                what: what.to_string(),
                timeout,
                received: normalize(&String::from_utf8_lossy(&self.pending)),
            };
            if remaining.is_zero() {
                return Err(timed_out());
            }

            match tokio::time::timeout(remaining, self.channel.wait()).await {
                Err(_) => return Err(timed_out()),
                Ok(None) => return Err(Error::ChannelClosed),
                Ok(Some(ChannelMsg::Data { data })) => self.pending.extend_from_slice(&data),
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => self.pending.extend_from_slice(&data),
                Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) => return Err(Error::ChannelClosed),
                Ok(Some(_)) => {}
            }
        }
    }

    fn matches(&self, pattern: &Regex, last_line: bool) -> bool {
        if last_line {
            let start = self.pending.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            let tail = normalize(&String::from_utf8_lossy(&self.pending[start..]));
            pattern.is_match(&tail)
        } else {
            pattern.is_match(&normalize(&String::from_utf8_lossy(&self.pending)))
        }
    }

    /// Close the shell and the SSH session.
    pub async fn disconnect(self) -> Result<()> {
        let _ = self.channel.close().await;
        self.handle.disconnect(Disconnect::ByApplication, "", "English").await?;
        Ok(())
    }
}

fn last_line(text: &str) -> &str {
    text.rsplit('\n').next().unwrap_or("")
}

async fn keyboard_interactive(handle: &mut client::Handle<Handler>, user: &str, password: &str) -> Result<bool> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| password.to_string()).collect();
                response = handle.authenticate_keyboard_interactive_respond(answers).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(base: &str) -> Regex {
        prompt_regex(base, "[>#]").unwrap()
    }

    #[test]
    fn strips_echo_prompt_and_trailing_blanks() {
        let raw = "show version\r\nArista DCS-7050\r\nSoftware image version: 4.30.1F\r\n\r\nSW-1#";
        assert_eq!(
            clean_output(raw, "show version", &prompt("SW-1"), None),
            "Arista DCS-7050\nSoftware image version: 4.30.1F"
        );
    }

    #[test]
    fn junos_status_line_before_prompt_is_stripped() {
        let preamble = Regex::new(Platform::juniper_junos().prompt_preamble.unwrap()).unwrap();
        let raw = "show version\r\nJunos: 21.4R3\r\n\r\n{master:0}\r\nops@JUN-1> ";
        assert_eq!(
            clean_output(raw, "show version", &prompt("ops@JUN-1"), Some(&preamble)),
            "Junos: 21.4R3"
        );
    }

    #[test]
    fn keeps_output_lines_that_merely_contain_the_prompt_text() {
        let raw = "show running-config\r\nhostname SW-1\r\n!\r\nSW-1#";
        assert_eq!(
            clean_output(raw, "show running-config", &prompt("SW-1"), None),
            "hostname SW-1\n!"
        );
    }

    #[test]
    fn config_and_ha_mode_prompts_match() {
        let re = prompt("admin@PA-1");
        assert!(re.is_match("admin@PA-1(active)> "));
        assert!(re.is_match("admin@PA-1(passive)>"));
        assert!(re.is_match("admin@PA-1# "));
        assert!(!re.is_match("admin@PA-1 is the hostname"));
    }

    #[test]
    fn base_prompt_drops_terminator_and_mode() {
        let terminators = Regex::new(r"[>#]\s*$").unwrap();
        assert_eq!(base_prompt_of("SW-1# ", &terminators), "SW-1");
        assert_eq!(base_prompt_of("admin@PA-1(active)>", &terminators), "admin@PA-1");
        assert_eq!(
            base_prompt_of("RP/0/RP0/CPU0:XR-1#", &terminators),
            "RP/0/RP0/CPU0:XR-1"
        );
        assert_eq!(base_prompt_of("user@JUN-1> ", &terminators), "user@JUN-1");
    }

    #[test]
    fn ansi_sequences_are_removed() {
        assert_eq!(strip_ansi("\x1b[?7hSW-1#\x1b[0m"), "SW-1#");
        assert_eq!(normalize("a\r\nb\rc\n"), "a\nbc\n");
    }

    #[test]
    fn fingerprints_compare_without_prefix_or_padding() {
        assert_eq!(normalize_fingerprint("SHA256:abc="), normalize_fingerprint(" abc"));
    }
}
