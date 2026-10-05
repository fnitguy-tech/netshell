//! The driver: connect, check the host key, authenticate, open a
//! shell, find the prompt, turn paging off, then send commands and
//! read until the prompt comes back.

use std::borrow::Cow;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use regex::Regex;
use russh::client::{self, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{AlgorithmKind, Channel, ChannelMsg, Disconnect, MethodKind, Preferred, cipher, kex, mac};
use zeroize::Zeroizing;

use crate::known_hosts::{self, Verdict};
use crate::platform::Enable;
use crate::{Error, Platform, Result, Secret};

/// How long a prompt may sit unanswered by a command echo before it's
/// accepted anyway. See [`Device::send_command`].
const ECHO_FALLBACK_QUIET: Duration = Duration::from_secs(2);

/// The echo is the first thing a device sends back, so only the start
/// of the output is searched for it. This keeps a 10 MB
/// `show ip bgp` from being rescanned on every packet.
const ECHO_SEARCH_WINDOW: usize = 16 * 1024;

/// A keyboard-interactive login gets this many questions. A normal
/// login is one (`Password:`), sometimes followed by an empty one.
const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 3;

/// How many times prompt discovery re-asks before giving up on a
/// prompt that keeps changing.
const PROMPT_PROBES: usize = 4;

/// What to do with the host key the device presents.
///
/// The default, [`HostKeyPolicy::KnownHosts`], is what `ssh` does:
/// remember the key on first contact, and refuse to connect if it
/// ever changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostKeyPolicy {
    /// Trust on first use. A new device's key is written to the
    /// known-hosts file. After that, a different key is refused with
    /// [`Error::HostKeyChanged`].
    #[default]
    KnownHosts,
    /// Like `KnownHosts`, but a changed key replaces the stored one.
    /// Use it once, after you replaced or re-imaged a device. The
    /// CLI's `--accept-new-host-key` is this.
    ReplaceKnownHost,
    /// `SHA256:` base64 fingerprint, as `ssh-keygen -l` prints it. The
    /// `SHA256:` prefix is optional. The known-hosts file isn't read
    /// or written.
    Sha256Fingerprint(String),
    /// Accept any key and remember nothing. Anyone on the path can
    /// pose as the device and read the password, so choose this only
    /// for a lab. The CLI's `--insecure-accept-any-host-key` is this.
    AcceptAny,
}

/// How to reach a device.
///
/// Build one with [`ConnectOptions::new`] and the setter methods. The
/// struct is `#[non_exhaustive]`, so a new option in a later release
/// doesn't break your build. `{:?}` prints `<redacted>` for the
/// password and the enable secret.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Secret,
    /// See [`ConnectOptions::enable_secret`].
    pub enable_secret: Option<Secret>,
    /// See [`ConnectOptions::allow_user_mode`].
    pub allow_user_mode: bool,
    pub platform: Platform,
    /// Applies to each setup step on its own: the TCP connect plus
    /// SSH handshake, authentication, and opening the shell.
    pub connect_timeout: Duration,
    /// Default wait for a command's prompt to come back. `show ip bgp`
    /// on a full table can take minutes; raise it per call with
    /// [`Device::send_command_timeout`].
    pub read_timeout: Duration,
    /// How long the device may take to accept what's sent to it.
    pub write_timeout: Duration,
    /// See [`ConnectOptions::settle`].
    pub settle: Duration,
    pub host_key: HostKeyPolicy,
    /// See [`ConnectOptions::known_hosts`].
    pub known_hosts: Option<PathBuf>,
    /// See [`ConnectOptions::legacy_algorithms`].
    pub legacy_algorithms: bool,
}

impl ConnectOptions {
    /// Port 22, 15 s connect timeout, 30 s read timeout, 10 s write
    /// timeout, host keys checked against the known-hosts file,
    /// modern algorithms only.
    ///
    /// The password can be a `&str`, a `String`, or a [`Secret`].
    pub fn new(
        host: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<Secret>,
        platform: Platform,
    ) -> ConnectOptions {
        ConnectOptions {
            host: host.into(),
            port: 22,
            username: username.into(),
            password: password.into(),
            enable_secret: None,
            allow_user_mode: false,
            platform,
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            settle: Duration::from_millis(300),
            host_key: HostKeyPolicy::KnownHosts,
            known_hosts: None,
            legacy_algorithms: false,
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

    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// How long the channel must stay quiet before the login banner
    /// counts as finished and a prompt counts as stable. Default
    /// 300 ms. Raise it for a slow link, such as a satellite hop,
    /// where a banner can pause mid-way for longer than that.
    pub fn settle(mut self, settle: Duration) -> Self {
        self.settle = settle;
        self
    }

    pub fn host_key(mut self, policy: HostKeyPolicy) -> Self {
        self.host_key = policy;
        self
    }

    /// Use this known-hosts file instead of the default. Without it,
    /// the file is the one named by the `NETSHELL_KNOWN_HOSTS`
    /// environment variable, or else
    /// [`crate::default_known_hosts_path`].
    pub fn known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts = Some(path.into());
        self
    }

    /// Also offer the old algorithms: SHA-1 key exchange
    /// (`diffie-hellman-group1-sha1`, `group14-sha1`, group exchange
    /// with SHA-1), CBC ciphers including `3des-cbc`, and `hmac-sha1`.
    /// They're off by default because each has known weaknesses. Turn
    /// them on for a device that offers nothing newer; the modern
    /// algorithms still go first, so a current device is unaffected.
    pub fn legacy_algorithms(mut self, legacy: bool) -> Self {
        self.legacy_algorithms = legacy;
        self
    }

    /// The secret for `enable`. With it, a login that lands in user
    /// mode (`RTR-1>`) on Cisco IOS, IOS-XE, or Arista EOS is taken to
    /// privileged mode (`RTR-1#`) before any command runs. Pass an
    /// empty string when `enable` asks for no password. It's ignored
    /// on platforms with no enable mode, so one inventory-wide secret
    /// is fine.
    pub fn enable_secret(mut self, secret: impl Into<Secret>) -> Self {
        self.enable_secret = Some(secret.into());
        self
    }

    /// Stay in user mode when the login lands there and no enable
    /// secret was given. Off by default: the connect fails with
    /// [`Error::EnableRequired`] instead, because a capture taken in
    /// user mode is missing `show running-config` and you'd only find
    /// out later.
    pub fn allow_user_mode(mut self, allow: bool) -> Self {
        self.allow_user_mode = allow;
        self
    }
}

struct Handler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts: Option<PathBuf>,
}

/// `("ssh-ed25519", "SHA256:nThbg6kX...")` for the key a device
/// presented.
fn describe_key(key: &PublicKeyOrCertificate) -> (String, String) {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => (
            key.algorithm().to_string(),
            key.fingerprint(HashAlg::Sha256).to_string(),
        ),
        PublicKeyOrCertificate::Certificate(cert) => (
            cert.public_key().algorithm().to_string(),
            cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
        ),
    }
}

impl client::Handler for Handler {
    type Error = Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        let (algorithm, fingerprint) = describe_key(key);
        let replace = match &self.policy {
            HostKeyPolicy::AcceptAny => return Ok(true),
            HostKeyPolicy::Sha256Fingerprint(expected) => {
                return if known_hosts::same_fingerprint(&fingerprint, expected) {
                    Ok(true)
                } else {
                    Err(Error::HostKeyMismatch {
                        host: self.host.clone(),
                        expected: expected.clone(),
                        actual: fingerprint,
                    })
                };
            }
            HostKeyPolicy::KnownHosts => false,
            HostKeyPolicy::ReplaceKnownHost => true,
        };

        let path = known_hosts::resolve_path(self.known_hosts.as_deref()).map_err(|source| Error::KnownHosts {
            path: PathBuf::from("known_hosts"),
            source,
        })?;
        let id = known_hosts::host_id(&self.host, self.port);
        let offered = format!("{algorithm} {fingerprint}");

        // File I/O and a file lock: keep them off the async threads.
        let file = path.clone();
        let verdict = tokio::task::spawn_blocking(move || {
            known_hosts::check_and_record(&file, &id, &algorithm, &fingerprint, replace)
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|verdict| verdict)
        .map_err(|source| Error::KnownHosts {
            path: path.clone(),
            source,
        })?;

        match verdict {
            Verdict::Recorded | Verdict::Known | Verdict::Replaced => Ok(true),
            Verdict::Changed { stored, line } => Err(Error::HostKeyChanged {
                host: self.host.clone(),
                port: self.port,
                stored,
                offered,
                file: path,
                line,
            }),
        }
    }
}

const MODERN_KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP521,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP256,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
];

/// Everything that hashes the key exchange with SHA-1.
const LEGACY_KEX: &[kex::Name] = &[kex::DH_G14_SHA1, kex::DH_GEX_SHA1, kex::DH_G1_SHA1];

/// Not algorithms: markers that switch on protocol extensions. They
/// go last in the list either way.
const KEX_EXTENSIONS: &[kex::Name] = &[
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

const MODERN_CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
];

const LEGACY_CIPHERS: &[cipher::Name] = &[
    cipher::AES_256_CBC,
    cipher::AES_192_CBC,
    cipher::AES_128_CBC,
    cipher::TRIPLE_DES_CBC,
];

const MODERN_MACS: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

const LEGACY_MACS: &[mac::Name] = &[mac::HMAC_SHA1_ETM, mac::HMAC_SHA1];

/// The algorithms offered to a device by default, strongest first.
///
/// This is close to what a current OpenSSH client offers: Curve25519
/// and NIST-curve key exchange, Diffie-Hellman with SHA-2, ChaCha20,
/// AES-GCM and AES-CTR, and HMAC-SHA-2. A switch or firewall running
/// software from the last several years speaks at least one of each.
///
/// Anything built on SHA-1 or CBC is left out. See
/// [`legacy_algorithms`] for devices that have nothing else.
pub fn preferred_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Owned([MODERN_KEX, KEX_EXTENSIONS].concat()),
        cipher: Cow::Borrowed(MODERN_CIPHERS),
        mac: Cow::Borrowed(MODERN_MACS),
        ..Preferred::DEFAULT
    }
}

/// [`preferred_algorithms`] plus the old ones, which is the set
/// [`ConnectOptions::legacy_algorithms`] switches on.
///
/// The additions are `diffie-hellman-group14-sha1`,
/// `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1`,
/// `aes256-cbc`, `aes192-cbc`, `aes128-cbc`, `3des-cbc`,
/// `hmac-sha1-etm@openssh.com`, and `hmac-sha1`. An old Cisco IOS 12
/// image, for example, offers only `aes128-cbc` and `3des-cbc` with
/// `hmac-sha1`. The device picks the first entry on our list that it
/// supports, and the modern ones are listed first, so the old entries
/// only matter when nothing better is on offer.
pub fn legacy_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Owned([MODERN_KEX, LEGACY_KEX, KEX_EXTENSIONS].concat()),
        cipher: Cow::Owned([MODERN_CIPHERS, LEGACY_CIPHERS].concat()),
        mac: Cow::Owned([MODERN_MACS, LEGACY_MACS].concat()),
        ..Preferred::DEFAULT
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

fn normalize_bytes(raw: &[u8]) -> String {
    normalize(&String::from_utf8_lossy(raw))
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

    strip_tail(lines, prompt, preamble)
}

/// Drop the trailing prompt, the status line before it, and blank
/// lines.
fn strip_tail(mut lines: Vec<&str>, prompt: &Regex, preamble: Option<&Regex>) -> String {
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

/// Where the command's own output starts: the offset just past the
/// line that echoes `command`. `None` until that whole line, newline
/// included, has arrived.
///
/// The echo line is `SW-1#show version` on most devices and a bare
/// `show version` on some, so the test is "ends with the command".
fn find_echo(pending: &[u8], command: &str) -> Option<usize> {
    let window = &pending[..pending.len().min(ECHO_SEARCH_WINDOW)];
    let mut start = 0;
    while let Some(offset) = window[start..].iter().position(|&byte| byte == b'\n') {
        let end = start + offset + 1;
        if normalize_bytes(&window[start..end]).trim_end().ends_with(command) {
            return Some(end);
        }
        start = end;
    }
    None
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
    host: String,
    platform: Platform,
    base_prompt: String,
    prompt: Regex,
    preamble: Option<Regex>,
    read_timeout: Duration,
    write_timeout: Duration,
    settle: Duration,
    pending: Vec<u8>,
    poisoned: bool,
    warnings: Vec<String>,
}

impl Device {
    /// Connect, check the host key, authenticate (password, or
    /// keyboard-interactive when that's all the device offers), open a
    /// shell, find the prompt, enter enable mode if asked, and run the
    /// platform's preparation commands.
    ///
    /// Every step has a timeout, so a device that accepts the TCP
    /// connection and then goes silent costs `connect_timeout`, not
    /// forever.
    pub async fn connect(options: ConnectOptions) -> Result<Device> {
        let ConnectOptions {
            host,
            port,
            username,
            password,
            enable_secret,
            allow_user_mode,
            platform,
            connect_timeout,
            read_timeout,
            write_timeout,
            settle,
            host_key,
            known_hosts,
            legacy_algorithms: legacy,
        } = options;

        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            preferred: if legacy {
                legacy_algorithms()
            } else {
                preferred_algorithms()
            },
            ..Default::default()
        });
        let handler = Handler {
            host: host.clone(),
            port,
            policy: host_key,
            known_hosts,
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
            Ok(Err(Error::Ssh(russh::Error::NoCommonAlgo { kind, theirs, .. }))) => {
                return Err(Error::NoCommonAlgorithm {
                    host,
                    kind: algorithm_kind(&kind).to_string(),
                    offered: theirs,
                    legacy_tried: legacy,
                });
            }
            Ok(Err(Error::Ssh(source))) => return Err(Error::Session { host, source }),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(handle)) => handle,
        };

        authenticate(&mut handle, &host, &username, &password, connect_timeout).await?;

        let channel = setup_step(
            &host,
            "opening the session channel",
            connect_timeout,
            handle.channel_open_session(),
        )
        .await?;
        setup_step(
            &host,
            "the terminal request",
            connect_timeout,
            channel.request_pty(false, "vt100", 511, 1000, 0, 0, &[]),
        )
        .await?;
        setup_step(
            &host,
            "the shell request",
            connect_timeout,
            channel.request_shell(false),
        )
        .await?;

        let terminators = Regex::new(&format!(r"{}\s*$", platform.prompt_terminators))?;
        let preamble = platform.prompt_preamble.map(Regex::new).transpose()?;
        let login_timeout = platform.login_timeout;
        let mut device = Device {
            handle,
            channel,
            host,
            prompt: terminators.clone(),
            preamble,
            platform,
            base_prompt: String::new(),
            read_timeout,
            write_timeout,
            settle,
            pending: Vec::new(),
            poisoned: false,
            warnings: Vec::new(),
        };

        device.login(&terminators).await?;
        let prompt = device.discover_prompt(login_timeout).await?;

        if let Some(enable) = device.platform.enable.clone()
            && Regex::new(enable.user_prompt)?.is_match(&prompt)
        {
            match &enable_secret {
                Some(secret) => device.enter_enable(&enable, secret).await?,
                None if allow_user_mode => {}
                None => {
                    return Err(Error::EnableRequired {
                        host: device.host,
                        prompt,
                    });
                }
            }
        }

        for step in device.platform.preparation {
            let output = device.send_command(step.command).await?;
            let Some(complaint) = device.platform.error_in(&output) else {
                continue;
            };
            if step.required {
                return Err(Error::PreparationFailed {
                    host: device.host,
                    command: step.command.to_string(),
                    output,
                });
            }
            device
                .warnings
                .push(format!("`{}` was rejected: {}", step.command, complaint.trim()));
        }

        Ok(device)
    }

    /// Wait out the banner; escape an OS shell if the platform has one.
    ///
    /// Nothing here decides what the prompt is. A banner line can end
    /// in `#` or `>` and look exactly like one, so the banner is only
    /// drained: read until the channel has been quiet for the settle
    /// period, then thrown away. [`Device::discover_prompt`] finds the
    /// prompt afterwards by asking for it.
    async fn login(&mut self, terminators: &Regex) -> Result<()> {
        let login_timeout = self.platform.login_timeout;
        self.drain_until_quiet(login_timeout).await?;

        if let Some(escape) = self.platform.shell_escape.clone() {
            let shell = Regex::new(escape.shell_prompt)?;
            let either = Regex::new(&format!(r"(?:{})|(?:{})", terminators.as_str(), escape.shell_prompt))?;
            self.write_raw("\n").await?;
            let text = self.read_settled("the login prompt", &either, login_timeout).await?;
            if shell.is_match(last_line(&text)) {
                self.write_raw(&format!("{}\n", escape.command)).await?;
                self.read_settled("the CLI prompt", terminators, login_timeout).await?;
            }
        }

        Ok(())
    }

    /// Send a bare newline and record the prompt the device answers
    /// with. Called once at connect; call again if you changed mode
    /// and the prompt no longer matches.
    pub async fn find_prompt(&mut self) -> Result<String> {
        self.check_usable()?;
        self.discover_prompt(self.read_timeout).await
    }

    /// Ask for the prompt until two answers in a row agree.
    ///
    /// One answer isn't proof. Say a slow device prints the last
    /// banner line, `# Authorised access only #`, just after the
    /// newline went out: that line ends in `#` and would be taken as
    /// the prompt. Asked again, the device answers `SW-1#`, the two
    /// differ, and a third answer of `SW-1#` settles it.
    ///
    /// Each answer is read until the channel is quiet, so a device
    /// that was slow to start and answers two newlines at once leaves
    /// nothing behind to be mistaken for a command's output.
    async fn discover_prompt(&mut self, timeout: Duration) -> Result<String> {
        let terminators = Regex::new(&format!(r"{}\s*$", self.platform.prompt_terminators))?;
        let mut previous = self.probe_prompt(&terminators, timeout).await?;
        for _ in 0..PROMPT_PROBES {
            let prompt = self.probe_prompt(&terminators, timeout).await?;
            if prompt != previous {
                previous = prompt;
                continue;
            }

            let base_prompt = base_prompt_of(&prompt, &terminators);
            if base_prompt.is_empty() {
                break;
            }
            self.prompt = prompt_regex(&base_prompt, self.platform.prompt_terminators)?;
            self.base_prompt = base_prompt;
            return Ok(prompt);
        }
        Err(Error::NoPrompt {
            host: self.host.clone(),
            received: previous,
        })
    }

    async fn probe_prompt(&mut self, terminators: &Regex, timeout: Duration) -> Result<String> {
        self.discard_arrived().await;
        self.write_raw("\n").await?;
        let text = self.read_settled("the prompt", terminators, timeout).await?;
        Ok(last_line(&text).trim_end().to_string())
    }

    /// `enable`, then the secret if the device asks for one.
    async fn enter_enable(&mut self, enable: &Enable, secret: &Secret) -> Result<()> {
        let failed = |device: &Device| Error::EnableFailed {
            host: device.host.clone(),
        };
        let password_prompt = Regex::new(enable.password_prompt)?;
        let user_prompt = Regex::new(enable.user_prompt)?;
        let either = Regex::new(&format!(r"(?:{})|(?:{})", self.prompt.as_str(), enable.password_prompt))?;
        let timeout = self.read_timeout;

        self.discard_arrived().await;
        self.write_raw(&format!("{}\n", enable.command)).await?;
        let mut text = self.read_raw("the answer to `enable`", &either, timeout, true).await?;

        if password_prompt.is_match(last_line(&text)) {
            // The line is built in a buffer that's wiped on drop.
            let line = Zeroizing::new(format!("{}\n", secret.expose()));
            self.write_raw(&line).await?;
            // If this read times out, the text received could hold the
            // secret: a device that wasn't really at a password prompt
            // echoes what it's sent. So the timeout's text is dropped.
            text = match self
                .read_raw("the prompt after the enable secret", &either, timeout, true)
                .await
            {
                Err(Error::ReadTimeout { .. }) => return Err(failed(self)),
                other => other?,
            };
        }

        // IOS asks `Password:` again after a wrong secret. EOS prints
        // `% Bad secret` and goes back to `SW-1>`.
        let landed = last_line(&text);
        if password_prompt.is_match(landed) || user_prompt.is_match(landed) {
            return Err(failed(self));
        }
        self.discover_prompt(timeout).await?;
        Ok(())
    }

    /// The prompt minus its terminator and mode suffix, e.g. `SW-1`.
    pub fn base_prompt(&self) -> &str {
        &self.base_prompt
    }

    pub fn platform(&self) -> &Platform {
        &self.platform
    }

    /// The host this device was connected with, as given in
    /// [`ConnectOptions`].
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Optional preparation commands the device rejected at connect,
    /// e.g. ``"`terminal width 511` was rejected: % Invalid input"``.
    /// The session works, but output may be wrapped. A rejected
    /// paging-off command is never a warning: it fails the connect.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// True after a read or write timed out. A poisoned session
    /// refuses to send anything more: every call returns
    /// [`Error::SessionPoisoned`]. Disconnect and connect again.
    ///
    /// Here's why. `show tech-support` times out after 30 s, but the
    /// device keeps printing it. If the next command, `show version`,
    /// went out now, the rest of the tech-support dump would come
    /// back as its answer, and every later answer would be one
    /// command late.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_usable(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::SessionPoisoned {
                host: self.host.clone(),
            });
        }
        Ok(())
    }

    /// Send a command and return its output with the echo and the
    /// prompt stripped, using the connection's default read timeout.
    ///
    /// The answer starts at the command's echo. A prompt only ends
    /// the read once the device has echoed the command back, the same
    /// check netmiko makes. So a prompt left over from something
    /// earlier is never taken as this command's answer.
    ///
    /// Some devices don't echo. For those there's a fallback: a prompt
    /// with no echo is accepted after the channel has been quiet for
    /// 2 seconds. Such a device works, but each command takes 2
    /// seconds longer, and the read timeout must be above 2 seconds.
    pub async fn send_command(&mut self, command: &str) -> Result<String> {
        self.send_command_timeout(command, self.read_timeout).await
    }

    /// [`Device::send_command`] with an explicit wait for the prompt.
    pub async fn send_command_timeout(&mut self, command: &str, timeout: Duration) -> Result<String> {
        self.check_usable()?;
        // Whatever is already here was printed before this command
        // went out, so it can't be part of the answer.
        self.discard_arrived().await;
        self.write_raw(&format!("{}\n", command.trim_end())).await?;
        self.read_command(command.trim(), timeout).await
    }

    async fn read_command(&mut self, command: &str, timeout: Duration) -> Result<String> {
        let prompt = self.prompt.clone();
        let deadline = Instant::now() + timeout;
        let mut last_data = Instant::now();
        // An empty command has no echo to wait for.
        let mut echo_end = command.is_empty().then_some(0);

        loop {
            if echo_end.is_none() {
                echo_end = find_echo(&self.pending, command);
            }
            let at_prompt = self.matches(&prompt, true);
            if at_prompt && let Some(start) = echo_end {
                let raw = std::mem::take(&mut self.pending);
                let text = normalize_bytes(&raw[start..]);
                return Ok(strip_tail(text.split('\n').collect(), &prompt, self.preamble.as_ref()));
            }

            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(self.timed_out(&format!("the prompt after `{command}`"), timeout));
            }
            // At a prompt with no echo: wait only until the quiet
            // period is up, then decide.
            let wait = if at_prompt {
                remaining.min(ECHO_FALLBACK_QUIET.saturating_sub(now.duration_since(last_data)))
            } else {
                remaining
            };
            if self.receive(wait).await? {
                last_data = Instant::now();
            } else if at_prompt && last_data.elapsed() >= ECHO_FALLBACK_QUIET {
                let raw = std::mem::take(&mut self.pending);
                return Ok(clean_output(
                    &String::from_utf8_lossy(&raw),
                    command,
                    &prompt,
                    self.preamble.as_ref(),
                ));
            }
        }
    }

    /// Send a command and read until `pattern` matches anywhere in the
    /// output instead of waiting for the prompt (for confirmations and
    /// the like). The raw text is returned, prompt and echo included.
    pub async fn send_command_expect(&mut self, command: &str, pattern: &str, timeout: Duration) -> Result<String> {
        self.check_usable()?;
        let pattern = Regex::new(pattern)?;
        self.discard_arrived().await;
        self.write_raw(&format!("{}\n", command.trim_end())).await?;
        self.read_raw(&format!("`{}`", pattern.as_str()), &pattern, timeout, false)
            .await
    }

    /// Write raw text to the shell, no newline added.
    pub async fn write(&mut self, text: &str) -> Result<()> {
        self.check_usable()?;
        self.write_raw(text).await
    }

    async fn write_raw(&mut self, text: &str) -> Result<()> {
        match tokio::time::timeout(self.write_timeout, self.channel.data(text.as_bytes())).await {
            Err(_) => {
                // Part of the text may have gone out. There's no
                // telling what the device will answer now.
                self.poisoned = true;
                Err(Error::WriteTimeout {
                    host: self.host.clone(),
                    timeout: self.write_timeout,
                })
            }
            Ok(Err(source)) => Err(Error::Session {
                host: self.host.clone(),
                source,
            }),
            Ok(Ok(())) => Ok(()),
        }
    }

    /// Read until `pattern` matches (the last line only when
    /// `last_line` is set, otherwise anywhere in the buffered text) or
    /// `timeout` elapses. Returns the normalized text consumed.
    ///
    /// A timeout here poisons the session like any other: see
    /// [`Device::is_poisoned`].
    pub async fn read_until(
        &mut self,
        what: &str,
        pattern: &Regex,
        timeout: Duration,
        last_line: bool,
    ) -> Result<String> {
        self.check_usable()?;
        self.read_raw(what, pattern, timeout, last_line).await
    }

    async fn read_raw(&mut self, what: &str, pattern: &Regex, timeout: Duration, last_line: bool) -> Result<String> {
        let deadline = Instant::now() + timeout;

        loop {
            if self.matches(pattern, last_line) {
                return Ok(normalize_bytes(&std::mem::take(&mut self.pending)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || !self.receive(remaining).await? {
                return Err(self.timed_out(what, timeout));
            }
        }
    }

    /// Read until the last line matches `pattern` and nothing more
    /// has arrived for the settle period. "Matches" alone isn't
    /// enough during login, where a device may still be mid-banner or
    /// about to print a second prompt.
    async fn read_settled(&mut self, what: &str, pattern: &Regex, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;

        loop {
            let matched = self.matches(pattern, true);
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(self.timed_out(what, timeout));
            }
            let wait = if matched { remaining.min(self.settle) } else { remaining };
            if !self.receive(wait).await? {
                if matched {
                    return Ok(normalize_bytes(&std::mem::take(&mut self.pending)));
                }
                return Err(self.timed_out(what, timeout));
            }
        }
    }

    /// Read and discard until the channel has been quiet for the
    /// settle period. Waits up to `first_wait` for the first byte, and
    /// no longer than that in total. A device that says nothing at
    /// all is fine: some only print a prompt once they see a key.
    async fn drain_until_quiet(&mut self, first_wait: Duration) -> Result<()> {
        let deadline = Instant::now() + first_wait;
        let mut wait = first_wait;
        while !wait.is_zero() && self.receive(wait).await? {
            wait = deadline.saturating_duration_since(Instant::now()).min(self.settle);
        }
        self.pending.clear();
        Ok(())
    }

    /// Throw away what has already arrived, without waiting. A closed
    /// channel isn't reported here; the write that follows will fail
    /// and say so.
    async fn discard_arrived(&mut self) {
        while let Ok(true) = self.receive(Duration::ZERO).await {}
        self.pending.clear();
    }

    /// Wait up to `wait` for output and add it to `pending`. `true`
    /// when data arrived, `false` when the time ran out.
    async fn receive(&mut self, wait: Duration) -> Result<bool> {
        let deadline = Instant::now() + wait;
        let closed = |host: &str| Error::ChannelClosed { host: host.to_string() };

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, self.channel.wait()).await {
                Err(_) => return Ok(false),
                Ok(None) | Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) => return Err(closed(&self.host)),
                Ok(Some(ChannelMsg::Data { data })) => {
                    self.pending.extend_from_slice(&data);
                    return Ok(true);
                }
                Ok(Some(ChannelMsg::ExtendedData { data, .. })) => {
                    self.pending.extend_from_slice(&data);
                    return Ok(true);
                }
                Ok(Some(_)) => {}
            }
        }
    }

    /// Build the timeout error and poison the session.
    fn timed_out(&mut self, what: &str, timeout: Duration) -> Error {
        self.poisoned = true;
        Error::ReadTimeout {
            host: self.host.clone(),
            what: what.to_string(),
            timeout,
            received: normalize_bytes(&self.pending),
        }
    }

    fn matches(&self, pattern: &Regex, last_line: bool) -> bool {
        if last_line {
            let start = self.pending.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            pattern.is_match(&normalize_bytes(&self.pending[start..]))
        } else {
            pattern.is_match(&normalize_bytes(&self.pending))
        }
    }

    /// Close the shell and the SSH session.
    pub async fn disconnect(self) -> Result<()> {
        let _ = tokio::time::timeout(self.write_timeout, self.channel.close()).await;
        let goodbye = self.handle.disconnect(Disconnect::ByApplication, "", "English");
        match tokio::time::timeout(self.write_timeout, goodbye).await {
            Err(_) => Err(Error::WriteTimeout {
                host: self.host,
                timeout: self.write_timeout,
            }),
            Ok(Err(source)) => Err(Error::Session {
                host: self.host,
                source,
            }),
            Ok(Ok(())) => Ok(()),
        }
    }
}

fn last_line(text: &str) -> &str {
    text.rsplit('\n').next().unwrap_or("")
}

fn algorithm_kind(kind: &AlgorithmKind) -> &'static str {
    match kind {
        AlgorithmKind::Kex => "key exchange",
        AlgorithmKind::Key => "host key",
        AlgorithmKind::Cipher => "cipher",
        AlgorithmKind::Compression => "compression",
        AlgorithmKind::Mac => "MAC",
    }
}

/// Run one session-setup step under `timeout`, and put the host on
/// whatever goes wrong.
async fn setup_step<T>(
    host: &str,
    step: &'static str,
    timeout: Duration,
    work: impl Future<Output = std::result::Result<T, russh::Error>>,
) -> Result<T> {
    match tokio::time::timeout(timeout, work).await {
        Err(_) => Err(Error::SetupTimeout {
            host: host.to_string(),
            step,
            timeout,
        }),
        Ok(Err(source)) => Err(Error::Session {
            host: host.to_string(),
            source,
        }),
        Ok(Ok(value)) => Ok(value),
    }
}

/// Log in with the password, spending as few attempts as possible.
///
/// Devices lock accounts after a few failures (three is common), so a
/// wrong password must cost one attempt, not two. The plan:
///
/// 1. Ask which methods the device accepts, with a `none` request.
///    Every SSH client starts this way and it doesn't count as a
///    failure.
/// 2. If `password` is on the list, try it and stop there. A wrong
///    password would be just as wrong over keyboard-interactive.
/// 3. Otherwise, if `keyboard-interactive` is on the list, use that.
///    This is the Cisco case: some images offer only that method.
///
/// A device that answers the `none` request with an empty list gets
/// the password tried blind, then keyboard-interactive if its answer
/// lists it.
async fn authenticate(
    handle: &mut client::Handle<Handler>,
    host: &str,
    user: &str,
    password: &Secret,
    timeout: Duration,
) -> Result<()> {
    const STEP: &str = "authentication";
    let failed = |tried: &str| Error::AuthFailed {
        user: user.to_string(),
        host: host.to_string(),
        tried: tried.to_string(),
    };

    let mut offered = match setup_step(host, STEP, timeout, handle.authenticate_none(user)).await? {
        client::AuthResult::Success => return Ok(()),
        client::AuthResult::Failure { remaining_methods, .. } => remaining_methods,
    };

    let mut tried = Vec::new();
    let password_offered = offered.contains(&MethodKind::Password);
    if password_offered || offered.is_empty() {
        tried.push("password");
        let attempt = handle.authenticate_password(user, password.expose());
        match setup_step(host, STEP, timeout, attempt).await? {
            client::AuthResult::Success => return Ok(()),
            client::AuthResult::Failure { .. } if password_offered => return Err(failed("password")),
            client::AuthResult::Failure { remaining_methods, .. } => offered = remaining_methods,
        }
    }

    if offered.contains(&MethodKind::KeyboardInteractive) {
        tried.push("keyboard-interactive");
        if keyboard_interactive(handle, host, user, password, timeout).await? {
            return Ok(());
        }
    }

    if tried.is_empty() {
        let methods: Vec<&str> = offered.iter().map(Into::into).collect();
        return Err(failed(&format!(
            "nothing: the device accepts only {}",
            methods.join(", ")
        )));
    }
    Err(failed(&tried.join(" and ")))
}

/// Answer a keyboard-interactive login with the password, but only
/// when the device asks exactly one hidden question.
///
/// That's what a password prompt looks like: one question, echo off.
/// Anything else is refused rather than guessed at. A visible
/// question (`Verification code:` with echo on) or two questions at
/// once mean the device wants something netshell doesn't have, and
/// typing the password into it would both fail and show the password
/// where it doesn't belong.
///
/// The device gets three questions at most, so a device that keeps
/// re-asking can't turn one bad password into a lockout.
async fn keyboard_interactive(
    handle: &mut client::Handle<Handler>,
    host: &str,
    user: &str,
    password: &Secret,
    timeout: Duration,
) -> Result<bool> {
    const STEP: &str = "authentication";
    let refused = |reason: String| Error::KeyboardInteractiveRefused {
        host: host.to_string(),
        reason,
    };

    let start = handle.authenticate_keyboard_interactive_start(user, None::<String>);
    let mut response = setup_step(host, STEP, timeout, start).await?;
    let mut rounds = 0;
    loop {
        let prompts = match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => prompts,
        };

        rounds += 1;
        if rounds > MAX_KEYBOARD_INTERACTIVE_ROUNDS {
            return Err(refused(format!(
                "the device asked more than {MAX_KEYBOARD_INTERACTIVE_ROUNDS} times"
            )));
        }
        let answers = match prompts.as_slice() {
            // A device may send a round with no question, to show a
            // message. The protocol wants an empty answer back.
            [] => Vec::new(),
            [only] if !only.echo => vec![password.expose().to_string()],
            [only] => {
                return Err(refused(format!(
                    "the device asked {:?} with echo on, which isn't a password prompt",
                    only.prompt.trim()
                )));
            }
            many => return Err(refused(format!("the device asked {} questions at once", many.len()))),
        };
        let respond = handle.authenticate_keyboard_interactive_respond(answers);
        response = setup_step(host, STEP, timeout, respond).await?;
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
        for status in ["{master:0}", "{primary:node0}", "{secondary:node1}", "{linecard:2}"] {
            let raw = format!("show version\r\nJunos: 21.4R3\r\n\r\n{status}\r\nops@JUN-1> ");
            assert_eq!(
                clean_output(&raw, "show version", &prompt("ops@JUN-1"), Some(&preamble)),
                "Junos: 21.4R3",
                "{status}"
            );
        }
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
    fn echo_is_found_only_once_its_line_is_complete() {
        // A stale prompt and a stale line come first; the answer
        // starts after the echo.
        let raw = b"old tail\r\nSW-1#\r\nSW-1#show version\r\nArista\r\nSW-1#";
        let start = find_echo(raw, "show version").unwrap();
        assert_eq!(&raw[start..], b"Arista\r\nSW-1#");

        assert_eq!(find_echo(b"SW-1#show version", "show version"), None);
        assert_eq!(find_echo(b"old tail\r\nSW-1#", "show version"), None);
    }

    fn names<T: AsRef<str>>(list: &[T]) -> Vec<&str> {
        list.iter().map(AsRef::as_ref).collect()
    }

    const LEGACY_NAMES: &[&str] = &[
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "hmac-sha1",
        "hmac-sha1-etm@openssh.com",
    ];

    #[test]
    fn default_algorithms_leave_out_every_legacy_name() {
        let preferred = preferred_algorithms();
        let offered = [names(&preferred.kex), names(&preferred.cipher), names(&preferred.mac)].concat();
        for legacy in LEGACY_NAMES {
            assert!(!offered.contains(legacy), "{legacy} is offered by default");
        }
        assert!(
            !offered.iter().any(|name| name.contains("sha1") || name.contains("cbc")),
            "{offered:?}"
        );
        assert_eq!(offered[0], "mlkem768x25519-sha256");
        assert!(offered.contains(&"ecdh-sha2-nistp256"));
        assert!(offered.contains(&"aes128-ctr"));
        assert!(offered.contains(&"hmac-sha2-256"));
    }

    #[test]
    fn opt_in_algorithms_add_the_legacy_names_after_the_modern_ones() {
        let modern = preferred_algorithms();
        let legacy = legacy_algorithms();
        let offered = [names(&legacy.kex), names(&legacy.cipher), names(&legacy.mac)].concat();
        for name in LEGACY_NAMES {
            assert!(offered.contains(name), "{name} is missing from the legacy set");
        }

        // Modern first: a current device picks the same algorithm
        // whether the flag is on or not.
        assert_eq!(names(&legacy.cipher)[..modern.cipher.len()], names(&modern.cipher)[..]);
        assert_eq!(names(&legacy.mac)[..modern.mac.len()], names(&modern.mac)[..]);
        let modern_kex = MODERN_KEX.len();
        assert_eq!(names(&legacy.kex)[..modern_kex], names(&modern.kex)[..modern_kex]);
    }

    #[test]
    fn debug_output_redacts_the_password_and_the_enable_secret() {
        let options = ConnectOptions::new("192.0.2.11", "admin", "hunter2-login", Platform::cisco_ios())
            .enable_secret("hunter2-enable");
        let debug = format!("{options:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("password: <redacted>"), "{debug}");
        assert!(debug.contains("enable_secret: Some(<redacted>)"), "{debug}");
        assert!(debug.contains("192.0.2.11"), "{debug}");
        // The pretty form is a separate code path in `Debug`.
        assert!(!format!("{options:#?}").contains("hunter2"));
    }

    #[test]
    fn negotiation_error_names_the_device_its_offer_and_the_flag() {
        let error = Error::NoCommonAlgorithm {
            host: "192.0.2.40".into(),
            kind: "cipher".into(),
            offered: vec!["aes128-cbc".into(), "3des-cbc".into()],
            legacy_tried: false,
        };
        let text = error.to_string();
        assert!(
            text.contains("192.0.2.40 and netshell share no cipher algorithm"),
            "{text}"
        );
        assert!(text.contains("aes128-cbc, 3des-cbc"), "{text}");
        assert!(text.contains("--legacy-algorithms"), "{text}");
    }
}
