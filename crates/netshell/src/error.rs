use std::path::PathBuf;
use std::time::Duration;

/// Everything that can go wrong between "connect" and "output".
///
/// Every variant raised after the TCP connect names the host, so a
/// collector that runs 50 devices at once can tell which one failed.
/// The enum is `#[non_exhaustive]`: match with a `_` arm, because new
/// variants can appear in a minor release.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "unknown platform '{0}'; known: arista_eos, cisco_ios (cisco_xe), cisco_nxos, cisco_xr, juniper_junos, paloalto_panos"
    )]
    UnknownPlatform(String),

    #[error("could not connect to {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },

    #[error("connection to {host}:{port} timed out after {timeout:?}")]
    ConnectTimeout { host: String, port: u16, timeout: Duration },

    /// The device took the TCP connection and the SSH handshake, then
    /// stopped answering. `step` says where: `authentication`,
    /// `opening the session channel`, and so on.
    #[error("{host} stopped answering during {step}; gave up after {timeout:?}")]
    SetupTimeout {
        host: String,
        step: &'static str,
        timeout: Duration,
    },

    /// The device and netshell have no algorithm in common.
    #[error("{}", no_common_algorithm(.host, .kind, .offered, *.legacy_tried))]
    NoCommonAlgorithm {
        host: String,
        /// `key exchange`, `cipher`, `MAC`, `host key`, or `compression`.
        kind: String,
        /// What the device offered, in its order.
        offered: Vec<String>,
        /// Whether the legacy set was already switched on.
        legacy_tried: bool,
    },

    #[error("authentication failed for {user}@{host} (tried {tried})")]
    AuthFailed {
        user: String,
        host: String,
        /// The methods that were tried, for example `password`.
        tried: String,
    },

    /// The device asked something other than one hidden password
    /// question, for example a one-time code.
    #[error(
        "netshell stopped the keyboard-interactive login to {host}: {reason}. It only answers one hidden password prompt, so it can't do one-time codes or multi-question logins"
    )]
    KeyboardInteractiveRefused { host: String, reason: String },

    /// A pinned fingerprint ([`crate::HostKeyPolicy::Sha256Fingerprint`])
    /// didn't match.
    #[error("host key for {host} is {actual}, expected {expected}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },

    /// The known-hosts file holds a different key for this device.
    #[error(
        "the host key for {host}:{port} changed, so netshell didn't connect.\n  stored:  {stored} ({}, line {line})\n  offered: {offered}\nIf you replaced or re-imaged this device, remove line {line} from that file, or run netshell once with --accept-new-host-key. If you didn't, stop here: something else may be answering on that address.",
        .file.display()
    )]
    HostKeyChanged {
        host: String,
        port: u16,
        /// `algorithm SHA256:fingerprint` as stored in the file.
        stored: String,
        /// `algorithm SHA256:fingerprint` the device presented now.
        offered: String,
        file: PathBuf,
        /// 1-based line number of the stored key.
        line: usize,
    },

    #[error(
        "couldn't use the known-hosts file {}: {source}. Point NETSHELL_KNOWN_HOSTS at a file you can write",
        .path.display()
    )]
    KnownHosts {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Login landed in user mode and no enable secret was given.
    #[error(
        "{host} logged in at `{prompt}`, which is user mode, and commands like `show running-config` need enable mode. Give an enable secret (CLI: --enable), or allow user mode (CLI: --user-mode)"
    )]
    EnableRequired { host: String, prompt: String },

    #[error("couldn't enter enable mode on {host}: the device didn't accept the enable secret")]
    EnableFailed { host: String },

    /// A required preparation command (paging off) was rejected.
    #[error(
        "{host} rejected `{command}`, so paging is still on and long output would stall. The device said:\n{output}"
    )]
    PreparationFailed {
        host: String,
        command: String,
        output: String,
    },

    #[error("timed out after {timeout:?} waiting for {what} on {host}; received so far:\n{received}")]
    ReadTimeout {
        host: String,
        what: String,
        timeout: Duration,
        received: String,
    },

    #[error("{host} didn't take the data within {timeout:?}; the session is stuck, so reconnect")]
    WriteTimeout { host: String, timeout: Duration },

    /// An earlier read or write timed out, so the device may still be
    /// printing an old answer. Sending more would pair commands with
    /// the wrong output.
    #[error(
        "the session to {host} is out of step after a timeout, so its next answer could belong to an earlier command. Disconnect and connect again"
    )]
    SessionPoisoned { host: String },

    #[error("{host} closed the channel")]
    ChannelClosed { host: String },

    #[error("could not find a prompt on {host} in:\n{received}")]
    NoPrompt { host: String, received: String },

    /// An SSH protocol error after the TCP connect.
    #[error("ssh error talking to {host}: {source}")]
    Session {
        host: String,
        #[source]
        source: russh::Error,
    },

    /// An SSH protocol error with no host attached. The driver wraps
    /// these in [`Error::Session`]; this variant exists so russh can
    /// hand its own errors to the host-key callback.
    #[error("ssh error: {0}")]
    Ssh(#[from] russh::Error),

    /// The blocking wrapper couldn't start its runtime.
    #[error("couldn't start the async runtime: {0}")]
    Runtime(#[source] std::io::Error),

    /// A blocking [`crate::blocking::Device`] was used after it was
    /// disconnected.
    #[error("this device is already disconnected")]
    Disconnected,

    #[error("invalid pattern: {0}")]
    Regex(#[from] regex::Error),
}

/// Example, a 2009 switch with defaults on:
///
/// ```text
/// 192.0.2.40 and netshell share no cipher algorithm. The device
/// offers: aes128-cbc, 3des-cbc. Those are legacy algorithms, which
/// netshell leaves off by default. Try again with --legacy-algorithms
/// (library: ConnectOptions::legacy_algorithms(true)).
/// ```
fn no_common_algorithm(host: &str, kind: &str, offered: &[String], legacy_tried: bool) -> String {
    let offered = if offered.is_empty() {
        "nothing".to_string()
    } else {
        offered.join(", ")
    };
    let advice = if legacy_tried {
        "The legacy algorithms are already on, so netshell can't talk to this device."
    } else {
        "If those are legacy algorithms, netshell leaves them off by default. Try again with --legacy-algorithms (library: ConnectOptions::legacy_algorithms(true))."
    };
    format!("{host} and netshell share no {kind} algorithm. The device offers: {offered}. {advice}")
}
