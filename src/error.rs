use std::time::Duration;

/// Everything that can go wrong between "connect" and "output".
#[derive(Debug, thiserror::Error)]
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

    #[error("authentication failed for {user}@{host} (tried password and keyboard-interactive)")]
    AuthFailed { user: String, host: String },

    #[error("host key for {host} is {actual}, expected {expected}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },

    #[error("timed out after {timeout:?} waiting for {what}; received so far:\n{received}")]
    ReadTimeout {
        what: String,
        timeout: Duration,
        received: String,
    },

    #[error("the device closed the channel")]
    ChannelClosed,

    #[error("could not find a prompt in:\n{0}")]
    NoPrompt(String),

    #[error("ssh error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("invalid pattern: {0}")]
    Regex(#[from] regex::Error),
}
