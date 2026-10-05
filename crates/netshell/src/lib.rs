//! netmiko-style SSH shell driver for network devices.
//!
//! netmiko does a great deal more than most tools need. What a
//! pre/post-change checker or a config backup job needs is: open an
//! interactive shell, turn paging off, send a `show` command, get the
//! output back with the echo and the prompt removed. That is all this
//! crate does, for six platforms:
//!
//! | `device_type`    | platform                          |
//! |------------------|-----------------------------------|
//! | `arista_eos`     | Arista EOS                        |
//! | `cisco_ios`      | Cisco IOS / IOS-XE (`cisco_xe`)   |
//! | `cisco_nxos`     | Cisco NX-OS                       |
//! | `cisco_xr`       | Cisco IOS-XR                      |
//! | `juniper_junos`  | Juniper Junos                     |
//! | `paloalto_panos` | Palo Alto PAN-OS                  |
//!
//! The names are netmiko's, so an inventory written for netmiko works
//! unchanged.
//!
//! ```no_run
//! use netshell::{ConnectOptions, Device, Platform};
//!
//! # async fn run() -> Result<(), netshell::Error> {
//! let options = ConnectOptions::new("192.0.2.11", "admin", "secret", Platform::by_name("arista_eos")?);
//! let mut device = Device::connect(options).await?;
//!
//! let output = device.send_command("show ip bgp summary").await?;
//! println!("{output}");
//! device.disconnect().await?;
//! # Ok(()) }
//! ```
//!
//! The API is async (tokio). [`blocking::Device`] wraps it for callers
//! that drive devices from plain threads.
//!
//! # Host keys
//!
//! Host keys are checked by default, the way `ssh` does it. The first
//! connect to a device writes its key to a known-hosts file. Every
//! later connect compares, and a different key is refused with
//! [`Error::HostKeyChanged`]. See [`HostKeyPolicy`] for the other
//! choices and [`default_known_hosts_path`] for where the file lives.
//!
//! # Cargo features
//!
//! `cli` (on by default) builds the `netshell` binary and pulls in
//! clap and rpassword. A library user can leave it out:
//!
//! ```toml
//! netshell = { version = "0.1", default-features = false }
//! ```
//!
//! # Status
//!
//! The driver logic is exercised in CI against a fake SSH server that
//! plays each platform's prompt and paging behaviour (see `tests/`).
//! It has **not yet been validated against real hardware**. Prompt
//! shapes, banners and timing are where shell drivers break, so run it
//! against one box of each type you care about before trusting it in
//! a maintenance window.

pub mod blocking;
mod device;
mod error;
mod known_hosts;
mod platform;
mod secret;

pub use device::{
    ConnectOptions, Device, HostKeyPolicy, clean_output, legacy_algorithms, preferred_algorithms, strip_ansi,
};
pub use error::Error;
pub use known_hosts::{KNOWN_HOSTS_ENV, default_known_hosts_path};
pub use platform::{Enable, Platform, Preparation, ShellEscape};
pub use secret::Secret;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
