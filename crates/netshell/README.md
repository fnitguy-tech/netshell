# netshell

[![ci](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml/badge.svg)](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml)

A netmiko-style SSH shell driver for network devices, in Rust. Open an
interactive shell, turn paging off, send a `show` command, get the
output back with the echo and the prompt removed. That is the whole
job, and it is the part of netmiko that tools like
[prepost-check](https://github.com/fnitguy-tech/prepost-check) actually
use.

| `device_type`    | Platform                       | Paging off with                                             |
|------------------|--------------------------------|-------------------------------------------------------------|
| `arista_eos`     | Arista EOS                     | `terminal length 0`, `terminal width 511`                   |
| `cisco_ios`      | Cisco IOS / IOS-XE (`cisco_xe`)| `terminal length 0`, `terminal width 511`                   |
| `cisco_nxos`     | Cisco NX-OS                    | `terminal length 0`, `terminal width 511`                   |
| `cisco_xr`       | Cisco IOS-XR                   | `terminal length 0`, `terminal width 512`, no timestamps    |
| `juniper_junos`  | Juniper Junos                  | `set cli screen-length 0`, width 511, complete-on-space off |
| `paloalto_panos` | Palo Alto PAN-OS               | `set cli scripting-mode on`, `set cli pager off`, width 500 |

The names are netmiko's, so an inventory written for netmiko works
unchanged. Password and keyboard-interactive authentication are both
tried with the same password, which covers Cisco boxes that only offer
the latter. The Junos profile escapes a root login's FreeBSD shell with
`cli` before doing anything else.

## Status

The driver is exercised in CI against a fake SSH server
(`tests/common/mod.rs`) that plays each platform's banner, prompt,
paging and command outputs, including PAN-OS's slow first prompt and
HA suffix, Junos's `{master:0}` status line, and output that only
returns to the prompt once paging is off.

It has **not yet been validated against real hardware.** Prompt
shapes, login banners and timing are exactly where shell drivers
break. Run it against one box of each type before trusting it in a
maintenance window, and open an issue with the raw output if a prompt
is not recognised.

Out of scope on purpose: config mode, Telnet, SCP, TextFSM parsing and
the other 140-odd netmiko platforms. Any of them can be added; none is
needed for read-only state capture.

## Command line

```text
netshell --platform arista_eos --host 192.0.2.11 --username admin \
    "show version" "show ip bgp summary" "show running-config"
```

The password is prompted for, or read from an environment variable
named with `--password-env VAR`. It is never a flag. Output is written
in the `### command ###` section format prepost-check captures use, or
as JSON with `--json`. `--fingerprint SHA256:...` refuses to connect
unless the host key matches; without it any host key is accepted, which
is netmiko's default too. `--read-timeout` (seconds, default 60) is the
wait for each command's prompt to come back; raise it for
`show ip bgp` on a full table.

Binaries for Linux, Windows and macOS are attached to each
[release](https://github.com/fnitguy-tech/netshell/releases). No Python,
no venv.

## Library

```rust
use std::time::Duration;
use netshell::{ConnectOptions, Device, Platform};

let mut device = Device::connect(
    ConnectOptions::new("192.0.2.11", "admin", password, Platform::by_name("arista_eos")?)
        .read_timeout(Duration::from_secs(180)),
)
.await?;

let bgp = device.send_command("show ip bgp summary").await?;
let full_table = device.send_command_timeout("show ip bgp", Duration::from_secs(600)).await?;
device.disconnect().await?;
```

The API is async on tokio. `netshell::blocking::Device` wraps it with
the same methods for callers that drive one device per thread.
`send_command_expect` reads until an arbitrary pattern instead of the
prompt, for confirmations. `find_prompt` re-learns the prompt if you
changed mode by hand.

A platform that is not built in is a `Platform` struct literal: the
prompt terminator class, the preparation commands, an optional shell
escape and an optional prompt preamble pattern. See `src/platform.rs`.

## Building

```text
cargo build --release
cargo test
```

Pure Rust (`russh` with `ring`), so a C compiler is the only thing
needed beyond the toolchain, and cross-compiling to a single Windows
binary needs no OpenSSL.

## License

MIT - see [LICENSE](LICENSE).
