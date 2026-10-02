# netshell

[![ci](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml/badge.svg)](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml)

Network maintenance tooling in Rust, as two crates in one workspace:

| crate | what it is |
|-------|------------|
| [`netshell`](crates/netshell/) | A netmiko-style SSH shell driver: open a shell on Arista EOS, Cisco IOS/IOS-XE/NX-OS/IOS-XR, Juniper Junos or Palo Alto PAN-OS, turn paging off, run `show` commands, get clean output back. Library plus a small CLI. |
| [`prepost`](crates/prepost/) | Pre/post change validation: capture device state before a maintenance window and after, diff the two with expected churn stripped, and turn the difference into an interpreted HTML report. A port of the Python [prepost-check](https://github.com/fnitguy-tech/prepost-check), built on `netshell`. |

Both ship as single static binaries for Linux, Windows and macOS on
every [release](https://github.com/fnitguy-tech/netshell/releases): no
Python, no venv, nothing to install.

```text
cargo build --release --workspace
cargo test --workspace
```

Pure Rust (`russh` with `ring`), so a C compiler is the only thing
needed beyond the toolchain, and cross-compiling to a single Windows
binary needs no OpenSSL.

## Status

The SSH driver is exercised in CI against a fake SSH server that plays
each platform's banner, prompt, paging and command outputs. The
validation tool is checked against the fictional four-device dataset
bundled as fixtures, including the text and HTML reports the Python
tool produces from it. Neither has **been validated against real
hardware yet**; run them against one box of each type before trusting
them in a maintenance window.

## License

MIT - see [LICENSE](LICENSE).
