# netshell

<img src="assets/mw.png" width="48" align="left" alt="mw icon"> <img src="assets/netshell.png" width="48" align="left" alt="netshell icon">

[![ci](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml/badge.svg)](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml)

Network maintenance tooling in Rust, as two crates in one workspace:

| crate | what it is |
|-------|------------|
| [`netshell`](crates/netshell/) | A netmiko-style SSH shell driver: open a shell on Arista EOS, Cisco IOS/IOS-XE/NX-OS/IOS-XR, Juniper Junos or Palo Alto PAN-OS, turn paging off, run `show` commands, get clean output back. Library plus a small CLI. |
| [`mw-check`](crates/mw-check/) | Maintenance window check: capture device state before a maintenance window and after, diff the two with expected churn stripped, and turn the difference into an interpreted HTML report. A port of the Python [prepost-check](https://github.com/fnitguy-tech/prepost-check), built on `netshell`. |

## Install

```text
winget install fnitguy-tech.mw                       # Windows
scoop bucket add fnitguy https://github.com/fnitguy-tech/netshell
scoop install mw                                     # Windows, Scoop
cargo install mw-check                               # any OS with Rust; the binary is mw
cargo install netshell
```

Or take the binaries straight from a
[release](https://github.com/fnitguy-tech/netshell/releases): single
static files for Linux, Windows and macOS, no Python, no venv. Each
release lists SHA-256 checksums, and every binary carries a GitHub
build provenance attestation, so a download can be proven to have
been built by this repository's workflow from a given commit:

```text
gh attestation verify mw-windows-x86_64.exe --owner fnitguy-tech
```

The binaries are not code-signed yet, so a direct download still gets
the SmartScreen prompt on first run on Windows; winget and Scoop
installs do not. See [packaging/](packaging/) for how the channels
are fed.

```text
cargo build --release --workspace
cargo test --workspace
```

The Windows executables carry their icons and version info, embedded
by each crate's `build.rs` from the `.ico` files that
`assets/icons.py` draws (Pillow; rerun it to change the artwork).

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
