# netshell

[![ci](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml/badge.svg)](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml)

A netmiko-style SSH shell driver for network devices, in Rust. Open an
interactive shell, turn paging off, send a `show` command, and get the
output back with the echo and the prompt stripped.

That's the whole job. It's also the part of netmiko that tools like
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
unchanged. The Junos profile escapes a root login's FreeBSD shell with
`cli` before doing anything else.

## Changed in the next release

**Host keys are now checked by default.** Before, netshell accepted any
host key, so anything on the path could pose as your switch and read
the password. Now it works like `ssh`: it remembers each device's key
the first time and refuses to connect if the key ever changes.

What that means for you:

- **Nothing to do on day one.** The first connect to each device
  records its key and carries on.
- **A re-imaged device is refused once.** The error tells you which
  line to remove. See [Host keys](#host-keys).
- **Two more defaults moved.** Old algorithms such as `3des-cbc` are
  now behind `--legacy-algorithms`. And a login that lands in user
  mode (`RTR-1>`) is an error unless you pass `--enable` or
  `--user-mode`.
- **Library users:** `Error` and `HostKeyPolicy` are now
  `#[non_exhaustive]`, `ConnectOptions.password` is a `Secret`, and
  `Platform.preparation` is a list of `Preparation` values.

## Status

CI runs the driver against a fake SSH server (`tests/common/mod.rs`)
that plays each platform's banner, prompt, paging, and command output.
That includes the awkward cases: PAN-OS's slow first prompt and HA
suffix, Junos's `{master:0}` and `{primary:node0}` status lines, a
banner line that ends in `#`, a prompt split across two packets, and
output that only returns to the prompt once paging is off.

It has run against real **Arista EOS** and **Palo Alto PAN-OS** devices,
from both Windows and Linux. The Cisco and Juniper platforms have only
met the fake server so far.

Prompt shapes, login banners, and timing are exactly where shell drivers
break. So run it against one box of each type before you trust it in a
maintenance window. If a prompt isn't recognised, open an issue with the
raw output.

Out of scope on purpose: config mode, SSH key and one-time-code logins,
Telnet, SCP, TextFSM parsing, and the other 140-odd netmiko platforms. Any of them could be added. None is
needed for read-only state capture.

## Command line

```text
netshell --platform arista_eos --host 192.0.2.11 --username admin \
    "show version" "show ip bgp summary" "show running-config"
```

The password is prompted for, or read from an environment variable you
name with `--password-env VAR`. It's never a flag, so it never shows up
in your shell history or in `ps`.

Output uses the `### command ###` section format prepost-check captures
use, or JSON with `--json`.

`--read-timeout` (seconds, default 60) is how long to wait for each
command's prompt to come back. Raise it for `show ip bgp` on a full
table.

Binaries for Linux, Windows, and macOS are attached to each
[release](https://github.com/fnitguy-tech/netshell/releases). No Python,
no venv. The Linux binary is static, so the same file runs on RHEL 9,
Rocky 9, Debian, and Ubuntu.

### Exit codes

A script can tell "the device is down" from "one command failed":

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | Every command ran.                                                   |
| 1    | Couldn't connect or log in. Nothing was collected.                   |
| 2    | Bad arguments.                                                       |
| 3    | Connected, but at least one command failed. The rest is still printed. |

Say you run three commands and the second one times out. You still get
the first command's output on stdout. The second section reads
`COMMAND FAILED:` with the reason, stderr says `2 of 3 commands failed`,
and the exit code is 3.

Why two failures? After a timeout the device may still be printing the
old answer. Sending the third command now could pair it with the wrong
output. So netshell stops sending on that session and says so, rather
than hand you a capture that's one command out of step.

## Host keys

netshell remembers each device's host key and checks it on every
connect. That's what stops something else on the network from posing
as your switch and collecting your password.

**First connect.** The key is written to the known-hosts file, one
line per device: address and port, key type, fingerprint.

```text
192.0.2.11:22 ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
```

**Every later connect.** The key is compared with that line. If it
matches, you won't notice anything.

**If the key changed,** netshell doesn't connect and doesn't send your
password. You get this:

```text
netshell: the host key for 192.0.2.11:22 changed, so netshell didn't connect.
  stored:  ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 (/home/you/.config/netshell/known_hosts, line 3)
  offered: ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
If you replaced or re-imaged this device, remove line 3 from that file, or run netshell once with --accept-new-host-key. If you didn't, stop here: something else may be answering on that address.
```

So there are two ways to accept a new key, and both are things you do
on purpose:

1. Delete the line the error names (line 3 above). The next connect
   records the new key.
2. Run the same command once with `--accept-new-host-key`. It replaces
   that one line and connects.

**Where the file lives.** The first of these that's set wins:

| Set by                                  | Example                                          |
|-----------------------------------------|--------------------------------------------------|
| `--known-hosts FILE`                    | `--known-hosts ./change-1234.known_hosts`        |
| `NETSHELL_KNOWN_HOSTS` environment variable | `NETSHELL_KNOWN_HOSTS=/srv/netshell/known_hosts` |
| Default on Linux and macOS              | `~/.config/netshell/known_hosts`                 |
| Default on Windows                      | `%APPDATA%\netshell\known_hosts`                 |

The file is created for you, readable by your user only (mode 0600 on
Linux and macOS). It's plain text, so you can add `#` comments or
delete lines by hand. Several `netshell` runs can share one file: each
write happens under a lock, so two runs meeting two new devices at the
same moment both get recorded.

**Other choices.**

- `--fingerprint SHA256:nThbg6kX...` connects only if the key has
  exactly that fingerprint, and doesn't touch the known-hosts file.
  Good for a script that already knows what the key should be.
- `--insecure-accept-any-host-key` skips the check. The name is long on
  purpose. Use it for a throwaway lab, not for production.

## Older devices: `--legacy-algorithms`

By default netshell offers only current algorithms. Some older devices
have nothing current to offer, and for those you pass
`--legacy-algorithms`.

You'll know when you need it, because the error says so and lists what
the device offered. An IOS 12.4 router looks like this:

```text
netshell: 192.0.2.40 and netshell share no cipher algorithm. The device offers: aes128-cbc, 3des-cbc. If those are legacy algorithms, netshell leaves them off by default. Try again with --legacy-algorithms (library: ConnectOptions::legacy_algorithms(true)).
```

Here's what each setting offers:

| | Default | Added by `--legacy-algorithms` |
|---|---|---|
| Key exchange | Curve25519, NIST curves, Diffie-Hellman with SHA-2 | `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1` |
| Cipher | ChaCha20-Poly1305, AES-GCM, AES-CTR | `aes256-cbc`, `aes192-cbc`, `aes128-cbc`, `3des-cbc` |
| MAC | HMAC-SHA2-512, HMAC-SHA2-256 | `hmac-sha1`, `hmac-sha1-etm@openssh.com` |

The flag is safe to leave on for a mixed fleet. The current algorithms
are still offered first, and a device picks the first one it supports.
A new switch ends up on the same algorithm with or without the flag.
The old ones are off by default because each has a known weakness, and
it's better to choose that than to get it without asking.

## Enable mode: `--enable`

On Cisco IOS, IOS-XE, and Arista EOS, a login can land in user mode.
The prompt ends in `>` (`RTR-1>`), and `show running-config` doesn't
work there. `--enable` takes you to privileged mode (`RTR-1#`) before
any command runs.

```text
netshell --platform cisco_ios --host 192.0.2.21 --username admin --enable "show running-config"
Password for admin@192.0.2.21:
Enable secret for 192.0.2.21:
```

Like the password, the enable secret is prompted for and is never a
flag. For a script, `--enable-env VAR` reads it from an environment
variable instead. If `enable` asks for no password on your device (the
EOS default), press Enter at the prompt.

What happens without it depends on where the login lands:

| Login lands at | You passed | Result |
|---|---|---|
| `RTR-1#` | anything | Connects. No enable step is needed. |
| `RTR-1>` | `--enable` | Sends `enable`, answers `Password:`, connects at `RTR-1#`. |
| `RTR-1>` | nothing | Stops with an error that names the prompt and both flags. |
| `RTR-1>` | `--user-mode` | Connects and stays at `RTR-1>`. |

The third row is an error on purpose. A capture taken in user mode is
missing the running config, and you'd only find out when you needed it.

**Platforms without enable.** Cisco NX-OS, Cisco IOS-XR, Juniper Junos,
and Palo Alto PAN-OS have no enable step in netshell. `--enable` is
ignored on them, so one script can pass it for every device.

## Logging in

netshell logs in with your password and spends as few attempts as it
can. Many devices lock an account after three failures, so a typo
should cost one attempt, not two.

It first asks the device which login methods it accepts. Then:

- If the device accepts `password`, it tries the password once and
  stops there.
- If the device accepts only `keyboard-interactive` (some Cisco images),
  it uses that, and answers one hidden `Password:` question.

It won't answer anything else. A device that asks for a one-time code,
or asks two questions at once, gets no answer and you get an error that
quotes what it asked. netshell can't do one-time codes.

Every step has a timeout. A device that accepts the connection and then
goes silent costs you `--connect-timeout` seconds (default 15), not a
hung terminal.

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

The CLI flags above map to `ConnectOptions` methods:

| CLI flag                         | Library                                            |
|----------------------------------|----------------------------------------------------|
| `--known-hosts FILE`             | `.known_hosts("FILE")`                             |
| `--accept-new-host-key`          | `.host_key(HostKeyPolicy::ReplaceKnownHost)`       |
| `--fingerprint SHA256:...`       | `.host_key(HostKeyPolicy::Sha256Fingerprint(...))` |
| `--insecure-accept-any-host-key` | `.host_key(HostKeyPolicy::AcceptAny)`              |
| `--legacy-algorithms`            | `.legacy_algorithms(true)`                         |
| `--enable`                       | `.enable_secret("...")`                            |
| `--user-mode`                    | `.allow_user_mode(true)`                           |

**Passwords stay out of logs.** A password or enable secret is held in
a `Secret`. Printing `ConnectOptions` with `{:?}` shows
`password: <redacted>`, and the memory is wiped when the value is
dropped. You don't have to build one: `ConnectOptions::new` takes a
`&str` or a `String`.

**After a timeout, reconnect.** If a command times out, the session is
marked poisoned: `is_poisoned()` returns `true` and every later call
returns `Error::SessionPoisoned`. The device may still be printing the
old answer, so the next answer can't be trusted. Disconnect and connect
again.

**Check `warnings()` after connect.** If the device rejects the
paging-off command (`terminal length 0`), the connect fails with
`Error::PreparationFailed`, because long output would stall. If it
rejects a nice-to-have command such as `terminal width 511`, the
connect succeeds and `warnings()` tells you, for example
`` `terminal width 511` was rejected: % Invalid input ``.

**Match errors with a `_` arm.** `Error` is `#[non_exhaustive]`, so a
new variant in a later release won't break your build. Errors raised
after the connect name the host, which helps when 50 devices run at
once.

**A platform that isn't built in** starts from the closest profile.
Change only what differs:

```rust
use netshell::{Platform, Preparation};

const ASA_PREPARATION: &[Preparation] = &[Preparation::required("terminal pager 0")];

let asa = Platform {
    name: "cisco_asa",
    preparation: ASA_PREPARATION,
    ..Platform::cisco_ios()
};
```

See `src/platform.rs` for the other fields.

### The `cli` feature

The `netshell` binary needs clap and rpassword. The library doesn't. If
you only want the library, turn the default `cli` feature off and those
two crates (and the Windows icon build step) drop out of your build:

```toml
[dependencies]
netshell = { version = "0.1", default-features = false }
```

`cargo install netshell` needs nothing extra, because `cli` is on by
default. The crate needs Rust 1.89 or newer.

## Building

```text
cargo build --release
cargo test
```

Pure Rust (`russh` with `ring`). A C compiler is all you need beyond the
toolchain, and cross-compiling to a single Windows binary needs no
OpenSSL.

## License

MIT - see [LICENSE](LICENSE).
