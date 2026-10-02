# mw

<img src="assets/mw.png" width="64" align="right" alt="mw icon">

[![ci](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml/badge.svg)](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/fnitguy-tech/netshell)](https://github.com/fnitguy-tech/netshell/releases)
[![crates.io](https://img.shields.io/crates/v/mw-check?label=mw-check)](https://crates.io/crates/mw-check)

**Maintenance window check.** Capture your network devices before a
change, capture them again after, and get told what actually changed:
a quick text diff for the on-call view, and an interpreted HTML report
with impact-rated findings for everyone else.

```text
mw before NET-123 -r      capture before the change, secrets stripped
   (do the change)
mw after  NET-123 -r      capture after the change, quick text diff
mw report NET-123         the interpreted HTML report
```

One static binary for Windows, macOS and Linux. No Python, no venv,
nothing to install. Every command it sends to a device is a read-only
`show`. Arista EOS, Cisco IOS/IOS-XE/NX-OS/IOS-XR, Juniper Junos and
Palo Alto PAN-OS over SSH, through this repository's own
[`netshell`](crates/netshell/) driver.

![Report overview: health verdict, outcome summary, attention items](docs/img/report-overview.png)

## What it tells you

A 10-device window, condensed from the full
[sample report](docs/sample-report.html) (download it and open it in a
browser; GitHub does not render repository HTML):

```text
NET-2043   Network Health: ATTENTION    devices 10 · changed 34 · attention 4

SITE-B-SW-2    Attention 1 · Action Required 0 · Impact 28
  BGP Peer Activated        EXTNET-LAB  10.118.9.3  AS65000
    State                   Idle(Admin) → Estab
    Prefixes Received       0 → 3
    Evidence: show ip bgp summary + related BGP shutdown/no shutdown config

SITE-A-SW-1    Attention 1 · Action Required 0 · Impact 31
  BGP Prefix Count Changed  198.18.85.240  AS4200000001
    Prefixes Received       248 → 53
```

Every finding links to the raw before/after diff behind it. All
hostnames, addresses and ASNs in the sample are fictional.

## Install

```text
cargo install mw-check                               # any OS with Rust; the binary is mw
scoop bucket add fnitguy https://github.com/fnitguy-tech/netshell
scoop install mw                                     # Windows, Scoop
```

Or download `mw` for your platform from the
[latest release](https://github.com/fnitguy-tech/netshell/releases/latest).
`SHA256SUMS` sits next to the binaries, and each one carries a GitHub
build provenance attestation:

```text
gh attestation verify mw-windows-x86_64.exe --owner fnitguy-tech
```

The binaries are not code-signed yet, so a direct download gets the
SmartScreen prompt on first run on Windows; a Scoop or cargo install
does not.

## Try it in 60 seconds, no devices

```text
mw demo
```

That runs the whole workflow on a bundled fictional four-device uplink
migration ([scenario](crates/mw-check/fixtures/NET-DEMO/SCENARIO.md)):
the parallel collector with SSH swapped for a stub that replays the
bundled captures, the zip packaging, the quick text diff and the HTML
report, all landing in `reports/NET-DEMO/` under the current directory.

![Terminal: full demo run, precheck through report](docs/img/demo-terminal.png)

Open `reports/NET-DEMO/Compare/compare_<timestamp>.html` for the
interpreted report. The `.txt` next to it is what the on-call engineer
reads before leaving the window:

![Quick text diff: interface status, BGP summary, routes and config changes](docs/img/quick-diff.png)

Note what is *not* in that diff: uptime, BGP message counters, OSPF
dead timers and optic readings all moved between the two captures, and
the normalizer dropped every one of them. SITE-B-SW-1, untouched by the
change, reports "No meaningful changes detected."

## Run it against your network

Put your devices in `inventory/devices.yml` (copy
[`devices.example.yml`](crates/mw-check/fixtures/devices.example.yml) to
start), then from that directory:

```text
mw before NET-123 -r
   (do the change)
mw after NET-123 -r
mw report NET-123
```

The ticket is the first argument; leave it off and you are prompted.
`-u` gives the SSH username, otherwise it is prompted; the password is
always prompted, never a flag. Devices are collected five at a time
with a live progress bar; an unreachable device is logged and recorded
as a `<host>_FAILED.txt` finding instead of aborting the run.

![Terminal: parallel collection in progress](docs/img/progress-bar.png)

Everything lands under `reports/<TICKET>/` in the current directory, or
under `$MW_HOME` when that is set:

```text
reports/<TICKET>/
  Precheck/precheck_<timestamp>/<hostname>.txt   (+ .zip)
  Postcheck/postcheck_<timestamp>/<hostname>.txt (+ .zip)
  Compare/compare_<timestamp>.txt / .html
  expectations.yml   (optional, written by hand: expected BGP deltas)
```

The Python tool's names (`precheck`, `postcheck`, `compare`) still work
as aliases, and the capture files are the same format, so captures and
reports from [prepost-check](https://github.com/fnitguy-tech/prepost-check)
and `mw` can be mixed on one `reports/` tree.

### Keeping passwords out of the evidence

A running-config capture carries every `secret sha512 $6$...`, BGP
`password 7`, TACACS key, SNMP community and PAN-OS `phash` / `-AQ==`
value on the device. `-r` replaces each value with `<REDACTED>` before
the capture is written, so neither the text files, the zip nor the
reports ever hold it. The keyword and type marker stay
(`username admin secret sha512 <REDACTED>`), so a credential that was
added or removed during the window still shows up as a change; only a
password that was *rotated* is invisible. Use it on both captures. The
rules are in [`redact.rs`](crates/mw-check/src/redact.rs), one commented
pattern per line.

## What the report interprets

Raw `show` output diffs are useless on their own: uptimes, ARP timers
and BGP message counters change every second. Each command has a
normalization rule that strips expected churn so the diff only shows
operational change. On top of that, the report understands:

- **BGP peers.** Summary tables (EOS, IOS, NX-OS) and PAN-OS peer
  blocks are parsed into per-peer state, prefix counts and uptime. A
  peer going `Estab → Idle(Admin)` right after a `neighbor x.x.x.x
  shutdown` line appeared in the config is one finding with its
  evidence. A session whose uptime went *backwards* is a reset, even
  when it reads `Estab → Estab`. Prefix deltas cite the prefix-list,
  route-map and policy lines that changed.
- **Prefix lists**, entry by entry. A withdrawn permit or a
  same-sequence overwrite (the classic Arista replace-by-sequence
  mistake) is `Attention`; a resequenced entry `Changed`; an added one
  `Stable`.
- **Pair symmetry.** The two members of a redundant pair are compared
  against each other: same-named prefix-lists, route-maps and PAN-OS HA
  state. "SW-1 and SW-2 now disagree" is invisible to a per-device
  report, so it gets its own section near the top.
- **Interfaces** that gained an address during the window and are still
  down: the step configured cleanly and still does not work.
- **Expectations.** Write down what the change should do to prefix
  counts and the report rates each delta as planned, different,
  unexplained or not happened, instead of hedging on all of them.

![Interpreted BGP findings with impact ratings and before/after state](docs/img/report-findings.png)

![Health, category and per-device impact charts](docs/img/report-charts.png)

The HTML report is one self-contained file: overall health verdict
(`Stable / Changed / Attention / Action Required`), per-device impact
scores, findings with before/after state, category and impact charts,
and every raw diff behind a collapsible section for evidence. Chart.js
from a CDN is its only external asset.

## Configuring the inventory

`inventory/devices.yml` groups devices by platform. Each platform
carries its netmiko-style `device_type` and the command list captured
for it, so adding a device, a command or a platform never means
touching code:

```yaml
platforms:
  - name: arista
    device_type: arista_eos        # arista_eos, cisco_ios, cisco_nxos, cisco_xr, juniper_junos, paloalto_panos
    hosts:
      - 192.0.2.11
    commands:
      - show ip bgp summary
      - show running-config
```

The example inventory carries curated command lists for Arista EOS and
PAN-OS, including IPsec/IKE tunnel state and LSVPN hub/satellite
status, normalized so SPIs, rekey timers and satellite login times
never show up as changes but a tunnel going `active → init` does.

**Redundant pairs.** Hostnames that differ only by a trailing number
are paired automatically. Pairs not named that way go in an optional
top-level list:

```yaml
pairs:
  - [CORE-EAST, CORE-WEST]
  - [EDGE-FW-PRIMARY, EDGE-FW-SECONDARY]
```

**Expectations.** A routing change usually has a known effect: "SW-2
learns three more transit prefixes", "ISP-B sends the full table, 815
prefixes". Write it in `reports/<TICKET>/expectations.yml` (or pass a
file with `mw report -e`), one entry per device and peer:

```yaml
ticket: NET-123                  # optional; must match when present
expectations:
  - device: SITE-A-SW-2          # capture hostname, case-insensitive
    peer: 10.0.0.1               # neighbor IP or the Description column
    expected_delta: +3           # change in prefixes received, or
  - device: SITE-A-SW-1
    peer: ISP-B
    expected_prefixes: 815       # absolute prefixes received afterwards
    note: full table minus bogons
```

**A per-change inventory.** Copy the parts of `devices.yml` you need
into a file named for the change and pass it with `-i`. The capture
then covers only the devices in scope and can carry the commands that
prove that change.

## netshell, the driver underneath

[`netshell`](crates/netshell/) is the SSH piece on its own: open a
shell, turn paging off, send `show` commands, get clean output back,
for the six platforms above. It is what `mw` collects with, and it is
usable alone as a library or a CLI:

```text
netshell --platform arista_eos --host 192.0.2.11 --username admin "show version" "show ip bgp summary"
```

It offers the full algorithm set older devices need (NIST curves,
SHA-1 group exchange, CBC ciphers) with the modern ones first, tries
password and keyboard-interactive authentication, escapes a Junos
root shell with `cli`, and can pin a host key by SHA-256 fingerprint.

## Repository layout

```text
crates/mw-check/      the mw binary (package mw-check on crates.io)
  src/commands/       before, after, report, demo
  src/collect.rs      parallel SSH capture, zip packaging
  src/redact.rs       the -r rules
  src/textcompare.rs  normalization rules + quick .txt diff
  src/analysis/       parsers, findings, pair symmetry, impact scoring
  src/report.rs       the HTML report
  src/difflib.rs      port of Python's ndiff, so every diff reads the same
  fixtures/NET-DEMO/  the demo captures and the reports they produce
crates/netshell/      the SSH driver (library + CLI)
docs/                 sample report and screenshots
packaging/            winget and Scoop manifests, release rendering
assets/               icons
```

## Building and testing

```text
cargo build --release --workspace
cargo test --workspace
```

Pure Rust, so a C compiler is the only thing needed beyond the
toolchain, and the Windows binary needs no OpenSSL. The 200-odd tests
run offline: the netshell tests talk to an in-process fake SSH server
that plays each platform's prompt and paging behaviour, and the mw
tests check every rule against synthetic captures and the bundled demo
against the reports the original Python tool produced from it, byte for
byte.

## Status

`mw` has collected from Arista EOS and PAN-OS in production. Cisco
IOS/NX-OS/IOS-XR and Juniper Junos are tested against the fake server
only; a prompt or paging quirk on real hardware is a one-line fix in
`netshell`'s platform profile, so please open an issue with the raw
output if one bites.

## License

MIT - see [LICENSE](LICENSE).
