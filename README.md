# mw

<img src="assets/mw.png" width="64" align="right" alt="mw icon">

[![ci](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml/badge.svg)](https://github.com/fnitguy-tech/netshell/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/fnitguy-tech/netshell)](https://github.com/fnitguy-tech/netshell/releases)
[![crates.io](https://img.shields.io/crates/v/mw-check?label=mw-check)](https://crates.io/crates/mw-check)

**Maintenance window check.** Capture your network devices before a
change, capture them again after, and get told what actually changed.

You get a quick text diff for the on-call view, and an interpreted HTML
report with impact-rated findings for everyone else.

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

The binaries aren't code-signed yet, so a direct download gets the
SmartScreen prompt on first run on Windows; a Scoop or cargo install
does not.

## Try it in 60 seconds, no devices

```text
mw demo
```

That runs the whole workflow on a bundled fictional four-device uplink
migration ([scenario](crates/mw-check/fixtures/NET-DEMO/SCENARIO.md)) -
the parallel collector, the zip packaging, the quick text diff, and the
HTML report. It all lands in `reports/NET-DEMO/` under the current
directory. No SSH happens; a stub replays the bundled captures.

![Terminal: full demo run, precheck through report](docs/img/demo-terminal.png)

Open `reports/NET-DEMO/Compare/compare_<timestamp>.html` for the
interpreted report. The `.txt` next to it is what the on-call engineer
reads before leaving the window:

![Quick text diff: interface status, BGP summary, routes and config changes](docs/img/quick-diff.png)

Now notice what *isn't* in that diff. Uptime, BGP message counters, OSPF
dead timers, and optic readings all moved between the two captures. The
normalizer dropped every one. SITE-B-SW-1 wasn't touched by the change,
so it reports "No meaningful changes detected."

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

The ticket is the first argument. Leave it off and you'll be prompted.
`-u` gives the SSH username; without it you're prompted for that too.
The password is always prompted, never a flag.

Devices are read five at a time behind a live progress bar. An
unreachable one is logged and recorded as a `<host>_FAILED.txt` finding,
and the run keeps going.

![Terminal: parallel collection in progress](docs/img/progress-bar.png)

Everything lands under `reports/<TICKET>/` in the current directory, or
under `$MW_HOME` when that is set:

```text
reports/<TICKET>/
  Precheck/precheck_<timestamp>/<hostname>.txt   (+ .zip)
  Postcheck/postcheck_<timestamp>/<hostname>.txt (+ .zip)
  Compare/compare_<timestamp>.txt / .html
  notes.md           (optional: your account of the window)
```

The Python tool's names (`precheck`, `postcheck`, `compare`) still work
as aliases. The capture files use the same format too, so you can mix
captures and reports from
[prepost-check](https://github.com/fnitguy-tech/prepost-check) and `mw`
on one `reports/` tree.

### Keeping passwords out of the evidence

A running-config capture carries every secret on the box: `secret sha512
$6$...`, BGP `password 7`, TACACS keys, SNMP communities, and PAN-OS
`phash` / `-AQ==` values.

`-r` turns every one of them into `<REDACTED>` before anything is written
to disk. The text files, the zip, and the reports never hold the real
value. Use it on both captures.

The keyword and type marker stay, so you still see
`username admin secret sha512 <REDACTED>`. That means a credential added
or removed during the window still shows up as a change. Here's the
trade-off: a password *rotated* to a new value looks identical before and
after, so you won't see it.

The rules are in [`redact.rs`](crates/mw-check/src/redact.rs), one
commented pattern per line.

## What the report interprets

A raw `show` diff is noise on its own - uptimes, ARP timers, and BGP
message counters all move every second. Each command gets a normalization
rule that strips the churn, so what's left is real change. On top of
that, the report understands:

- **BGP peers.** Summary tables (EOS, IOS, NX-OS) and PAN-OS peer
  blocks are parsed into per-peer state, prefix counts, and uptime. A
  peer going `Estab → Idle(Admin)` right after a `neighbor x.x.x.x
  shutdown` line appeared in the config is one finding with its
  evidence. A session whose uptime went *backwards* is a reset, even
  when it reads `Estab → Estab`. Prefix deltas cite the prefix-list,
  route-map and policy lines that changed.
- **Prefix lists**, entry by entry. A removed permit is `Attention`, and
  so is an entry replaced at the same sequence number - the classic
  Arista replace-by-sequence trap. An entry that just moved is `Changed`.
  A new one is `Stable`.
- **Pair symmetry.** The two members of a redundant pair get compared
  against each other: same-named prefix-lists, route-maps, and PAN-OS HA
  state. "SW-1 and SW-2 now disagree" is invisible to a per-device
  report, so it gets its own section near the top. Route-map comparison
  skips the knobs a pair is meant to differ in, like prepend depth and
  local-preference.
- **Interfaces** that gained an address during the window and are still
  down. The config is fine and the link isn't.
- **Prefix-count changes.** A peer whose received or accepted count moved
  is `Changed`, with the caveat that routing policy, communities,
  failover, and advertised routes all move it legitimately. Whether this
  particular move was meant to happen is a judgement, so it goes in your
  notes rather than in a rating.

![Interpreted BGP findings with impact ratings and before/after state](docs/img/report-findings.png)

![Health, category and per-device impact charts](docs/img/report-charts.png)

The HTML report is one self-contained file. It carries the health verdict
(`Stable / Changed / Attention / Action Required`) and a per-device impact
score. Under that, every finding with its before and after state, the
category and impact charts, and each raw diff folded into a collapsible
section. Chart.js from a CDN is its only external asset.

## Configuring the inventory

`inventory/devices.yml` groups devices by platform. Each platform carries
its netmiko-style `device_type` and the commands to capture for it. So
adding a device, a command, or a whole platform never means touching
code:

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
PAN-OS. The PAN-OS list adds IPsec/IKE tunnel state and LSVPN
hub/satellite status. Those are normalized, so SPIs, rekey timers, and
satellite login times never read as changes - but a tunnel going
`active → init` does.

**Redundant pairs.** Hostnames that differ only by a trailing number
are paired automatically. Pairs not named that way go in an optional
top-level list:

```yaml
pairs:
  - [CORE-EAST, CORE-WEST]
  - [EDGE-FW-PRIMARY, EDGE-FW-SECONDARY]
```

**Your write-up.** The report says what changed. It can't say why you
changed it, what surprised you, or what you only noticed afterwards.
`mw notes NET-123` writes `reports/<TICKET>/notes.md`, seeded with the
ticket, the window times, and the devices your captures hold, under five
headings:

```markdown
## What we set out to do
## What actually happened
## What we missed
## Still open
## Would do differently
```

Fill it in with any editor and `mw report` renders it above the machine
findings. Bullets, `- [ ]` and `- [x]` checkboxes, `` `code` `` and
`**bold**` all work, and open checkboxes get counted. A section you leave
empty is left out, a template with nothing filled in renders nothing at
all, and it never overwrites notes you already started.

**A per-change inventory.** Copy the parts of `devices.yml` you need into
a file named for the change and pass it with `-i`. The capture then covers
only the devices in scope, and it can carry the commands that prove that
one change.

## netshell, the driver underneath

[`netshell`](crates/netshell/) is the SSH piece on its own. Open a shell,
turn paging off, send `show` commands, get clean output back - for the
six platforms above. It's what `mw` collects with, and you can use it
alone as a library or a CLI:

```text
netshell --platform arista_eos --host 192.0.2.11 --username admin "show version" "show ip bgp summary"
```

It carries the full algorithm set older devices need - NIST curves,
SHA-1 group exchange, CBC ciphers - with the modern ones offered first.
It tries password and keyboard-interactive auth, escapes a Junos root
shell with `cli`, and can pin a host key by SHA-256 fingerprint.

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

Pure Rust. A C compiler is all you need beyond the toolchain, and the
Windows binary needs no OpenSSL.

The 200-odd tests all run offline. The netshell tests talk to an
in-process fake SSH server that plays each platform's prompt and paging
behaviour. The mw tests check every rule against synthetic captures. They also
check the bundled demo against the report the original Python tool
produced from it, byte for byte.

## Status

`mw` has collected from Arista EOS and PAN-OS in production. Cisco
IOS/NX-OS/IOS-XR and Juniper Junos are only tested against the fake
server so far.

If a prompt or paging quirk bites you on real hardware, that's a
one-line fix in `netshell`'s platform profile. Open an issue with the raw
output and I'll add it.

## License

MIT - see [LICENSE](LICENSE).
