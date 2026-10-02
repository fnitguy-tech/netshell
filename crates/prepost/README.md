# prepost

Pre/post change validation for network maintenance windows. Capture
device state before the change, capture it again after, and turn the
difference into evidence you can attach to the ticket: a quick text
diff for the on-call view and an interpreted HTML report for everyone
else.

This is the Rust port of
[prepost-check](https://github.com/fnitguy-tech/prepost-check). It
reads the same inventory file, writes the same capture files, text diff
and HTML report, and produces the same findings, so the two can be used
interchangeably on the same `reports/` tree. SSH goes through the
[`netshell`](../netshell/) crate instead of netmiko; every command it
runs is a read-only `show`.

## One binary, four subcommands

```text
prepost precheck  [--ticket T] [--username U] [--inventory F] [--redact-secrets]
prepost postcheck [--ticket T] [--username U] [--inventory F] [--redact-secrets]
prepost compare   [--ticket T] [--inventory F] [--expectations F]
prepost demo      [--home DIR]
```

Anything not given as a flag is prompted for. The SSH password is
always prompted, never a flag. Output lands under `reports/<TICKET>/`
in the current directory, or under `$PREPOST_HOME` when that is set:

```text
reports/<TICKET>/
  Precheck/precheck_<timestamp>/<hostname>.txt   (+ .zip)
  Postcheck/postcheck_<timestamp>/<hostname>.txt (+ .zip)
  Compare/compare_<timestamp>.txt / .html
  expectations.yml   (optional, written by hand: expected BGP deltas)
```

## Try it in 60 seconds, no devices

`prepost demo` runs the whole workflow on the bundled fictional
four-device uplink migration: SSH is replaced by a stub that replays
the captures in `fixtures/NET-DEMO/`, everything else is the real code
path, and the reports land in `reports/NET-DEMO/`.

## Run it against your network

Copy `fixtures/devices.example.yml` to `inventory/devices.yml`, fill in
your management addresses, then:

```text
prepost precheck --redact-secrets
   (do the change)
prepost postcheck --redact-secrets
prepost compare
```

`--redact-secrets` replaces every password hash, BGP/OSPF key, SNMP
community and PAN-OS encrypted value with `<REDACTED>` before the
capture is written, so the zip is safe to attach to a ticket. The rules
are in `src/redact.rs`, one commented pattern per line.

## What the report interprets

Everything beyond a raw diff that the Python tool understands, ported
rule for rule:

- **BGP peers**: state changes, prefix-count deltas correlated with
  the BGP-relevant config lines that changed, a session whose uptime
  went backwards (a reset the summary table would otherwise hide),
  peers that appeared or vanished.
- **Prefix lists**: a withdrawn entry or a same-sequence overwrite is
  `Attention`; a resequenced entry is `Changed`; an added one `Stable`.
- **Pair symmetry**: same-named prefix-lists, route-maps and PAN-OS HA
  state compared across each redundant pair (inferred from hostnames
  that differ only by a trailing number, or listed under `pairs:` in
  the inventory). A divergence is reported on both members.
- **Interfaces** that gained an address during the window and are
  still down.
- **Expectations**: `reports/<TICKET>/expectations.yml` states the
  intended prefix deltas per peer; matching deltas are rated `Stable`
  "as planned", the rest `Attention`.

## Layout

```text
src/main.rs           clap: precheck, postcheck, compare, demo
src/commands/         one module per subcommand
src/inventory.rs      loads + validates inventory/devices.yml
src/collect.rs        parallel SSH capture (netshell), zip packaging
src/redact.rs         --redact-secrets rules
src/capture.rs        the "### command ###" capture file format
src/textcompare.rs    normalization rules + quick .txt diff report
src/analysis/         parsers, findings, pair symmetry, impact scoring
src/expectations.rs   expected BGP prefix deltas for one change
src/report.rs         the self-contained HTML report
src/layout.rs         reports/<TICKET>/ directory conventions
src/vpn.rs            IPsec/IKE/LSVPN churn rule shared by both views
fixtures/NET-DEMO/    the demo captures and the Python tool's reports for them
```

## License

MIT - see [../../LICENSE](../../LICENSE).
