# mw

`mw` is short for maintenance window. Capture your devices before the
change, capture them again after, and get told what actually changed - a
quick text diff for the on-call view, and an interpreted HTML report you
can attach to the ticket.

This is the Rust port of
[prepost-check](https://github.com/fnitguy-tech/prepost-check). It reads
the same inventory file and writes the same capture files, text diff, and
HTML report. The findings match too, so you can use either one on the
same `reports/` tree.

SSH goes through the [`netshell`](../netshell/) crate instead of netmiko.
Every command it runs is a read-only `show`.

The full guide, with screenshots, install options, and the inventory
and notes formats, is the
[repository README](../../README.md). In short:

```text
mw before NET-123 -r      capture before the change, secrets stripped
mw after  NET-123 -r      capture after the change, quick text diff
mw notes  NET-123         start the write-up for the window
mw report NET-123         the interpreted HTML report
mw demo                   the whole workflow on bundled data, no devices
```

Flags: `-u USER`, `-i FILE` (inventory), `-r` (strip secrets), `-n FILE`
(notes, report only), `-H DIR` (demo output). Anything not given is
prompted for; the SSH password is always prompted.

## Did the capture work?

**The last lines of `mw before` or `mw after` tell you.** A capture that
missed a device is not a baseline, and you want to know before the
window closes.

```text
INCOMPLETE
7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
Precheck ZIP created: reports/NET-123/Precheck/precheck_2026-04-14_08-48-05.zip
```

`SUCCESS` prints only when every device was captured in full.

| Exit code | What happened | Example summary line |
|-----------|---------------|----------------------|
| `0` | Every device was captured in full. | `8 of 8 captured.` |
| `1` | Some devices were captured, and some weren't. | `7 of 8 captured; 1 failed: 10.0.0.5 (unreachable)` |
| `2` | No device was captured. | `0 of 8 captured; 1 failed: 10.0.0.5 (authentication failed); 7 not attempted` |

Three things keep a bad run from looking like a good one:

- **A wrong password is tried once.** The first connection goes alone.
  If that device rejects the password, no more are tried, so a typo
  can't lock your account. The skipped devices are recorded as
  `NOT ATTEMPTED`.
- **A slow command can't shift later answers.** If `show ip bgp` runs
  past the 180-second limit, the rest of that device's commands are
  written as `SKIPPED after timeout on show ip bgp`, and the device
  counts as incomplete.
- **A device you couldn't check is never reported as fine.** A device
  that failed, went missing, or is new is rated `Action Required` and
  listed first in both reports, under "Devices Not Verified".

## SSH host keys

**Each device's host key is checked before your password is sent.** The
first connect saves the key. A different key later refuses the
connection, with the reason `host key changed`.

One line per device, in `~/.config/mw/known_hosts` (on Windows,
`%APPDATA%\mw\known_hosts`):

```text
192.0.2.11:22 ssh-ed25519 SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
```

| Flag or variable | What you get |
|------------------|--------------|
| `--known-hosts FILE` | Another file for this run. |
| `MW_KNOWN_HOSTS` | Another file for every run. The flag wins over it. |
| `--accept-new-host-key HOST` | That one device's changed key is accepted and saved. Use it after you replace or re-image a device. |
| `--insecure-accept-any-host-key` | No checking, and nothing saved. Lab use only. |
| `--legacy-algorithms` | Old SHA-1 and CBC algorithms are offered too, for devices with nothing newer. |
| `--enable` | You're prompted for the enable secret, for logins that land at `RTR-1>`. |
| `--user-mode` | The capture stays at `RTR-1>` and says which commands failed. |

`mw` keeps its own file. It doesn't read `~/.ssh/known_hosts`, and it
doesn't share a file with `netshell` or prepost-check.

## Tests and parity

`cargo test -p mw-check` runs offline. The reports are checked byte for
byte against what the Python tool wrote for the same captures: the
bundled demo, plus the failed-device and stale-baseline runs in
[`fixtures/parity/`](fixtures/parity/README.md).

## License

MIT - see [../../LICENSE](../../LICENSE).
