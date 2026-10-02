# mw

`mw` is short for maintenance window. Capture
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

The full guide, with screenshots, install options and the inventory
and expectations formats, is the
[repository README](../../README.md). In short:

```text
mw before NET-123 -r      capture before the change, secrets stripped
mw after  NET-123 -r      capture after the change, quick text diff
mw report NET-123         the interpreted HTML report
mw demo                   the whole workflow on bundled data, no devices
```

Flags: `-u USER`, `-i FILE` (inventory), `-r` (strip secrets), `-e FILE`
(expectations, report only), `-H DIR` (demo output). Anything not given
is prompted for; the SSH password is always prompted.

## License

MIT - see [../../LICENSE](../../LICENSE).
