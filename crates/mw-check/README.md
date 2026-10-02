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

## License

MIT - see [../../LICENSE](../../LICENSE).
