# Parity fixtures

**These files are what the Python tool writes, kept so `mw` can be
checked against it byte for byte.** If the two tools ever drift, a test
fails and names the first line that differs.

The bundled demo covers a clean run. These cover what the demo doesn't
reach.

## What's here

| Folder | What it holds | The test that reads it |
|--------|---------------|------------------------|
| `reports/NET-FAIL/` | Captures where one device is unreachable after the change (`10.0.0.5_FAILED.txt`), one is missing (`SW-3`), and one is new (`SW-9`). `Compare/` holds Python's text report, HTML report, and console output. | `tests/parity_python.rs` |
| `reports/NET-STALE/` | A before folder that's newer than the after folder and has no completion marker. Devices that failed both times, were never attempted, or have an IPv6 address. Same three files in `Compare/`. | `tests/parity_python.rs` |
| `ndiff_cap/` | Three replaced blocks: 200 by 200 lines (at the 40,000-pair cap), 200 by 201 (just over), and 300 by 200 (over, longer side first). Each has an `_a`, a `_b`, and Python's `_expected` diff. | `tests/parity_python.rs` |

The same script also writes the redaction files in
`tests/fixtures_collect/`:

| File | What it holds |
|------|---------------|
| `redact_corpus.txt` | One secret per line. `mw` checks these one line at a time. |
| `redact_expected.txt` | What Python's `redact.scrub` returns for that file. |
| `redact_blocks_corpus.txt` | Secrets that need the lines around them: IOS-XE server blocks and PEM private keys. |
| `redact_blocks_expected.txt` | What Python returns for that file. |

Every hostname, address, and secret in these files is made up.

## How they were generated

`generate.py` in this folder writes all of them. It imports the Python
tool's own modules, so the output is Python's, not a copy of the rules.

Use Python 3.12. Python 3.13 changed `difflib`, and the diffs would no
longer match. Use a clean clone of prepost-check too, so its local
`reports/` folder can't leak in.

From the root of this repository:

```text
git clone -q https://github.com/fnitguy-tech/prepost-check /tmp/ppc-clean
podman run --rm \
  -v /tmp/ppc-clean:/src:ro,z \
  -v "$PWD/crates/mw-check:/crate:z" \
  -w /src docker.io/library/python:3.12-slim \
  bash -c "pip install -q -r requirements.txt && python /crate/fixtures/parity/generate.py /src /crate"
```

Then run `cargo test -p mw-check`. A change in Python's output shows up
as a failing test.

The demo fixture in `fixtures/NET-DEMO/expected/` is made the same way,
with `python scripts/demo.py` in that clone. Copy
`reports/NET-DEMO/Compare/compare_*.html` and `compare_*.txt` over
`compare.html` and `compare.txt`.

## What changes on each run

Only one thing: the `Generated <time>` line in the footer of each HTML
report. The tests read that time from the fixture, so it doesn't matter.
The captures and the completion markers carry fixed times.
