#!/usr/bin/env python3
"""Write the Python tool's output for the parity fixtures.

The Rust tests in crates/mw-check/tests/ compare mw's output to these
files byte for byte. Run it with Python 3.12 from a clean checkout of
prepost-check (see README.md next to this file for the exact command).

Arguments: the prepost-check checkout, then the mw-check crate folder.
"""

import io
import os
import random
import shutil
import sys
import types

PPC, CRATE = (os.path.abspath(arg) for arg in sys.argv[1:3])
sys.path.insert(0, PPC)

from rich.console import Console  # noqa: E402

from modules import captures, difftrim, htmlreport, layout, redact, textcompare  # noqa: E402
from modules.captures import section_header  # noqa: E402

PARITY = os.path.join(CRATE, "fixtures", "parity")
REDACT_DIR = os.path.join(CRATE, "tests", "fixtures_collect")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        file.write(text)


# --- device scenarios --------------------------------------------------

BGP_HEADER = "  Neighbor         V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc"


def capture(hostname, address, bgp_rows, config_lines):
    return (
        f"Hostname: {hostname}\nIP Address: {address}\nGenerated: 2026-04-14 08:48:02.123456\n" + "=" * 80 + "\n"
        "\n\n" + section_header("show ip bgp summary") + "\n".join([BGP_HEADER, *bgp_rows]) + "\n"
        "\n\n" + section_header("show running-config") + "\n".join(config_lines) + "\n"
    )


def config(hostname, extra=()):
    return [
        f"hostname {hostname}",
        "banner login",
        "### AUTHORIZED USE ONLY ###",
        "EOF",
        "router bgp 65001",
        "   neighbor 203.0.113.1 remote-as 65010",
        *extra,
    ]


ESTAB = "  203.0.113.1      4  65010          1234      1230    0    0 5d02h    Estab   100    98"
IDLE = "  203.0.113.1      4  65010          1234      1230    0    0 00:02:10 Idle(Admin)"


def scenario(ticket, pre_name, post_name, fill, markers=("precheck", "postcheck"), stamp="2026-04-14_10-45-00"):
    """Build one ticket's folders, then both reports, the way the
    scripts do. Everything lands under fixtures/parity/reports/."""
    base = os.path.join(PARITY, "reports", ticket)
    shutil.rmtree(base, ignore_errors=True)

    dirs = {
        "precheck": os.path.join(base, "Precheck"),
        "postcheck": os.path.join(base, "Postcheck"),
        "compare": os.path.join(base, "Compare"),
    }
    pre_run = os.path.join(dirs["precheck"], pre_name)
    post_run = os.path.join(dirs["postcheck"], post_name)
    os.makedirs(pre_run)
    os.makedirs(post_run)
    fill(pre_run, post_run)

    # The marker carries the time it was written, so the fixture keeps
    # a fixed one. Only its presence matters to the reports.
    for phase, folder in (("precheck", pre_run), ("postcheck", post_run)):
        if phase in markers:
            write(
                os.path.join(folder, captures.COMPLETE_MARKER),
                '{\n  "phase": "%s",\n  "finished": "2026-04-14 10:43:00",\n  "devices": 3\n}\n' % phase,
            )

    console = Console(file=io.StringIO(), width=300)
    textcompare.write_compare_report(ticket, dirs, stamp, console)
    htmlreport.build_html_report(ticket, dirs, stamp, console)
    write(os.path.join(dirs["compare"], "console.txt"), console.file.getvalue())


def fill_failed(pre_run, post_run):
    """One device unreachable after the change, one missing, one new,
    and one captured both times with a real change in it."""
    write(os.path.join(pre_run, "SW-1.txt"), capture("SW-1", "10.0.0.5", [ESTAB], config("SW-1")))
    write(os.path.join(pre_run, "SW-2.txt"), capture("SW-2", "10.0.0.6", [ESTAB], config("SW-2")))
    write(os.path.join(pre_run, "SW-3.txt"), capture("SW-3", "10.0.0.7", [ESTAB], config("SW-3")))
    write(
        os.path.join(post_run, "SW-2.txt"),
        capture("SW-2", "10.0.0.6", [IDLE], config("SW-2", ["   neighbor 203.0.113.1 shutdown"])),
    )
    write(os.path.join(post_run, "SW-9.txt"), capture("SW-9", "10.0.0.9", [ESTAB], config("SW-9")))
    captures.write_failed(
        post_run,
        "10.0.0.5",
        captures.FAILED_FIRST_LINE,
        "could not connect to 10.0.0.5:22: Connection refused (os error 111)\n\n"
        "Device settings: arista_eos 10.0.0.5:22 <admin & \"ops\">\n",
    )


def fill_stale(pre_run, post_run):
    """The before folder is newer than the after folder and was cut
    short. One device failed both times, one was never attempted, one
    failed only before, and one has an IPv6 address."""
    write(os.path.join(pre_run, "SW-1.txt"), capture("SW-1", "10.0.0.5", [ESTAB], config("SW-1")))
    write(os.path.join(post_run, "SW-1.txt"), capture("SW-1", "10.0.0.5", [ESTAB], config("SW-1")))
    write(os.path.join(post_run, "LATE.txt"), capture("LATE", "10.0.0.3", [ESTAB], config("LATE")))
    write(os.path.join(pre_run, "V6.txt"), capture("V6", "2001:db8::5", [ESTAB], config("V6")))
    captures.write_failed(pre_run, "10.0.0.3", captures.FAILED_FIRST_LINE, "timed out\n")
    captures.write_failed(pre_run, "10.0.0.4", captures.FAILED_FIRST_LINE, "timed out\n")
    captures.write_failed(post_run, "10.0.0.4", captures.FAILED_FIRST_LINE, "timed out again\n")
    captures.write_failed(pre_run, "10.0.0.8", captures.FAILED_FIRST_LINE, "timed out\n")
    captures.write_failed(
        post_run,
        "10.0.0.9",
        captures.NOT_ATTEMPTED_FIRST_LINE,
        "Not tried, because 10.0.0.4 rejected the username or password. "
        "Trying it on more devices could lock the account.\n",
    )
    captures.write_failed(post_run, "2001:db8::5", captures.FAILED_FIRST_LINE, "no route to host\n")


def device_scenarios():
    # Paths in both reports are shown relative to the repo root; point
    # it at the fixture folder so they read "reports/<TICKET>/...".
    layout.REPO_ROOT = PARITY
    scenario("NET-FAIL", "precheck_2026-04-14_08-48-05", "postcheck_2026-04-14_10-42-10", fill_failed)
    scenario(
        "NET-STALE",
        "precheck_2026-04-14_10-40-00",
        "postcheck_2026-04-14_08-50-00",
        fill_stale,
        markers=("postcheck",),
    )


# --- the diff cap ------------------------------------------------------

def config_lines(count, tag):
    rng = random.Random(tag)
    return [
        f"   neighbor 10.{i // 250}.{i % 250}.{rng.randint(1, 250)} description {tag}-{rng.randint(0, 10**6)}"
        for i in range(count)
    ]


def ndiff_cap():
    """A replaced block just over the cap (200 x 201 = 40,200 pairs),
    one at the cap (200 x 200), and one over it with the longer side
    first, each between lines that didn't change."""
    cases = {
        "over": (config_lines(200, "old"), config_lines(201, "new")),
        "at": (config_lines(200, "old"), config_lines(200, "new")),
        "longer_old": (config_lines(300, "old"), config_lines(200, "new")),
    }

    for name, (old, new) in cases.items():
        a = ["router bgp 65001", *old, "end"]
        b = ["router bgp 65001", *new, "end"]
        folder = os.path.join(PARITY, "ndiff_cap")
        write(os.path.join(folder, f"{name}_a.txt"), "\n".join(a) + "\n")
        write(os.path.join(folder, f"{name}_b.txt"), "\n".join(b) + "\n")
        # Both reports drop difflib's "? " hint lines, and mw's port
        # never makes them, so the fixture holds the lines that are kept.
        kept = [line for line in difftrim.ndiff(a, b) if not line.startswith("? ")]
        write(os.path.join(folder, f"{name}_expected.txt"), "\n".join(kept) + "\n")


# --- redaction ---------------------------------------------------------

MARKER = "! --- review corpus: one line per rule, from prepost-check tests/test_redact.py ---"

LOOKALIKES = [
    " vrrp 10 authentication md5 key-chain VRRP-CHAIN",
    " standby 10 authentication md5 key-chain HSRP-CHAIN",
    "snmp-server host 10.0.0.9 version 3 priv snmpuser",
    "   authentication-key-chain BGP-CHAIN;",
    "crypto isakmp policy 10",
    " authentication pre-share",
    "<public-key>AAAAB3NzaC1yc2EAAAADAQAB</public-key>",
    " key 1",
    " tunnel key 4242",
]

ONE_LINE_PEM = "key: -----BEGIN EC PRIVATE KEY-----OneLineBody43-----END EC PRIVATE KEY----- done"
QUOTED_PEM = (
    'set shared certificate C private-key "-----BEGIN PRIVATE KEY-----\nQuotedKeyBody42\n-----END PRIVATE KEY-----"\nnext'
)
CUT_OFF_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nCutOffBody44\nCutOffBody45"


def redaction():
    # tests/test_redact.py imports pytest only for its decorators.
    stub = types.ModuleType("pytest")
    stub.mark = types.SimpleNamespace(parametrize=lambda *_a, **_k: (lambda function: function))
    sys.modules.setdefault("pytest", stub)
    from tests import test_redact

    corpus_path = os.path.join(REDACT_DIR, "redact_corpus.txt")
    with open(corpus_path, encoding="utf-8") as file:
        base = file.read().split("\n" + MARKER + "\n")[0].rstrip("\n")

    # One line each, so the Rust test can also check them one at a time.
    # Every expected line goes in again as input: a second run must
    # change nothing.
    review = [line for line, _secret, _expected in test_redact.CORPUS]
    review += [expected for _line, _secret, expected in test_redact.CORPUS]
    review += LOOKALIKES + [ONE_LINE_PEM]

    corpus = base + "\n" + MARKER + "\n" + "\n".join(review) + "\n"
    write(corpus_path, corpus)
    write(os.path.join(REDACT_DIR, "redact_expected.txt"), redact.scrub(corpus))

    # Secrets that need the lines around them: checked as one text.
    blocks = "\n".join([test_redact.IOS_XE_BLOCKS + test_redact.PEM_TEXT, QUOTED_PEM, CUT_OFF_PEM])
    write(os.path.join(REDACT_DIR, "redact_blocks_corpus.txt"), blocks)
    write(os.path.join(REDACT_DIR, "redact_blocks_expected.txt"), redact.scrub(blocks))


if __name__ == "__main__":
    assert sys.version_info[:2] == (3, 12), "difflib changed in 3.13; generate under Python 3.12"
    device_scenarios()
    ndiff_cap()
    redaction()
    print("parity fixtures written under", PARITY, "and", REDACT_DIR)
