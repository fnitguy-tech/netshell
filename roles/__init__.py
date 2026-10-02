"""Explicit role registry - not filesystem auto-discovery. Fails loudly
(KeyError) on an unknown role name instead of silently skipping it.

Replace this docstring with a real description of your pipeline once
you have one: how many stages, what order they run in, and why that
order matters (e.g. "provision the VM before installing the package
onto it"). The stage count and order below are illustrative only - use
however many stages your actual provisioning goal needs, not this
number specifically.

If the project provisions brand-new hosts, its first stages are
usually the VM/OS provisioning ones; if it targets existing
infrastructure, skip those stages entirely and start with your own
first role.
"""
import sys
from pathlib import Path

# repo root on sys.path - adjust the parents[N] index if this project
# becomes a nested subdirectory inside a monorepo rather than its own
# standalone repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from roles.example_install import role as example_install  # noqa: E402

ROLES = {
    "example_install": example_install.run,
}
