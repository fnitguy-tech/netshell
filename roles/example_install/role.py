"""Stub role - replace this docstring with what this stage actually
does, why it needs to run (what it depends on having happened already),
and any non-obvious gotchas discovered the first time this ran for
real. Rename this directory (and this file's imports elsewhere) to a
real role name before writing real logic.

Every role module exposes exactly one function, `run(target, apply,
console, **kwargs)`, with this contract:
- `target`: one inventory entry (a dict - typically a VM or host record
  from inventory/vms.yml).
- `apply`: False means dry-run - describe what would happen, touch
  nothing, return status "dry_run".
- `console`: a rich.console.Console for user-facing output.
- Return a dict with at least `host` and `status` keys; `error` and
  `detail` are used by scripts/provision.py's report writer if present.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.ssh_key import run_ssh_command, SSHKeyError  # noqa: E402
from modules.inventory import load_ssh_keys  # noqa: E402


def run(target, apply, console, **kwargs):
    vm_name = target["name"]
    admin_username = target.get("admin_username", "admin")
    ip = target["network"]["ip_address"]

    if not apply:
        console.print(f"[yellow]DRY RUN[/yellow] {ip}: would <describe the real "
                       f"action here> on '{vm_name}'")
        return {"host": ip, "status": "dry_run"}

    ssh_keys = load_ssh_keys()
    key_path = ssh_keys["default"]["ssh_private_key_path"]

    try:
        result = run_ssh_command(ip, "echo replace-this-with-a-real-command",
                                 key_path=key_path, username=admin_username)
    except SSHKeyError as e:
        return {"host": ip, "status": "failed", "error": f"{vm_name}: {e}"}

    # run_ssh_command's "success" only means the command RAN (transport
    # level) - the command's own result is in returncode. Always check it.
    if result["returncode"] != 0:
        return {"host": ip, "status": "failed",
                "error": f"{vm_name}: command exited {result['returncode']}: "
                         f"{result['stderr'].strip()}"}

    return {"host": ip, "status": "success"}
