#!/usr/bin/env python3
"""Orchestrator CLI: --role <name> --host <vm_name>|--all [--apply].
Dry-run by default. Loads inventory, calls the selected role's run()
once per target, writes a Markdown report to reports/.

--host is a VM/host name - a key in inventory/vms.yml.

Adjust build_role_kwargs() once your roles need arguments beyond
`target`/`apply`/`console` (e.g. a hypervisor lookup for a
vm_provision-style stage, or a secret passed via --root-token-style
flag). Add matching argparse arguments below.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console  # noqa: E402

from modules.inventory import load_vms, load_hypervisors, get_vm, get_hypervisor  # noqa: E402
from modules.report import write_report  # noqa: E402
from roles import ROLES  # noqa: E402

console = Console()

BAD_STATUSES = ("failed", "error", "not_in_inventory")


def build_role_kwargs(role_name, target, args, hypervisors):
    # Add per-role kwarg construction here as roles need it, e.g.:
    # if role_name == "vm_provision":
    #     hv_name = target.get("hypervisor")
    #     return {"hypervisor": get_hypervisor(hv_name, hypervisors) if hv_name else None}
    return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=sorted(ROLES.keys()))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="VM/host name, a key in inventory/vms.yml")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--apply", action="store_true", help="Default is dry-run")
    args = parser.parse_args()

    vms = load_vms()
    try:
        hypervisors = load_hypervisors()
    except FileNotFoundError:
        # Optional - only needed if a role provisions new VMs (see
        # build_role_kwargs). Projects that only target existing
        # infrastructure can delete inventory/hypervisors.example.yml
        # entirely without needing an empty hypervisors.yml in its place.
        hypervisors = {}

    names = list(vms.keys()) if args.all else [args.host]
    role_fn = ROLES[args.role]

    results = []
    for vm_name in names:
        if vm_name not in vms:
            console.print(f"[red]{vm_name} not found in inventory/vms.yml, skipping[/red]")
            results.append({"host": vm_name, "status": "not_in_inventory", "error": ""})
            continue

        target = get_vm(vm_name, vms)

        try:
            kwargs = build_role_kwargs(args.role, target, args, hypervisors)
            result = role_fn(target, args.apply, console, **kwargs)
        except Exception as e:  # noqa: BLE001 - report and continue to next host, never abort the batch
            console.print(f"[red]{vm_name}: unhandled exception - {e}[/red]")
            result = {"host": vm_name, "status": "error", "error": str(e)}

        results.append(result)

    report_path = write_report(
        f"provision_{args.role}_report",
        results,
        columns=["host", "status", "error", "detail"],
    )
    console.print(f"[cyan]Report written: {report_path}[/cyan]")

    if any(r.get("status") in BAD_STATUSES for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
