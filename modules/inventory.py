"""Inventory loaders - plain YAML files under inventory/, gitignored
except the *.example.yml templates. Copy an .example.yml to a real
filename and fill it in before running anything with --apply.
"""
from pathlib import Path

import yaml

INVENTORY_DIR = Path(__file__).resolve().parents[1] / "inventory"


def _load_yaml(filename):
    path = INVENTORY_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found - copy {filename.replace('.yml', '.example.yml')} "
            f"to {filename} and fill it in first."
        )
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_vms():
    return _load_yaml("vms.yml").get("vms", {})


def load_hypervisors():
    return _load_yaml("hypervisors.yml").get("hypervisors", {})


def load_ssh_keys():
    return _load_yaml("ssh_keys.yml").get("keys", {})


def get_vm(name, vms):
    if name not in vms:
        raise KeyError(f"{name} not found in inventory/vms.yml")
    target = dict(vms[name])
    target["name"] = name
    return target


def get_hypervisor(name, hypervisors):
    if name not in hypervisors:
        raise KeyError(f"{name} not found in inventory/hypervisors.yml")
    target = dict(hypervisors[name])
    target["name"] = name
    return target
