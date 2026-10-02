"""Rename this file to match your real role name once example_install
is renamed. Mock SSH/network calls - never let a test suite touch real
infrastructure."""
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from roles.example_install import role  # noqa: E402


FIXTURE_VM = {
    "name": "example-vm-01",
    "admin_username": "admin",
    "network": {"ip_address": "192.0.2.99"},
}


class FakeConsole:
    def print(self, *args, **kwargs):
        pass


def test_dry_run_does_not_call_ssh():
    with mock.patch("roles.example_install.role.run_ssh_command") as mock_ssh:
        result = role.run(FIXTURE_VM, apply=False, console=FakeConsole())
    mock_ssh.assert_not_called()
    assert result["status"] == "dry_run"


def test_apply_success():
    with mock.patch("roles.example_install.role.load_ssh_keys") as mock_keys, \
         mock.patch("roles.example_install.role.run_ssh_command") as mock_ssh:
        mock_keys.return_value = {"default": {"ssh_private_key_path": "/fake/key"}}
        mock_ssh.return_value = {"success": True, "stdout": "", "stderr": "", "returncode": 0}
        result = role.run(FIXTURE_VM, apply=True, console=FakeConsole())
    assert result["status"] == "success"


def test_apply_nonzero_returncode_is_failed():
    # run_ssh_command returns success=True whenever the command RAN -
    # the role must check returncode itself, not trust "success".
    with mock.patch("roles.example_install.role.load_ssh_keys") as mock_keys, \
         mock.patch("roles.example_install.role.run_ssh_command") as mock_ssh:
        mock_keys.return_value = {"default": {"ssh_private_key_path": "/fake/key"}}
        mock_ssh.return_value = {"success": True, "stdout": "",
                                 "stderr": "boom", "returncode": 1}
        result = role.run(FIXTURE_VM, apply=True, console=FakeConsole())
    assert result["status"] == "failed"
    assert "boom" in result["error"]


def test_apply_failure_returns_failed_status_not_exception():
    from roles.example_install.role import SSHKeyError
    with mock.patch("roles.example_install.role.load_ssh_keys") as mock_keys, \
         mock.patch("roles.example_install.role.run_ssh_command") as mock_ssh:
        mock_keys.return_value = {"default": {"ssh_private_key_path": "/fake/key"}}
        mock_ssh.side_effect = SSHKeyError("connection refused")
        result = role.run(FIXTURE_VM, apply=True, console=FakeConsole())
    assert result["status"] == "failed"
    assert "connection refused" in result["error"]
