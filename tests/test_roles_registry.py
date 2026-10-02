"""Asserts every registered role has the right run() signature - catches
a typo'd registry entry or a role that drifted from the shared contract."""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from roles import ROLES  # noqa: E402

REQUIRED_PARAMS = {"target", "apply", "console"}


def test_every_role_has_the_shared_signature():
    for name, fn in ROLES.items():
        params = set(inspect.signature(fn).parameters)
        missing = REQUIRED_PARAMS - params
        assert not missing, f"role '{name}' is missing required params: {missing}"


def test_roles_dict_is_not_empty():
    assert ROLES, "ROLES registry is empty - register at least one role"
