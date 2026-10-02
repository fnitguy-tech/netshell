"""OpenBao secrets access - the "stop using local credential files"
entry point. OpenBao is the PRIMARY secrets mechanism, not a
fallback: when this project needs a new credential (service password,
API token, bind account), seed it into OpenBao first; a gitignored
local inventory file holds at most a *reference* to it or serves as the
offline fallback.

API: get_secret(), SecretsClientError, SecretNotFoundError. Wraps
`hvac` (the Vault-API-compatible Python client - works against OpenBao
unchanged) with AppRole login and a KV-v2 read. Self-contained on
purpose - see modules/ssh_key.py's docstring for the convention.

Configuration - deliberately NO hardcoded environment-specific defaults
anywhere ("env override -> local file -> error, never guess"):

1. OPENBAO_ADDR - env var, required. The OpenBao server URL, e.g.
   https://vault.example.internal (mind the cert's SAN - use the name
   the cert actually carries).
2. OPENBAO_CACERT - env var, required. Path to a local copy of the
   server's TLS CA cert, or the literal string "insecure" to disable
   verification (loudly warned every time, never silent).
3. role_id - OPENBAO_ROLE_ID env var, OR an `openbao_role_id:` key in
   the gitignored inventory/openbao_approle.yml (role_id is a stable
   non-secret identifier by OpenBao's own design, so either is fine).
4. secret_id - OPENBAO_SECRET_ID env var ONLY. Deliberately never read
   from any file this module locates - same tier as any credential this
   repo never writes to disk in plaintext. Leaking one is a "rotate it"
   problem, not a "rebuild everything" problem.

Missing any of these raises SecretsClientError naming exactly which
value is missing.
"""
import os
from pathlib import Path

import hvac
import yaml

# Anchored to the repo, not the CWD, so get_secret() works no matter
# which directory a script is launched from.
APPROLE_INVENTORY_PATH = Path(__file__).resolve().parents[1] / "inventory" / "openbao_approle.yml"

__all__ = ["get_secret", "SecretsClientError", "SecretNotFoundError"]


class SecretsClientError(Exception):
    pass


class SecretNotFoundError(SecretsClientError):
    """The path itself does not exist - nothing was ever written there.

    A SUBCLASS, deliberately, so `except SecretsClientError` keeps
    catching it. It exists because "this optional integration was never
    configured" and "OpenBao is sealed, down, or refusing our token" are
    opposite situations the base class conflates: never-seeded is a
    stable fact about the deployment a caller may (loudly) skip an
    optional integration over; an outage is TRANSIENT and says nothing
    about whether the secret exists - treating it as "not configured"
    would silently deploy a degraded config on every vault hiccup.

    So: catch this subclass to tolerate absence of a genuinely optional
    secret. Never catch the base class to mean "no secret, use a
    default" - it means something is genuinely wrong; report it, stop."""


def _role_id_from_inventory_file(path=None):
    # path=None (not path=APPROLE_INVENTORY_PATH) deliberately - a default
    # bound at definition time would freeze the module-load-time value,
    # making it impossible for a test to override the module-level
    # constant and have this function see the change.
    if path is None:
        path = APPROLE_INVENTORY_PATH
    if not path.exists():
        return None
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return data.get("openbao_role_id")


def get_addr():
    addr = os.environ.get("OPENBAO_ADDR")
    if not addr:
        raise SecretsClientError(
            "OPENBAO_ADDR is not set - point it at the OpenBao server this "
            "project should use (the full https:// URL)"
        )
    return addr


def get_verify():
    cacert = os.environ.get("OPENBAO_CACERT")
    if not cacert:
        raise SecretsClientError(
            "OPENBAO_CACERT is not set - point it at a local copy of the OpenBao server's "
            "TLS cert, or set it to the literal string 'insecure' to explicitly disable "
            "verification (not recommended, logged loudly if used)"
        )
    if cacert == "insecure":
        import warnings
        warnings.warn(
            "OPENBAO_CACERT=insecure - TLS verification is DISABLED for this OpenBao "
            "connection. This should never be used against a real deployment.",
            stacklevel=2,
        )
        return False
    return cacert


def get_role_id():
    role_id = os.environ.get("OPENBAO_ROLE_ID") or _role_id_from_inventory_file()
    if not role_id:
        raise SecretsClientError(
            "no AppRole role_id found - set OPENBAO_ROLE_ID or add openbao_role_id: "
            f"to {APPROLE_INVENTORY_PATH}"
        )
    return role_id


def get_secret_id():
    secret_id = os.environ.get("OPENBAO_SECRET_ID")
    if not secret_id:
        raise SecretsClientError(
            "OPENBAO_SECRET_ID is not set - this is deliberately environment-variable-only, "
            "never read from a file (see this module's docstring). Export it from wherever "
            "your shell/wrapper keeps it before running this script."
        )
    return secret_id


def get_secret(path, mount_point="secret"):
    """Authenticates via AppRole and reads a KV-v2 secret at
    {mount_point}/data/{path}, returning its data dict.

    Raises SecretsClientError on missing configuration, auth failure, or
    an unreachable/misconfigured server, and the SecretNotFoundError
    subclass only for a path that was never seeded - see the class
    docstrings above for which one a caller may catch, and why."""
    addr = get_addr()
    verify = get_verify()
    role_id = get_role_id()
    secret_id = get_secret_id()

    client = hvac.Client(url=addr, verify=verify)

    try:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    except hvac.exceptions.VaultError as e:
        raise SecretsClientError(f"AppRole login to {addr} failed: {e}") from e

    if not client.is_authenticated():
        raise SecretsClientError(f"AppRole login to {addr} did not produce an authenticated client")

    try:
        response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)
    except hvac.exceptions.InvalidPath as e:
        raise SecretNotFoundError(f"no secret found at {mount_point}/data/{path}: {e}") from e
    except hvac.exceptions.VaultError as e:
        raise SecretsClientError(f"reading {mount_point}/data/{path} from {addr} failed: {e}") from e

    return response["data"]["data"]
