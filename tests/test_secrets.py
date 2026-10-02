"""modules/secrets.py configuration discovery - pure env/file logic, no
OpenBao server involved. Nothing here (or anywhere in tests/) may touch
real infrastructure."""
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import secrets  # noqa: E402


def test_missing_addr_raises_naming_the_variable():
    with mock.patch.dict("os.environ", {}, clear=True):
        with pytest.raises(secrets.SecretsClientError, match="OPENBAO_ADDR"):
            secrets.get_addr()


def test_missing_secret_id_raises_naming_the_variable():
    with mock.patch.dict("os.environ", {}, clear=True):
        with pytest.raises(secrets.SecretsClientError, match="OPENBAO_SECRET_ID"):
            secrets.get_secret_id()


def test_cacert_insecure_disables_verification_loudly():
    with mock.patch.dict("os.environ", {"OPENBAO_CACERT": "insecure"}):
        with pytest.warns(UserWarning, match="DISABLED"):
            assert secrets.get_verify() is False


def test_role_id_env_var_beats_inventory_file(tmp_path):
    approle = tmp_path / "openbao_approle.yml"
    approle.write_text("openbao_role_id: from-file\n")
    with mock.patch.object(secrets, "APPROLE_INVENTORY_PATH", approle):
        with mock.patch.dict("os.environ", {"OPENBAO_ROLE_ID": "from-env"}):
            assert secrets.get_role_id() == "from-env"
        with mock.patch.dict("os.environ", {}, clear=True):
            assert secrets.get_role_id() == "from-file"


def test_not_found_is_a_subclass_so_base_handlers_still_catch_it():
    # The contract optional-integration callers rely on: catching the
    # base class must also catch "never seeded".
    assert issubclass(secrets.SecretNotFoundError, secrets.SecretsClientError)
