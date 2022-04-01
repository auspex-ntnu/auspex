import os
from auspex_core.gcp.auth import credentials_from_keyfile
import pytest


def test_credentials_from_keyfile():
    # TODO: set up test file for CI/CD testing
    assert credentials_from_keyfile(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))

    with pytest.raises(FileNotFoundError):
        assert credentials_from_keyfile("not_a_file")
