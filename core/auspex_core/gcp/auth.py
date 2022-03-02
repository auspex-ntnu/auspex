from pathlib import Path
from typing import Union
from google.oauth2.service_account import Credentials
from .env import SERVICE_ACCOUNT_KEYFILE


def credentials_from_env() -> Credentials:
    """Instantiates GCP credentials from a JSON key file."""
    if not SERVICE_ACCOUNT_KEYFILE:
        return ValueError(
            "environment variable 'SERVICE_ACCOUNT_KEYFILE' is not set. "
            "Unable to create credentials from keyfile."
        )
    return _credentials_from_keyfile(SERVICE_ACCOUNT_KEYFILE)


def _credentials_from_keyfile(filepath: Union[str, Path]) -> Credentials:
    return Credentials.from_service_account_file(filepath)
