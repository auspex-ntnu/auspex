from pathlib import Path
from typing import Union
from google.oauth2.service_account import Credentials
from .env import GOOGLE_APPLICATION_CREDENTIALS


def credentials_from_keyfile(filepath: Union[str, Path]) -> Credentials:
    return Credentials.from_service_account_file(filepath)
