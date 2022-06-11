from auspex_core.gcp.firestore import check_db_exists
from loguru import logger

from .config import AppConfig


async def startup_health_check() -> None:
    """Checks that the application is ready to run."""
    # Check that config works
    AppConfig()

    # Check credentials
    check_credentials_json(AppConfig().google_credentials)
    check_credentials_usable(AppConfig().google_credentials)


def check_credentials_json(credentials_file: str) -> None:
    """Checks that JSON credentials file exists and is valid JSON"""
    try:
        import json

        with open(credentials_file, "r") as f:
            json.load(f)
    except FileNotFoundError:
        logger.error("Google credentials file not found. Exiting...")
        exit(1)
    except json.JSONDecodeError:
        logger.error("Google credentials file is not valid JSON. Exiting...")
        exit(1)


def check_credentials_usable(credentials_file: str) -> None:
    """Checks that GCP credentials file is usable to construct Credentials object"""
    try:
        from google.oauth2 import service_account

        service_account.Credentials.from_service_account_file(credentials_file)
    except Exception:
        logger.error("Google credentials file is not valid. Exiting...")
        exit(1)
