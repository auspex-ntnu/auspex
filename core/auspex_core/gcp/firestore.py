import os
from functools import cache

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.async_client import AsyncClient
from google.oauth2.service_account import Credentials
from loguru import logger

from .env import GCP_PROJECT


def get_credentials() -> Credentials:
    """Retrieves GCP credentials to be used for firebase authentication.

    Uses application default credentials if running on GCP,
    otherwise falls back on JSON key file authentication.

    Returns
    -------
    `Credentials`
        Google oauth2 credentials
    """

    env = os.getenv("environment")
    logger.debug(f"environment: {env}")
    if env not in ["testing", "staging"]:
        return credentials.ApplicationDefault()
    return _credentials_from_keyfile()


def _credentials_from_keyfile() -> Credentials:
    """Instantiates GCP credentials from a JSON key file."""
    keyfile = os.getenv("SERVICE_ACCOUNT_KEYFILE")
    if not keyfile:
        return ValueError("environment variable 'SERVICE_ACCOUNT_KEYFILE' is not set")
    return Credentials.from_service_account_file(keyfile)


@cache
def get_firestore_client() -> firestore.firestore.AsyncClient:
    """Returns an Async Firestore client that can be used to interact
    with the project's firestore database.

    NOTE
    ----
    This function can block on first run. Subsequent runs are cached.

    Returns
    -------
    `firestore.firestore.AsyncClient`
        Async firestore client.
    """

    return AsyncClient(
        project=GCP_PROJECT,
        credentials=get_credentials(),
    )


# NOTE: remove?
app = firebase_admin.initialize_app(
    credentials.ApplicationDefault(),
    {
        "projectId": GCP_PROJECT,
    },
)
