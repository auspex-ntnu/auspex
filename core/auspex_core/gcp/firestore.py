from functools import cache

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1 import DocumentSnapshot
from google.cloud.firestore_v1.async_client import AsyncClient
from google.oauth2.service_account import Credentials
from loguru import logger

from .auth import credentials_from_env
from .env import GCP_PROJECT, SERVICE_ACCOUNT_KEYFILE


def get_credentials() -> Credentials:
    """Retrieves GCP credentials to be used for firebase authentication.

    Uses application default credentials if running on GCP,
    otherwise falls back on JSON key file authentication.

    Returns
    -------
    `Credentials`
        Google oauth2 credentials
    """
    if SERVICE_ACCOUNT_KEYFILE:
        return credentials_from_env()
    return credentials.ApplicationDefault()


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


def get_firestore_logs_docpath(collection_name: str, document_id: str) -> str:
    return f"{collection_name}/{document_id}"


async def get_document(collection_name: str, document_id: str) -> DocumentSnapshot:
    db = get_firestore_client()
    # Get firestore document
    docpath = get_firestore_logs_docpath(collection_name, document_id)
    logger.debug(f"Fetching {docpath}")
    d = db.document(docpath)
    doc = await d.get()  # type: DocumentSnapshot
    if not doc.exists:
        raise ValueError("Document not found.")
    return doc
