from functools import cache

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1 import DocumentSnapshot
from google.cloud.firestore_v1.async_client import AsyncClient
from loguru import logger

from .env import GCP_PROJECT


@cache
def get_firestore_client() -> firestore.firestore.AsyncClient:
    """Returns an Async Firestore client that can be used to interact
    with the project's firestore database.

    NOTE
    ----
    This function can block on first run (which is fine).
    Subsequent calls return cached client.

    Returns
    -------
    `firestore.firestore.AsyncClient`
        Async firestore client.
    """

    return AsyncClient(
        project=GCP_PROJECT,
    )


# NOTE: remove?
app = firebase_admin.initialize_app(
    credentials.ApplicationDefault(),
    {
        "projectId": GCP_PROJECT,
    },
)


async def get_document(collection_name: str, document_id: str) -> DocumentSnapshot:
    db = get_firestore_client()
    # Get firestore document
    docpath = f"{collection_name}/{document_id}"
    logger.debug(f"Fetching {docpath}")
    d = db.document(docpath)
    doc = await d.get()  # type: DocumentSnapshot
    if not doc.exists:
        raise ValueError("Document not found.")
    return doc
