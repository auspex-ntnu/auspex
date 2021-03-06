import os
from functools import cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from google.cloud.firestore_v1.async_query import AsyncQuery

import aiohttp
import backoff
import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import ServerError
from google.cloud.firestore_v1 import DocumentSnapshot
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.async_document import AsyncDocumentReference
from loguru import logger

# TODO: refactor. Pass this in as a parameter where required.
GOOGLE_CLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")


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
        project=GOOGLE_CLOUD_PROJECT,
    )


# NOTE: remove?
app = firebase_admin.initialize_app(
    credentials.ApplicationDefault(),
    {
        "projectId": GOOGLE_CLOUD_PROJECT,
    },
)


@backoff.on_exception(
    backoff.expo,
    exception=(aiohttp.ClientResponseError, ServerError),
    max_tries=5,
    jitter=backoff.full_jitter,
)
async def get_document(collection_name: str, document_id: str) -> DocumentSnapshot:
    db = get_firestore_client()
    # Get firestore document
    docpath = f"{collection_name}/{document_id}"
    logger.debug(f"Fetching {docpath}")
    d = db.document(docpath)
    doc = await d.get()  # type: DocumentSnapshot
    if not doc.exists:
        raise ValueError(f"Document '{document_id}' not found.")
    return doc


@backoff.on_exception(
    backoff.expo,
    exception=(aiohttp.ClientResponseError, ServerError),
    max_tries=5,
    jitter=backoff.full_jitter,
)
async def add_document(
    collection_name: str, data: dict[str, Any]
) -> AsyncDocumentReference:
    db = get_firestore_client()
    d = db.collection(collection_name).document()
    await d.set(data)
    logger.debug(f"Added {collection_name}/{d.id}")
    return d


async def check_db_exists(collection: str) -> bool:
    """Checks if the database is available."""
    try:
        client = get_firestore_client()
        col = client.collection(collection)
        query = col.limit(1)  # type: AsyncQuery
        await query.get()
    except Exception as e:
        logger.warning(f"Could not connect to database: {e}")
        return False
    else:
        return True
