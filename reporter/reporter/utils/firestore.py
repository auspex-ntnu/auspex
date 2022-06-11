from auspex_core.gcp.firestore import get_document, get_firestore_client
from fastapi.exceptions import HTTPException
from google.cloud.firestore_v1 import DocumentSnapshot
from loguru import logger

from ..config import AppConfig


async def get_firestore_document(document_id: str, collection: str) -> DocumentSnapshot:
    """Wrapper around `auspex_core.firestore.get_document` that handles
    exceptions and logging for the service.

    Parameters
    ----------
    document_id : `str`
        The ID of the document to fetch.
    collection : `str`, optional
        The collection the document is stored in, by default collection given by env var.

    Returns
    -------
    `DocumentSnapshot`
        Firestore Document

    Raises
    ------
    `HTTPException`
        FastAPI HTTPException that is propagated to the user in the event
        of a failure.
    """
    # TODO: why not just bake this into get_document?
    try:
        doc = await get_document(collection, document_id)
    except Exception as e:
        msg = f"Failed to retrieve document '{collection}/{document_id}'"
        logger.exception(msg)
        if e.args and "not found" in e.args[0].lower():
            msg = e.args[0]
            code = 404
        else:
            code = 500
        raise HTTPException(code, msg)
    return doc
