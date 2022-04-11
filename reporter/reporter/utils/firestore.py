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


# FIXME: unused. Delete?!
async def get_firestore_documents(
    document_ids: list[str], collection: str = AppConfig().collection_logs
) -> list[DocumentSnapshot]:
    """Retrieves multiple firestore documents given a list of document IDs.

    Parameters
    ----------
    document_ids : `list[str]`
       List of Firestore document IDs
    collection : `str`, optional
        The collection to fetch from, by default collection given by env var.

    Returns
    -------
    `list[DocumentSnapshot]`
        List of Firestore Documents

    Raises
    ------
    `HTTPException`
        FastAPI HTTPException that is propagated to the user in the event
        of a failure.
    """
    failed = []  # type: list[str]
    docs = []  # type: list[DocumentSnapshot]

    for docid in document_ids:
        try:
            doc = await get_firestore_document(docid, collection)
        except Exception:
            logger.exception(f"Failed to retrieve document with ID {docid}")
            failed.append(docid)
        else:
            docs.append(doc)

    if failed:
        msg = f"Failed to retrieve the following documents: {failed} in collection '{collection}'"
        logger.error(msg)
        # TODO: add custom exception
        raise HTTPException(500, msg)

    return docs
