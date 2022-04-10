from datetime import timedelta, datetime
from typing import Any, Optional, Union

from auspex_core.gcp.env import COLLECTION_LOGS
from auspex_core.gcp.firestore import get_document, get_firestore_client
from auspex_core.models.scan import ReportData
from fastapi.exceptions import HTTPException
from google.cloud.firestore_v1 import DocumentSnapshot
from google.cloud.firestore_v1.async_query import AsyncQuery
from loguru import logger
from pydantic import ValidationError
from ..types.protocols import ScanTypeSingle


async def get_firestore_document(
    document_id: str, collection: str = COLLECTION_LOGS
) -> DocumentSnapshot:
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


async def get_firestore_documents(
    document_ids: list[str], collection: str = COLLECTION_LOGS
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


async def get_prev_scans(
    scan: ScanTypeSingle,
    collection: str,
    max_age: Union[timedelta, datetime],
    ignore_self: bool = True,
    by_image: bool = True,
) -> list[ReportData]:
    """Given a single image scan, find all previous scans going back
    to a certain date.

    Parameters
    ----------
    scan : `ScanType`
        The scan whose image to find previous reports of.
    collection : `str`
        The firestore collection to search for reports in.
    max_age : `Union[timedelta, datetime]`
        Maximum age of report to retrieve.
        Can be an absolute point in time (datetime) or a maximum age (timedelta).
    ignore_self : `bool`, optional
        If true, does not include the input scan in the returned list, by default True
    by_image : `bool`, optional
        If true, returns reports by image creation date instead of scan date, by default True

    Returns
    -------
    `list[ReportData]`
        List of previous scan reports.
    """
    if isinstance(max_age, timedelta):
        cutoff = datetime.now() - max_age
    else:
        cutoff = max_age

    client = get_firestore_client()
    col = client.collection(collection)
    query = col.where("image.image", "==", scan.image.image)  # type: AsyncQuery

    # Perform filtering by date client-side instead of using composite query
    # This will require more database reads and memory, but saves us from
    # having to create a composite index
    reports = []  # type: list[ReportData]
    async for doc in query.stream():
        d = doc.to_dict()
        if not d:  # always check for falsey values
            continue

        # Ignore self when searching for previous scans
        if ignore_self and d.get("id") == scan.id:
            continue

        # Verify that doc has a timestamp and retrieve it
        if by_image:
            # XXX: use doc.get instead for nested fields? Is that an extra read?
            img = d.get("image", {})  # type: dict[str, Any]
            timestamp = img.get("created")  # type: Optional[datetime]
        else:
            timestamp = d.get("timestamp")
        if not timestamp:
            k = "image.created" if by_image else "timestamp"
            logger.warning(f"Document '{doc.id}' has no key '{k}'.")
            continue

        # Use timezone from doc when comparing
        if timestamp > cutoff.replace(tzinfo=timestamp.tzinfo):
            try:
                r = ReportData(**d)
            except ValidationError:
                logger.exception(f"Unable to parse document '{doc.id}'")
                continue
            reports.append(r)

    # TODO: assert no duplicate ids?
    return reports
