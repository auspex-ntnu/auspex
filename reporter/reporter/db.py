from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Optional, Union

from loguru import logger

if TYPE_CHECKING:
    from google.cloud.firestore_v1.collection import CollectionReference

from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.models.cve import SEVERITIES
from auspex_core.models.scan import ParsedVulnerabilities, ReportData
from google.api_core.exceptions import InvalidArgument
from google.cloud.firestore import SERVER_TIMESTAMP
from google.cloud.firestore_v1.async_document import AsyncDocumentReference
from google.cloud.firestore_v1.async_query import AsyncQuery
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.types import WriteResult
from google.cloud.firestore_v1.types.write import WriteResult
from pydantic import ValidationError

from .config import AppConfig
from .types import ScanTypeSingle
from .types.protocols import ScanTypeSingle

# TODO: replace arg with protocol type to support multiple backends

# async def log_scan(scan: ScanTypeSingle) -> WriteResult:
#     client = get_firestore_client()
#     transaction = client.transaction()
# async def _log_scan(
#     transaction: firestore.AsyncTransaction, scan: ScanTypeSingle
# ) -> WriteResult:


async def log_scan(scan: ScanTypeSingle) -> None:
    """Store results of parsed container scan in the database and mark
    existing reports as historical."""
    client = get_firestore_client()
    doc = client.collection(AppConfig().collection_reports).document()

    scanres = await _log_scan(client, AppConfig().collection_reports, scan)
    logger.debug(f"Logged scan with ID '{scan.id}', result: {scanres}")

    hisres = await mark_scans_historical(client, AppConfig().collection_reports, scan)
    logger.debug(f"Marked historical scans: {hisres}")


async def _log_scan(
    client: AsyncClient, collection: str, scan: ScanTypeSingle
) -> WriteResult:
    """Store results of parsed container scan in the database."""
    r = ReportData(
        image=scan.image.dict(),
        id=scan.id,
        cvss=scan.cvss,  # TODO: use dedicated type
        vulnerabilities=scan.get_distribution_by_severity(),
        report_url=None,
    )

    doc = client.collection(collection).document()

    # TODO: Delete or update existing documents with the same image digest
    # TODO: handle exceptions
    # TODO: perform this as a transaction

    # Create document
    result = await doc.create(r.dict())

    # Create subcollections for vulnerabilities
    col = doc.collection("vulnerabilities")  # type: CollectionReference
    for severity in SEVERITIES:
        try:
            data = ParsedVulnerabilities(
                vulnerabilities=getattr(scan, severity),
                ok=True,
            )
            await col.document(severity).set(data.dict())
        except InvalidArgument as e:
            if e.args and "exceeds the maximum allowed size" in e.args[0]:
                logger.error(
                    f"Unable to log vulnerabilities with severity '{severity}' for scan with ID '{scan.id}' (image: '{scan.image}'). "
                    "Number of severities are too large to be stored in a firestore collection. Consult raw log."
                )
                data.vulnerabilities = []  # empty list
                data.ok = False
                # TODO: try to cut down size of list until it fits?
                #
                # Realistically no production image should have so many vulnerabilities
                # they can't be stored in a firestore document, but known vulnerable
                # images like "vulhub/php:5.4.1-cgi" do trigger this exception,
                # hence we have to account for it happening and handle it + log it.

                # This is a limitation of the firestore maximum document size.
                # It could be mitigated by creating subcollections of N size,
                # where N is a known safe number of vulnerabilities to store that
                # does not exceed the maximum document size.
                await col.document(severity).set(data.dict())
            else:
                raise

    return result


async def get_prev_scans(
    scan: ScanTypeSingle,
    collection: str,
    max_age: Union[timedelta, datetime],
    ignore_self: bool = True,
    by_image: bool = True,
    skip_historical: bool = True,
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
    skip_historical : `bool`, optional
        If true, skips historical reports, by default True

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

        # Ignore historical (older versions of) reports
        if skip_historical and d.get("historical") == True:
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


async def mark_scans_historical(
    client: AsyncClient, collection: str, scan: ScanTypeSingle
) -> dict[str, int]:
    """Mark all older reports with the same image as historical.

    Parameters
    ----------
    scan : `ScanTypeSingle`
        The scan to use as a reference for finding older reports.
    collection : `str`
        The collection to search for reports in.

    Returns
    -------
    `dict[str, int]`
        A dictionary of updated, skipped, and failed counts.
    """

    # This would be massively sped up by using a composite index
    # https://cloud.google.com/firestore/docs/query-data/composite-index
    client = get_firestore_client()
    col = client.collection(collection)
    query = col.where("image.image", "==", scan.image.image)  # type: AsyncQuery
    # if using composite index: query = query.where("historical", "==", False)

    res = {"updated": 0, "skipped": 0, "failed": 0}
    async for doc in query.stream():
        d = doc.to_dict()
        if not d:
            res["skipped"] += 1
            continue

        # We don't have to update existing historical documents
        if d.get("historical") == True:
            res["skipped"] += 1
            continue

        # Update any documents that are not historical that are older than our scan
        if not (timestamp := d.get("timestamp")) or not isinstance(timestamp, datetime):
            logger.warning(
                f"Document '{doc.id}' has no key 'timestamp' or is not a valid datetime object."
            )
            res["failed"] += 1
            continue

        if d.get("timestamp") < scan.timestamp.replace(tzinfo=timestamp.tzinfo):
            try:
                await _mark_historical(doc.reference)
            except:
                logger.exception(f"Failed to mark document '{doc.id}' as historical")
                res["failed"] += 1
                continue
            else:
                res["updated"] += 1
    return res


async def _mark_historical(docref: AsyncDocumentReference) -> WriteResult:
    """Marks a document as historical, meaning the document does not represent
    the most recent report for the given `image@sha256:hash`."""
    return await docref.update({"historical": True, "updated": SERVER_TIMESTAMP})
