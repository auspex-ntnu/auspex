from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Optional, Union, cast

from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.models.api.report import CVSSField, Direction, OrderOption, ReportQuery
from auspex_core.models.cve import SEVERITIES
from auspex_core.models.scan import ParsedVulnerabilities, ReportData
from google.api_core.exceptions import InvalidArgument
from google.cloud import firestore
from google.cloud.firestore import SERVER_TIMESTAMP, async_transactional
from google.cloud.firestore_v1 import DocumentSnapshot
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.async_collection import AsyncCollectionReference
from google.cloud.firestore_v1.async_document import AsyncDocumentReference
from google.cloud.firestore_v1.async_query import AsyncQuery
from google.cloud.firestore_v1.async_transaction import AsyncTransaction
from google.cloud.firestore_v1.collection import CollectionReference
from google.cloud.firestore_v1.types import WriteResult
from google.cloud.firestore_v1.types.write import WriteResult
from loguru import logger
from pydantic import ValidationError

from .config import AppConfig
from .types.protocols import ScanType
from .utils.types import get_reportdata

# async def log_report(scan: ScanType) -> WriteResult:
#     client = get_firestore_client()
#     transaction = client.transaction()
# async def _log_report(
#     transaction: firestore.AsyncTransaction, scan: ScanType
# ) -> WriteResult:


async def log_report(
    scan: ScanType,
    report_url: Optional[str] = None,
    aggregate: bool = False,  # TODO: add this to ScanType protocol
) -> ReportData:
    """Store results of parsed container scan in the database and mark
    existing reports for the same image as historical.

    Parameters
    ----------
    scan : `ScanType`
        Scan results to log.
    report_url : `Optional[str]`
        URL of the human-readable version of the report.
    aggregate : `bool`
        Whether or not the report is an aggregate report.

    Returns
    -------
    `ReportData`
        The representation of the logged report in the database.
    """
    client = get_firestore_client()

    # TODO: perform the two steps below as transaction
    # transaction = client.transaction()
    # How to write then read (then write) in a transaction?

    report_data = await _log_report(
        client, AppConfig().collection_reports, scan, report_url, aggregate
    )
    await mark_reports_historical(client, AppConfig().collection_reports, scan)
    return report_data


async def _log_report(
    client: AsyncClient,
    collection: str,
    scan: ScanType,
    report_url: Optional[str],
    aggregate: bool,
) -> ReportData:
    """Store results of parsed container scan in the database."""
    r = get_reportdata(scan, report_url)

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
    logger.debug(f"Logged report with ID '{scan.id}', result: {result}")
    return r


async def get_prev_scans(
    scan: ScanType,
    collection: str,
    max_age: Union[timedelta, datetime],
    ignore_self: bool = True,
    by_image: bool = True,
    aggregate: bool = False,
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
    aggregate : `bool`, optional
        If true, only returns reports marked 'aggregate', by default False
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

    query: AsyncQuery
    if aggregate:
        query = col.where("aggregate", "==", True)
    else:
        query = col.where("image.image", "==", scan.image.image)

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
        #
        # NOTE: This does not apply for aggregate reports.
        # Report are only marked historical when a newer report of the _SAME_
        # image is created. Aggregate reports do not work under the same principle,
        # since we don't factor in which images are in the aggregate, and thus
        # every aggregate report is considered to be the same image.
        if not aggregate and (skip_historical and d.get("historical") == True):
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


async def mark_reports_historical(
    client: AsyncClient, collection: str, report: ScanType
) -> None:
    """Mark all older reports with the same image as the input scan as historical.

    See: _mark_historical


    Parameters
    ----------
    report : `ScanType`
        The scan to use as a reference for finding older reports.
    collection : `str`
        The collection to search for reports in.

    Returns
    -------
    `dict[str, int]`
        A dictionary of updated, skipped, and failed counts.
    """
    # NOTE:
    # Until the Firestore AsyncClient has proper type stubs, we have to
    # manually cast AsyncClient queries to AsyncQuery to avoid mypy errors.
    # This clogs up the code a bit, but gives us proper type checking.

    client = get_firestore_client()
    col = client.collection(collection)
    query = col.where("image.image", "==", report.image.image)
    query = cast(AsyncQuery, query)  # cast for mypy

    # In this try/except block we try to use a composite index first,
    # but if that fails, we fall back to iterating over all docs with the given image.
    try:
        # Try to use composite index first
        query_composite = query.where("historical", "==", False)
        query_composite = cast(AsyncQuery, query_composite)  # cast for mypy
        async for doc in query_composite.stream():
            await _process_historical_doc(doc, report)
        logger.debug("Marked historical using composite index.")
    except:  # TODO: should be FailedPrecondition most likely
        # Fallback to iterating over all docs
        async for doc in query.stream():
            await _process_historical_doc(doc, report)
        logger.debug("Marked historical using single key index (iteration).")


async def _process_historical_doc(
    doc: DocumentSnapshot,
    report: ScanType,
) -> None:
    """Process a document and decide whether to mark it as historical."""
    d = doc.to_dict()
    if not d:
        return

    # We don't have to update existing historical documents
    if d.get("historical") == True:
        return

    # Check for presence of timestamp (if not, skip)
    if not (timestamp := d.get("timestamp")) or not isinstance(timestamp, datetime):
        logger.warning(
            f"Document '{doc.id}' has no key 'timestamp' or is not a valid datetime object."
        )
        return

    # If doc's timestamp is older than scan's timestamp, mark it as historical
    if timestamp < report.timestamp.replace(tzinfo=timestamp.tzinfo):
        try:
            await _mark_historical(doc.reference)
        except:
            logger.exception(f"Failed to mark document '{doc.id}' as historical")
            return


async def _mark_historical(docref: AsyncDocumentReference) -> WriteResult:
    """Marks a document as historical, meaning the document does not represent
    the most recent report for the given `image@sha256:hash`."""
    return await docref.update({"historical": True, "updated": SERVER_TIMESTAMP})


# async def get_documents_query


async def get_reports_filtered(params: ReportQuery) -> list[dict[str, Any]]:
    """Get reports filtered by query parameters.

    Parameters
    ----------
    params : `ReportQuery`
        Query parameters.

    Returns
    -------
    `list[dict[str, Any]]`
        List of reports.
    """
    # TODO: move this to a separate function in db.py?
    client = get_firestore_client()

    collection = client.collection(AppConfig().collection_reports)
    query = await construct_query(collection, params)

    # Query DB
    docs = [d async for d in filter_documents(query.stream(), params)]
    # TODO: add client-side sorting

    # Order by timestamp
    if params.order in [OrderOption.NEWEST, OrderOption.OLDEST]:
        now = datetime.now()  # default pre-computed for performance
        reverse = True if params.order == OrderOption.NEWEST else False
        docs = sorted(docs, key=lambda d: d.get("timestamp", now), reverse=reverse)

    # Order by Score
    elif params.order in [OrderOption.MAXSCORE, OrderOption.MINSCORE]:
        reverse = True if params.order == OrderOption.MAXSCORE else False
        docs = sorted(
            docs,
            key=lambda d: d.get("cvss", {}).get(params.field.value, 0),
            reverse=reverse,
        )

    if params.limit and len(docs) > params.limit:
        docs = docs[: params.limit]
    return docs


async def construct_query(
    collection: AsyncCollectionReference, params: ReportQuery
) -> AsyncQuery:  # TODO: find out if we return an AsyncQuery or a BaseQuery (thanks gcloud-aio..)
    """Constructs an async query from a request.

    Args
    ----
    collection : `AsyncCollectionReference`
        The collection to query.
    params : `ReportQuery`
        The query parameters.

    Returns
    -------
    `AsyncQuery`
        The constructed query.
    """
    # Filter
    query = collection.where("image.image", "==", params.image)
    if params.ge is not None:
        query = query.where(f"cvss.{params.field.value}", ">=", params.ge)
    if params.le is not None:
        query = query.where(f"cvss.{params.field.value}", "<=", params.le)

    # # # Sort
    # if params.sort_by:
    #     query = query.order("cvss.mean", direction=firestore.Query.DESCENDING)

    # Limit
    # TODO: inspect if we can use limit on the query itself
    # as opposed to limiting client-side
    if params.limit:
        query = query.limit(params.limit)

    # have to convince mypy that it's an AsyncQuery
    # See: AsyncCollectionReference._query
    query = cast(AsyncQuery, query)
    return query


async def filter_documents(
    docs: AsyncGenerator[DocumentSnapshot, None], params: ReportQuery
) -> AsyncGenerator[dict[str, Any], None]:
    """Filter a stream of documents given a user-defined document filter.

    Parameters
    ----------
    docs : AsyncGenerator[DocumentSnapshot, None]
        Async generator of DocumentSnapshot objects.
    params : `ReportQuery`
        The query params to filter the documents by.

    Returns
    -------
    AsyncGenerator[dict[str, Any], None]
        Returns an async generator of filtered documents converted to dicts.
    """
    async for doc in docs:
        if doc is None:  # filter None (should never happen?)
            continue

        # Get dict here to avoid re-reading from the database
        # This is the concession we make to avoid creating multiple composite indexes
        d = doc.to_dict()
        if not d:  # always check for falsey values (missing or empty)
            continue

        # Get value for the given cvss field
        field_value = await _get_cvss_value(doc, d, params.field)
        if field_value is None:
            continue

        # Filter min/max score
        if params.le is not None:
            if field_value > params.le:
                continue
        if params.ge is not None:
            if field_value < params.ge:
                continue

        # TODO: add max_age handling

        yield d


async def _get_cvss_value(
    doc: DocumentSnapshot, values: dict[str, Any], field: CVSSField
) -> Optional[float]:
    """Get the CVSS value for the given field.

    Parameters
    ----------
    doc : `DocumentSnapshot`
        The document to get the CVSS value from.
    values : `dict[str, Any]`
        The values of the document.
    field : `CVSSField`
        The field to get the CVSS value for.

    Returns
    -------
    Optional[float]
        The CVSS value for the given field.
    """
    # Get value for the given cvss field
    try:
        val = values["cvss"][field.value]
        if not isinstance(val, float):
            # log a warning if the value is not a float and return None
            logger.warning(
                f"Found non-float value for CVSS field '{field.vaue}' in document {doc.id}"
            )
            return None
    except KeyError:
        return None
    return val
