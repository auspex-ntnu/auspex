from json import JSONDecodeError
from typing import Any
from auspex_core.gcp.storage import fetch_json_blob
from auspex_core.models.api.report import ReportRequestIn

from fastapi import HTTPException
from loguru import logger
from .config import AppConfig


from auspex_core.models.scan import ReportData, ScanLog
import httpx
from .backends import get_backend
from .types.protocols import ScanType
from .backends.aggregate import AggregateReport
from .frontends.latex import create_document
from .utils.storage import upload_report_to_bucket
from .db import log_report


async def get_report(scan_id: str) -> ScanType:
    """Fetches and parses scan from the scanner service.

    Parameters
    ----------
    scan_id : `str`
        The ID of the scan to fetch.

    Returns
    -------
    report : `ScanType`
        The report created from the parsed scan.
    """
    scan = await fetch_scan(scan_id)
    return await _parse_scan(scan)


async def fetch_scan(scan_id: str) -> ScanLog:
    """Fetches a scan from the scanner service.

    Parameters
    ----------
    scan_id : `str`
        The ID of the scan to fetch.

    Returns
    -------
    scan : `ScanLog`
        The scan object.
    """
    # TODO: make timeout configurable (and standardized?)
    async with httpx.AsyncClient(timeout=30) as client:
        url = f"{AppConfig().url_scanner}/scans/{scan_id}"
        r = await client.get(url)
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=r.text)
    try:
        scan = ScanLog(**r.json())
    except JSONDecodeError as e:
        raise HTTPException(
            status_code=500, detail=f"Could not parse response: {r.text}"
        )
    return scan


async def _parse_scan(scan: ScanLog) -> ScanType:
    """
    Parses a scan using the backend defined in the scan's `backend` field.

    Parameters
    ----------
    scan : `ScanLog`
        The scan to parse.

    Returns
    -------
    scan : `ScanType`
        The parsed scan.
        The actual class depends on the backend, but it will always fulfill
        the `ScanType` interface.
    """
    # TODO: support aggregate
    obj = await fetch_json_blob(scan.bucket, scan.blob)
    backend = get_backend(scan.backend)
    return backend(scan, obj.content)


async def fetch_raw_scan(url: str) -> dict[str, Any]:
    """Downloads a raw scan from the URL and parses it as JSON."""
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


async def create_and_upload_report(
    report: ScanType,
    prev_scans: list[ReportData],
    settings: ReportRequestIn,
) -> ReportData:
    # TODO: pass in frontend creation function
    # TODO: Make this function frontend-agnostic
    doc = await create_document(report, prev_scans)
    if not doc.path.exists():
        logger.error(f"Expected {doc.path} to exist, but it doesn't. Exiting.")
        raise HTTPException(500, "Failed to generate report.")
    status = await upload_report_to_bucket(doc.path, AppConfig().bucket_reports)

    # TODO: don't rely on isinstance check here. Implement .aggregate property?
    aggregate = report.is_aggregate or isinstance(report, AggregateReport)

    # FIXME: we don't mark the previous scans historical until here
    #    because we create the report, THEN log and mark the previous scans
    #
    # Edit 2022-05-08: I'm not sure why this is an issue?
    try:
        report = await log_report(report, status.mediaLink, aggregate)
    except Exception as e:
        logger.error(f"Failed to log report: {e}")
        raise HTTPException(500, f"Failed to log report: {e}")
    return report
