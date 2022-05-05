from json import JSONDecodeError
from typing import Any
from auspex_core.gcp.storage import fetch_json_blob

from fastapi import HTTPException
from .config import AppConfig


from auspex_core.models.scan import ScanLog
import httpx
from .backends import get_backend
from .types.protocols import ScanType, ScanTypeAggregate, ScanTypeSingle


async def parse_scan(scan_id: str) -> ScanTypeSingle:
    """Fetches and parses scan from the scanner service.

    Parameters
    ----------
    scan_id : `str`
        The ID of the scan to fetch.

    Returns
    -------
    scan : `ScanTypeSingle`
        The scan object.
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


async def _parse_scan(scan: ScanLog) -> ScanTypeSingle:
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
