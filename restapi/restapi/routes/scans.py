import asyncio
from json import JSONDecodeError

import backoff
import httpx
from auspex_core.docker.registry import get_repos_in_registry
from auspex_core.models.api.scan import ScanRequest
from auspex_core.models.scan import ScanLog
from auspex_core.utils.backoff import on_backoff, on_giveup
from fastapi import APIRouter
from fastapi.exceptions import HTTPException
from loguru import logger

from ..config import AppConfig

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanLog)
async def get_scan(scan_id: str) -> ScanLog:
    """Get a scan by its ID."""
    async with httpx.AsyncClient(timeout=AppConfig().timeout_scanner) as client:
        res = await client.get(f"{AppConfig().url_scanner}/{scan_id}")
    res.raise_for_status()
    try:
        return res.json()
    except Exception as e:
        logger.error(f"Could not parse response: {e}")
        raise HTTPException(status_code=500, detail="Could not parse scan response.")


@router.get("", response_model=list[ScanLog])
async def get_scans() -> list[ScanLog]:
    """Get all scans."""
    # NYI
    pass


@router.post("", response_model=list[ScanLog])
async def scan_images(req: ScanRequest) -> list[ScanLog]:
    """Scan one or more images."""
    # TODO: (further work) use pub/sub to submit one message for each image
    #       Spin up N cloud run instances to scan all images in parallel
    scans = await do_request_scans(req)
    return scans


async def do_request_scans(req: ScanRequest) -> list[ScanLog]:
    """Sends requests to the scanner service in parallel.
    Collects the results, parses them, and returns the parsed scans.

    Parameters
    ----------
    req : `ScanRequest`
        The request body to use to construct the requests for the scanner service.

    Returns
    -------
    `list[ScanLog]`
        The parsed scans.
    """
    async with httpx.AsyncClient(timeout=AppConfig().timeout_scanner) as client:
        res = await client.post(f"{AppConfig().url_scanner}/scans", json=req.dict())
    res.raise_for_status()  # can we do this?
    try:
        j = res.json()
        return [ScanLog(**s) for s in j]
    except Exception as e:
        logger.error(f"Could not parse response: {e}")
        raise HTTPException(status_code=500, detail="Could not parse scan response.")
