from contextlib import suppress
from functools import partial
import json
import os
from typing import Any
from auspex_core.gcp.firestore import get_document, check_db_exists
from auspex_core.models.api.scan import ScanRequest

import backoff
import httpx
from auspex_core.models.scan import ScanLog
from auspex_core.utils.backoff import on_backoff
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from auspex_core.docker.models import ImageInfo
from auspex_core.docker.registry import get_image_info
from auspex_core.models.status import ServiceStatus, ServiceStatusCode
from json import JSONDecodeError

from .config import AppConfig
from .exceptions import APIError, UserAPIError
from .scan import scan_container
from .types import ScanResultsType
from .models import CompletedScan, ScanIn
from .db import log_scan
from .health import startup_health_check
from .exceptions import install_handlers

app = FastAPI()
install_handlers(app)


@app.on_event("startup")
async def on_app_startup():
    await startup_health_check()


@app.post("/scans", response_model=ScanLog)
async def scan_image(options: ScanRequest) -> ScanLog:
    """Scans a single container image."""
    # Can we copy and monkey-patch the ScanRequest class to assert 1 image is required?
    assert options.images, "No image specified"  # TODO: make this a HTTP error

    image_info = await get_image_info(options.images[0], AppConfig().project)
    logger.debug(image_info)
    # TODO: pass ImageInfo object to scan_container
    #       Only use credentials if scanning image from private repo
    scan = await scan_container(image_info, options)
    if not scan.ok:
        detail = {"message": "The scan failed.", **scan.error}
        logger.error(detail)
        # FIXME: add detail message
        raise HTTPException(status_code=500, detail=detail)
    s = await log_scan(scan, image_info, options)
    return s


@app.get("/scans", response_model=list[ScanLog])
async def get_scans(image: str = "") -> list[ScanLog]:
    pass


@app.get("/scans/{scan_id}", response_model=ScanLog)
async def get_scan(scan_id: str) -> ScanLog:
    """Retrieve scan for a given scan ID.

    Args
    ----
    scan_id: `str`
        The scan ID to retrieve.
        A scan ID is the ID of a Firestore document.

    Returns
    -------
    `ScanLog`
        The scan log for the given scan ID.
    """
    try:
        doc = await get_document(AppConfig().collection_scans, scan_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanLog(**doc.to_dict(), id=doc.id)


@app.head("/scans")
async def get_scans_head() -> PlainTextResponse:
    """HEAD request handler that checks if database is reachable."""
    if await check_db_exists(AppConfig().collection_scans):
        return PlainTextResponse(status_code=200)
    else:
        raise HTTPException(status_code=500, detail="Database unreachable")


@app.get("/status", response_model=ServiceStatus)
async def get_service_status(request: Request) -> ServiceStatus:
    """Get the status of the server."""
    # TODO: expand with more heuristics to determine if the service is OK
    status = partial(ServiceStatus, url=request.url)
    if await check_db_exists(AppConfig().collection_scans):
        return status(
            status=ServiceStatusCode.OK,
        )
    else:
        return status(
            status=ServiceStatusCode.ERROR,
            message="Database unreachable",
        )
