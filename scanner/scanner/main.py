from functools import partial
import os
from typing import Any
from auspex_core.gcp.firestore import get_document, check_db_exists

import backoff
import httpx
from auspex_core.models.scan import ScanLog
from auspex_core.utils.backoff import on_backoff
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from auspex_core.models.gcr import ImageInfo
from auspex_core.gcp.gcr import get_image_info
from auspex_core.models.status import ServiceStatus, ServiceStatusCode

from .config import AppConfig
from .exceptions import APIError, UserAPIError
from .scan import scan_container
from .types import ScanResultsType
from .models import CompletedScan, ScanIn
from .db import log_scan
from .health import startup_health_check

if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()

app = FastAPI()


@app.on_event("startup")
async def on_app_startup():
    await startup_health_check()


# TODO: improve exception handlers

# TODO: remove this. It just obscures the actual error message
@app.exception_handler(ValidationError)
async def handle_validation_error(request: Request, exc: ValidationError):
    # TODO: improve message
    logger.error("A pydantic validation error occured", exc)
    return JSONResponse(
        status_code=400,
        content={"detail": exc.errors()},
    )


@app.exception_handler(APIError)
async def handle_api_error(request: Request, exc: APIError):
    # TODO: improve message
    logger.error("An exception occured", exc)
    return JSONResponse(status_code=400, content=exc.args)


@app.exception_handler(UserAPIError)
async def handle_user_api_error(request: Request, exc: UserAPIError):
    logger.debug("A user API exception occured", exc)
    return JSONResponse(status_code=500, content=exc.args)


@app.post("/scan", response_model=ScanLog)
async def scan_image(scan_request: ScanIn) -> ScanLog:
    """Scans a single container image."""
    image_info = await get_image_info(scan_request.image, AppConfig().project)
    logger.debug(image_info)
    # NOTE: use image name from image_info instead?
    scan = await scan_container(
        image=scan_request.image,
        backend=scan_request.backend,
    )
    if not scan.ok:
        msg = f"Scan failed with the following output:\nstdout: {scan.scan}\nstderr:{scan.error}"
        logger.error(msg)
        # FIXME: add detail message
        raise HTTPException(status_code=500, detail=msg)

    s = await log_scan(scan, image_info)

    # use scan
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
    return ScanLog(**doc.to_dict())


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
