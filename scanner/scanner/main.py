import os
from typing import Any

import backoff
import httpx
from auspex_core.models.scan import ScanLog
from auspex_core.utils.backoff import on_backoff
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel, ValidationError
from auspex_core.models.gcr import ImageInfo
from auspex_core.gcp.gcr import get_image_info

from .config import AppConfig
from .exceptions import APIError, UserAPIError
from .scan import scan_container
from .types import ScanResultsType
from .models import CompletedScan, ScanIn
from .db import log_scan

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
    # instantiate config to check that all envvars are defined
    AppConfig()


# TODO: improve exception handlers


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
async def scan_endpoint(scan_request: ScanIn) -> ScanLog:
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
