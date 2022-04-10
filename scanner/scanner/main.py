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

if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()

app = FastAPI()


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


def _scan_giveup_callback(details: dict[str, Any]) -> None:
    """Callback function that is fired when the results of a scan cannot be logged."""
    logger.error(
        "Gave up after {tries} tries calling function {target} "
        "with args {args} and kwargs {kwargs}".format(**details)
    )
    raise HTTPException(status_code=500, detail="Unable to log scan results.")


def merge_scan_and_imageinfo(
    scan: ScanResultsType, image_info: ImageInfo
) -> CompletedScan:
    # TODO: rename function to something more descriptive
    """Merges the scan results with the image info."""
    return CompletedScan(
        image=image_info,
        backend=scan.backend,
        scan=scan.scan,
    )


@backoff.on_exception(
    backoff.expo,
    exception=(httpx.RequestError, httpx.HTTPStatusError),
    max_tries=5,
    on_backoff=on_backoff,
    on_giveup=_scan_giveup_callback,
)
async def log_completed_scan(
    scan: ScanResultsType, image_info: ImageInfo
) -> dict[str, Any]:
    # Merge scan data and image_info
    s = merge_scan_and_imageinfo(scan, image_info)
    async with httpx.AsyncClient() as client:
        res = await client.post(AppConfig().logger_url, json=s.dict())
        res.raise_for_status()
        try:
            j = res.json()  # type: dict[str, Any]
        except:  # TODO: specify which exception
            msg = "Unable to deserialize JSON response"
            logger.error(msg, res.text)
            raise APIError(
                msg
            )  # this will not be caught by backoff and abort immediately
        return j


@app.post("/scan", response_model=ScanLog)
async def scan_endpoint(scan_request: ScanIn) -> ScanLog:
    """Scans a single container image."""
    image_info = await get_image_info(scan_request.image, AppConfig().project)

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

    s = await log_completed_scan(scan, image_info)

    # use scan
    return s
