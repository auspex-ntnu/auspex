from functools import partial
from typing import Any

from auspex_core.docker.registry import get_image_info
from auspex_core.gcp.firestore import check_db_exists, get_document
from auspex_core.models.api.scan import ScanRequest, ScanResults
from auspex_core.models.scan import ScanLog
from auspex_core.models.status import ServiceStatus, ServiceStatusCode
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import PlainTextResponse
from loguru import logger
from pydantic import BaseModel


from .config import AppConfig
from .exceptions import install_handlers
from .health import startup_health_check
from .scan import scan_container
from .models import ScanOptions

app = FastAPI()
install_handlers(app)


@app.on_event("startup")
async def on_app_startup():
    await startup_health_check()


@app.post("/scans", response_model=ScanResults)
async def scan_image(options: ScanOptions) -> ScanResults:
    """Scans a single container image."""
    assert options.image, "No image specified"  # TODO: make this a HTTP error

    image_info = await get_image_info(options.image, AppConfig().project)
    logger.debug(image_info)
    # TODO: pass ImageInfo object to scan_container
    #       Only use credentials if scanning image from private repo
    scan = await scan_container(image_info, options)
    if not scan.ok:
        detail = {"message": "The scan failed.", **scan.error}
        logger.error(detail)
        # FIXME: add detail message
        raise HTTPException(status_code=500, detail=detail)
    return ScanResults(
        scan=scan.scan,
        error=scan.error,
        image=image_info,
        backend=scan.backend,
        ok=scan.ok,
    )


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


@app.get("/status", response_model=ServiceStatus)
async def get_service_status(request: Request) -> ServiceStatus:
    """Get the status of the server."""
    # TODO: expand with more heuristics to determine if the service is OK
    return ServiceStatus(code=ServiceStatusCode.OK, url=request.url)
