# NOTE: ONLY SUPPORTS GCP RIGHT NOW


import os
from datetime import timedelta
import time
from typing import Optional
from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.models.scan import ReportData

from fastapi import Depends, FastAPI, Query
from fastapi.exceptions import HTTPException
from loguru import logger

from .backends.snyk.model import SnykContainerScan
from .config import AppConfig
from .db import (
    get_reports_filtered,
    log_report,
    get_prev_scans,
)
from .frontends.latex import create_document
from .models import ReportRequestIn
from .types.protocols import ScanTypeSingle
from .utils.firestore import get_firestore_document
from .utils.storage import get_object_from_document, upload_report_to_bucket
from auspex_core.models.api.report import ReportQuery

if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()

app = FastAPI()

# Add mock routes for internal development
from contextlib import suppress

with suppress(ImportError):
    from ._mock import mockrouter

    app.include_router(mockrouter)


@app.on_event("startup")
async def on_app_startup():
    # instantiate config to check that all envvars are defined
    AppConfig()


async def scan_from_docid(docid: str, collection: str) -> ScanTypeSingle:
    # TODO: move to appropriate module (backends, db, or utils)

    # DB Document
    doc = await get_firestore_document(docid, collection)
    # Download blob from document
    obj = await get_object_from_document(doc)

    backends = {
        "snyk": SnykContainerScan,
    }
    backend = doc.get("backend")
    if backend not in backends:
        raise ValueError(f"Backend {backend} not supported")
    backend_class = backends[backend]

    id = f"{doc.id}-{obj.blob.id}-{int(time.time())}"
    image = doc.get("image")
    return backend_class(**obj.content, id=id, image=image)


@app.post("/report")
async def generate_report(r: ReportRequestIn):
    scan = await scan_from_docid(r.document_id[0], AppConfig().collection_scans)

    prev_scans = await get_prev_scans(
        scan,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=AppConfig().trend_weeks),
        ignore_self=True,
        skip_historical=False,  # FIXME: set to True & should be envvar
    )

    doc = await create_document(scan, prev_scans)
    if not doc.path.exists():
        raise HTTPException(500, "Failed to generate report.")
    status = await upload_report_to_bucket(doc.path, AppConfig().bucket_reports)

    # FIXME: we don't mark the previous scans historical until here
    #    because we create the report, THEN log and mark the previous scans

    try:
        await log_report(scan, status.mediaLink)
    except Exception as e:
        logger.error(f"Failed to log scan: {e}")
        raise HTTPException(500, f"Failed to log scan: {e}")

    return {"request": r.dict(), "status": status}


@app.post("/aggregate")
async def generate_aggregate_report(r: ReportRequestIn):
    failed = []  # type: list[str]
    scans = []  # type: list[ScanTypeSingle]
    for docid in r.document_id:
        try:
            scan = await scan_from_docid(docid, AppConfig().collection_scans)
        except Exception:
            logger.exception(f"Failed to retrieve document with ID {docid}")
            failed.append(docid)
        else:
            scans.append(scan)

    if failed:
        msg = f"Failed to retrieve the following documents: {failed}"
        logger.error(msg)
        if not r.ignore_failed or not scans:
            # TODO: clarify to user if _all_ requested scans fail with ignore_failed=True
            raise HTTPException(500, msg)

    return r

    # Make aggregate report


@app.get("/reports")  # name TBD
async def get_reports(
    params: ReportQuery = Depends(),
) -> list[ReportData]:
    try:
        return await get_reports_filtered(params)
    except Exception as e:
        logger.exception("Failed to retrieve reports", e)
        raise HTTPException(500, "Failed to retrieve reports")
