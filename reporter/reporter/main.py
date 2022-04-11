# NOTE: ONLY SUPPORTS GCP RIGHT NOW


import os
from datetime import timedelta
import time

from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from loguru import logger

from .backends.snyk.model import SnykContainerScan
from .config import AppConfig
from .db import log_scan, get_prev_scans
from .frontends.latex import create_document
from .models import ReportRequestIn
from .types.protocols import ScanTypeSingle
from .utils.firestore import get_firestore_document
from .utils.storage import get_object_from_document, upload_report_to_bucket

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


async def scan_from_docid(docid: str, collection: str) -> ScanTypeSingle:
    # DB Document
    doc = await get_firestore_document(docid, collection)
    # Download blob from document
    obj = await get_object_from_document(doc)
    # Parse scan log

    # TODO: use image from document
    image = doc.get("image")
    # use timestamp from document
    # use backend from document

    # assert hasattr(obj.blob, "id")
    id = f"{doc.id}-{obj.blob.id}-{int(time.time())}"
    return SnykContainerScan(**obj.content, id=id, image=image)


@app.post("/report")
async def generate_report(r: ReportRequestIn):
    scan = await scan_from_docid(r.document_id[0], AppConfig().collection_logs)
    await log_scan(scan)

    prev_scans = await get_prev_scans(
        scan,
        collection=AppConfig().collection_reports,
        max_age=timedelta(weeks=AppConfig().trend_weeks),
        ignore_self=True,
    )

    doc = await create_document(scan, prev_scans)
    if not doc.path.exists():
        raise HTTPException(500, "Failed to generate report.")
    status = await upload_report_to_bucket(doc.path, AppConfig().bucket_reports)

    return {"request": r.dict(), "status": status}


@app.post("/aggregate")
async def generate_aggregate_report(r: ReportRequestIn):
    failed = []  # type: list[str]
    scans = []  # type: list[ScanTypeSingle]
    for docid in r.document_id:
        try:
            scan = await scan_from_docid(docid, AppConfig().collection_logs)
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
