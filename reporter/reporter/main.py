# NOTE: ONLY SUPPORTS GCP RIGHT NOW


from datetime import timedelta
import io
import os
from pathlib import Path

from auspex_core.gcp.env import (
    COLLECTION_LOGS,
    BUCKET_SCANS,
    COLLECTION_REPORTS,
)
from auspex_core.gcp.firestore import get_document
from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse
from loguru import logger


from .db import log_scan
from .backends.snyk.model import SnykContainerScan
from .frontends.latex import create_document
from .models import ReportRequestIn
from .types.protocols import ScanTypeSingle
from .utils.firestore import get_firestore_document, get_prev_scans
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

    assert hasattr(obj.blob, "id")
    # TODO: fix typing!! Why does SnykContainerScan not pass as a ScanTypeSingle type?
    return SnykContainerScan(**obj.content, id=obj.blob.id, image=image)


@app.post("/report")
async def generate_report(r: ReportRequestIn):
    scan = await scan_from_docid(r.document_id[0], r.collection)
    await log_scan(scan)

    prev_scans = await get_prev_scans(
        scan, COLLECTION_REPORTS, max_age=timedelta(weeks=24), ignore_self=True
    )

    doc = await create_document(scan, prev_scans)
    if not doc.path.exists():
        raise HTTPException(500, "Failed to generate report.")
    status = await upload_report_to_bucket(
        doc.path, "auspex-reports"
    )  # FIXME: use env var

    return {"request": r.dict(), "status": status}


@app.post("/aggregate")
async def generate_aggregate_report(r: ReportRequestIn):
    failed = []  # type: list[str]
    scans = []  # type: list[ScanTypeSingle]
    for docid in r.document_id:
        try:
            scan = await scan_from_docid(docid, r.collection)
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
