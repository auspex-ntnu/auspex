# NOTE: ONLY SUPPORTS GCP RIGHT NOW


import io
from pathlib import Path

from auspex_core.gcp.env import LOGS_COLLECTION_NAME, SCANS_BUCKET_NAME
from auspex_core.gcp.firestore import get_document
from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse
from loguru import logger

from .db import log_scan
from .backends.snyk.model import SnykContainerScan
from .frontends.latex import create_document
from .models import ReportAggregateIn, ReportSingleIn
from .utils.firestore import get_firestore_document
from .utils.storage import get_object_from_document

app = FastAPI()

# Add mock routes for internal development
from contextlib import suppress

with suppress(ImportError):
    from ._mock import mockrouter

    app.include_router(mockrouter)


async def scan_from_docid(docid: str, collection: str) -> SnykContainerScan:
    # DB Document
    doc = await get_firestore_document(docid, collection)
    # Download blob from document
    obj = await get_object_from_document(doc)
    # Parse scan log
    assert hasattr(obj.blob, "id")
    return SnykContainerScan(**obj.content, id=obj.blob.id)


@app.post("/report")
async def generate_report(r: ReportSingleIn):
    scan = await scan_from_docid(r.document_id, r.collection)
    await log_scan(scan)

    latex_document = await create_document(scan)
    document_path = Path(f"{latex_document.default_filepath}.pdf")
    if not document_path.exists():
        raise HTTPException(500, "Failed to generate report.")

    # Send report file back as a streaming response
    with open(document_path, "rb") as f:
        return StreamingResponse(io.BytesIO(f.read()), media_type="application/pdf")


@app.post("/aggregate")
async def generate_aggregate_report(r: ReportAggregateIn):
    failed = []  # type: list[str]
    scans = []  # type: list[SnykContainerScan]
    for docid in r.document_ids:
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

    # Make aggregate report
