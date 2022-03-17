# NOTE: ONLY SUPPORTS GCP RIGHT NOW


import io
from pathlib import Path


from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from fastapi.responses import StreamingResponse
from loguru import logger
from auspex_core.gcp.storage import fetch_json_blob
from auspex_core.gcp.env import LOGS_COLLECTION_NAME, SCANS_BUCKET_NAME
from auspex_core.gcp.firestore import get_document

from .backends.snyk.model import SnykContainerScan
from .frontends.latex import create_document
from .models import ReportSingleIn

app = FastAPI()

# Add mock routes for internal development
from contextlib import suppress

with suppress(ImportError):
    from ._mock import mockrouter

    app.include_router(mockrouter)


@app.post("/report")
async def generate_report(r: ReportSingleIn):
    # Retrieve document
    try:
        doc = await get_document(LOGS_COLLECTION_NAME, r.document_id)
    except ValueError as e:
        raise HTTPException(
            404,
            detail=e.args[0] if e.args else f"Scan with id {r.document_id} not found",
        )

    # Get scan file from bucket
    blobname = doc.get("blob")
    if not blobname:
        raise HTTPException(
            422, f"Document {r.document_id} has no scan file associated with it."
        )
    obj = await fetch_json_blob(SCANS_BUCKET_NAME, blobname)

    # Parse scan log and create report
    scan = SnykContainerScan(**obj.content)
    latex_document = await create_document(scan)
    document_path = Path(f"{latex_document.default_filepath}.pdf")
    if not document_path.exists():
        raise HTTPException(500, "Failed to generate report.")

    # Send report file back as a streaming response
    with open(document_path, "rb") as f:
        return StreamingResponse(io.BytesIO(f.read()), media_type="application/pdf")


@app.post("/pdf/aggregate")
async def generate_aggregate_report(snyk_scan: SnykContainerScan):
    print(snyk_scan.severity_v3())
    return snyk_scan.architecture
