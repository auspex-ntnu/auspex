from fastapi import FastAPI, File, Request
from fastapi.responses import RedirectResponse
from loguru import logger
from pydantic import BaseModel
import os
from .backends.snyk import SnykContainerScan

# from .gcp.firestore import get_firestore_client
from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.gcp.env import LOGS_COLLECTION_NAME

app = FastAPI()

# ONLY SUPPORTS GCP RIGHT NOW


@app.post("/pdf/{document_id}")
async def generate_report(document_id: str):
    db = get_firestore_client()
    docpath = f"{LOGS_COLLECTION_NAME}/{document_id}"
    logger.debug(f"Fetching {docpath}")
    d = db.document(docpath)
    doc = await d.get()
    return doc.to_dict()


@app.post("/pdf/aggregate")
async def generate_aggregate_report(snyk_scan: SnykContainerScan):
    print(snyk_scan.severity_v3())
    return snyk_scan.architecture
