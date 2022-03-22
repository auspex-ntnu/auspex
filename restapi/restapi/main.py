from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.exceptions import HTTPException
import os

from auspex_core.models.scan import ParsedScan
from auspex_core.models.pdf import PDFRequestIn
from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.gcp.env import PARSED_COLLECTION_NAME


from .db import construct_query, filter_documents
from .exceptions import install_handlers
from .workflows.base import WorkflowRunner
from .workflows import get_runner
from .workflows.gcp import start_pdf_workflow, run_workflow
from .models import ParsedScanRequest, InvalidQueryString


app = FastAPI()
install_handlers(app)

runner: WorkflowRunner = get_runner()


@app.get("/logs", response_class=RedirectResponse)
async def logs():
    return "http://pdfurl.com"


@app.post("/pdf/generate")
async def generate_pdf_report(body: PDFRequestIn):
    return await start_pdf_workflow()


# @app.post("/scan", response_model=ScanOut)
# async def generate(scan_in: ScanIn):
#     return os.getenv("SCAN_URL")


@app.get("/")
async def root():
    return "Hello World!"


@app.get("/parsed")  # name TBD
async def get_parsed_scan(req: ParsedScanRequest) -> list[ParsedScan]:
    # TODO: handle empty query?
    client = get_firestore_client()

    # Query DB
    collection = client.collection(PARSED_COLLECTION_NAME)
    query = await construct_query(collection, req)
    # res = await query.get()

    # Use generator expression to conserve memory
    docs = (doc.to_dict() async for doc in query.stream())
    if req.filter:
        docs = filter_documents(docs, req.filter)
    return [d async for d in docs]
