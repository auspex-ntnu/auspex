import asyncio
from typing import Any, Optional
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.exceptions import HTTPException
import os

from auspex_core.models.scan import ReportData, ScanLog
from auspex_core.models.api.report import ReportRequest
from auspex_core.models.api.scan import ScanRequest
from auspex_core.gcp.firestore import get_firestore_client
from auspex_core.gcp.env import COLLECTION_REPORTS
import httpx
from loguru import logger
from pydantic import BaseSettings, Field
import backoff


from .db import construct_query, filter_documents
from .config import AppConfig
from .exceptions import install_handlers
from .workflows.base import WorkflowRunner
from .workflows import get_runner
from .workflows.gcp import start_pdf_workflow


app = FastAPI()
install_handlers(app)

runner: WorkflowRunner = get_runner()

# TODO: move to auspex_core
if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()


@app.get("/logs", response_class=RedirectResponse)
async def logs():
    return "http://pdfurl.com"


# @app.post("/pdf/generate")
# async def generate_pdf_report(body: PDFRequestIn):
#     return await start_pdf_workflow()


@app.get("/")
async def root():
    return "Hello World!"


@app.post("/scan")
async def scan_images(req: ScanRequest):
    # TODO: (further work) use pub/sub to submit one message for each image
    #       Spin up N cloud run instances to scan all images in parallel

    url = AppConfig().url_scanner
    if not url:
        raise HTTPException(500, "Can't contact scanner service. URL is not defined.")
    url = f"{url}/scan"

    # Instantiate async client
    # (`async with AsyncClient(...)` is inconsistent when combined with asyncio.gather)
    # Sometimes it closes the client while some requests are still pending
    client = httpx.AsyncClient()
    # send request for each image
    # TODO: implement backoff for these requests
    coros = [send_scan_request(client, url, image, req.backend) for image in req.images]
    responses = await asyncio.gather(*coros)
    await client.aclose()

    # Filter out failed responses
    # TODO: option to raise for bad responses
    ok, failed = await _check_responses(responses, req.ignore_failed)
    scans = await _parse_scan_responses(ok, req.ignore_failed)

    url = AppConfig().url_reporter
    if not url:
        raise HTTPException(500, "Can't contact reporter service. URL is not defined.")

    data = {
        "document_id": [scan.id for scan in scans],
        "ignore_failed": req.ignore_failed,
    }

    async with httpx.AsyncClient() as client:
        if len(scans) == 1:
            r = await request_single_report(url, data)
        else:
            r = await request_aggregate_report(url, data)
    return r.json()


# @backoff.on_exception(
#     backoff.expo,
#     exception=httpx.RequestError,
#     max_tries=5,
#     # TODO: add callback functions
# )
async def send_scan_request(
    client: httpx.AsyncClient, url: str, image: str, backend: str
) -> httpx.Response:
    res = await client.post(
        url, json={"image": image, "backend": backend}, timeout=None
    )
    res.raise_for_status()
    return res


async def _handle_failed(failed: list[httpx.Response], ignore_failed: bool):
    """Handles failed responses."""
    # Handle failed requests
    if failed:
        for f in failed:
            logger.error(
                f"Request failed: {f.url}. Code: {f.status_code}. Reason: '{f.text}'"
            )
        if not ignore_failed:
            failed_info = "\n".join([str(r.url) for r in failed])  # this is useless
            # TODO: add data structure for showing multiple failures
            raise HTTPException(status_code=500, detail=failed_info)


async def _check_responses(
    responses: list[httpx.Response], ignore_failed: bool
) -> tuple[list[httpx.Response], list[httpx.Response]]:
    """Sorts out failed or malformed responses and returns the rest."""
    failed = []
    ok = []
    for res in responses:
        j = res.json()
        if not j:
            failed.append(res)
            continue
        if res.is_error:
            failed.append(res)
        else:
            ok.append(res)
    await _handle_failed(failed, ignore_failed)
    return ok, failed


async def _parse_scan_responses(
    responses: list[httpx.Response], ignore_failed: bool
) -> list[ScanLog]:
    """Parses the responses and returns the parsed scans."""
    scans = []  # list[ScanLog]
    failed = []
    for res in responses:
        try:
            j = res.json()
            logger.debug(j)
            scans.append(ScanLog(**j))
        except:  # TODO: specify exception
            # TODO: specify which response failed
            failed.append(res)
            logger.exception("An error occured when attempting to parse the response")
    await _handle_failed(failed, ignore_failed)
    if not scans:
        raise HTTPException(
            status_code=500, detail="None of the images provided could be scanned."
        )
    return scans


REPORTER_TIMEOUT: Optional[float] = None


async def request_single_report(url: str, data: dict[str, Any]) -> httpx.Response:
    # TODO: investigate what a sane timeout is
    async with httpx.AsyncClient(timeout=REPORTER_TIMEOUT) as client:
        url = f"{url}/report"
        r = await client.post(url, json=data)
    return r


async def request_aggregate_report(url: str, data: dict[str, Any]) -> httpx.Response:
    async with httpx.AsyncClient(timeout=REPORTER_TIMEOUT) as client:
        url = f"{url}/aggregate"
        r = await client.post(url, json=data)
    return r


# @app.get("/parsed", response_model=list[ReportData])  # name TBD
@app.get("/reports")  # name TBD
async def get_reports(req: ReportRequest) -> list[ReportData]:
    client = get_firestore_client()

    # Query DB
    collection = client.collection(AppConfig().collection_reports)
    query = await construct_query(collection, req)

    # Use generator expression to conserve memory
    docs = (doc.to_dict() async for doc in query.stream())
    if req.filter:
        docs = filter_documents(docs, req.filter)
    return [d async for d in docs]
