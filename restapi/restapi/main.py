import asyncio
import os
from typing import Any

import httpx
from auspex_core.models.api.report import ReportQuery, ReportRequest
from auspex_core.models.api.scan import ScanRequest
from auspex_core.models.scan import ReportData, ScanLog
from auspex_core.models.status import ServiceStatusAggregate
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import HTTPException
from loguru import logger

from .config import AppConfig
from .exceptions import install_handlers
from .status import get_service_status

app = FastAPI()
install_handlers(app)


# TODO: move to auspex_core
if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()


@app.on_event("startup")
async def startup():
    logger.info("Starting up")
    # Instantiate config to check for missing fields
    AppConfig()


@app.get("/scans/{scan_id}", response_model=ScanLog)
async def get_scan(scan_id: str) -> ScanLog:
    """Get a scan by its ID."""
    async with httpx.AsyncClient() as client:
        res = await client.get(f"{AppConfig().url_scanner}/{scan_id}")
    res.raise_for_status()
    try:
        return res.json()
    except Exception as e:
        logger.error(f"Could not parse response: {e}")
        raise HTTPException(status_code=500, detail="Could not parse scan response.")


@app.post("/scans", response_model=list[ScanLog])
async def scan_images(req: ScanRequest) -> list[ScanLog]:
    # TODO: (further work) use pub/sub to submit one message for each image
    #       Spin up N cloud run instances to scan all images in parallel
    scans = await do_request_scans(req)
    return scans

    data = {
        "document_id": [scan.id for scan in scans],
        "ignore_failed": req.ignore_failed,
    }

    return r


async def do_request_scans(req: ScanRequest) -> list[ScanLog]:
    # Instantiate async client
    # (`async with AsyncClient(...)` is inconsistent when combined with asyncio.gather)
    # Sometimes it closes the client while some requests are still pending
    client = httpx.AsyncClient(timeout=AppConfig().timeout_scanner)

    # send request for each image
    url = f"{AppConfig().url_scanner}/scan"
    coros = [
        _send_scan_request(client, url, image, req.backend) for image in req.images
    ]
    responses = await asyncio.gather(*coros)

    await client.aclose()  # close connection since we don't use ctx manager

    # Filter out failed responses
    # TODO: option to raise for bad responses
    ok, failed = await _check_responses(responses, req.ignore_failed)
    scans = await _parse_scan_responses(ok, req.ignore_failed)
    return scans


# @backoff.on_exception(
#     backoff.expo,
#     exception=httpx.RequestError,
#     max_tries=5,
#     # TODO: add callback functions
# )
async def _send_scan_request(
    client: httpx.AsyncClient, url: str, image: str, backend: str
) -> httpx.Response:
    """Sends a request to the scanner service.

    Parameters
    ----------
    client : `httpx.AsyncClient`
        The client to use for sending the request.
    url : `str`
        The URL to send the request to.
    image : `str`
        The image to scan.
    backend : `str`
        The backend to use for scanning.

    Returns
    -------
    `httpx.Response`
        The response from the request.
    """

    res = await client.post(
        url,
        json={"image": image, "backend": backend},
    )
    res.raise_for_status()
    return res


async def do_request_report(req: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=AppConfig().timeout_reporter) as client:
        url = f"{AppConfig().url_reporter}/report"
        r = await client.post(url, json=req)
        # TODO: validate response and handle errors
        return r.json()


async def _handle_failed(failed: list[httpx.Response], ignore_failed: bool):
    """Handles failed responses.

    Parameters
    ----------
    failed : `list[httpx.Response]`
        List of failed responses.
    ignore_failed : `bool`
        Whether to raise an exception or not if there are failed responses.

    Raises
    ------
    `HTTPException`
        If there are failed responses and `ignore_failed` is `False`.
    """
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


@app.post("/reports", response_model=list[ReportData])
async def report_scans(req: ReportRequest) -> list[ReportData]:
    """Reports the results of scans."""


# @app.get("/parsed", response_model=list[ReportData])  # name TBD
@app.get("/reports")  # name TBD
async def get_reports(
    request: Request,
    params: ReportQuery = Depends(),  # can we only include this in the schema somehow?
) -> list[ReportData]:
    """Get reports for a given image from the reporter service."""
    async with httpx.AsyncClient() as client:
        res = await client.get(
            f"{AppConfig().url_reporter}/reports",
            params=request.query_params,
        )
        res.raise_for_status()  # Is this a bad idea
    # TODO: handle error from reporter
    try:
        return res.json()
    except:
        raise HTTPException(status_code=500, detail="Failed to parse response.")


@app.get("/status", response_model=ServiceStatusAggregate)
async def get_status() -> ServiceStatusAggregate:
    """Retrieves the status of all services."""
    services = {
        "scanner": AppConfig().url_scanner,
        "reporter": AppConfig().url_reporter,
        # BACKLOG: can we populate this dict automatically?
    }
    # TODO: use asyncio.gather to perform requests in parallel
    responses = {name: await get_service_status(url) for name, url in services.items()}
    return responses
