import asyncio
from functools import partial
from json import JSONDecodeError

import backoff
import httpx
from auspex_core.docker.registry import get_image_info, get_repos_in_registry
from auspex_core.gcp.firestore import check_db_exists, get_document
from auspex_core.models.api.scan import ScanRequest, ScanResults
from auspex_core.models.scan import ScanLog
from auspex_core.models.status import ServiceStatus, ServiceStatusCode
from auspex_core.utils.backoff import on_backoff, on_giveup
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import PlainTextResponse
from loguru import logger

from .config import AppConfig
from .exceptions import UnknownBackend, install_handlers
from .health import startup_health_check
from .db import log_scan

app = FastAPI()
install_handlers(app)

BACKENDS = {"snyk": AppConfig().url_scanner_snyk}
# clair?


@app.on_event("startup")
async def on_app_startup():
    await startup_health_check()


@app.post("/scans", response_model=list[ScanLog])
async def scan_images(req: ScanRequest) -> list[ScanLog]:
    """Scan one or more images."""
    # TODO: (further work) use pub/sub to submit one message for each image
    #       Spin up N cloud run instances to scan all images in parallel
    scans = await do_request_scans(req)
    return scans


async def do_request_scans(req: ScanRequest) -> list[ScanLog]:
    """Sends requests to the scanner service in parallel.
    Collects the results, parses them, and returns the parsed scans.

    Parameters
    ----------
    req : `ScanRequest`
        The request body to use to construct the requests for the scanner service.

    Returns
    -------
    `list[ScanLog]`
        The parsed scans.
    """

    # Instantiate async client
    # (`async with AsyncClient(...)` is inconsistent when combined with asyncio.gather)
    # Sometimes it closes the client while some requests are still pending
    client = httpx.AsyncClient(timeout=AppConfig().timeout_scanner)

    if req.repository:
        images = await get_repos_in_registry(req.repository, req.excluded_images)
    else:
        # get images from list
        images = req.images

    # send request for each image
    url = get_scan_service_url(req.backend)
    coros = [_send_scan_request(client, url, image, req) for image in images]
    responses = await asyncio.gather(*coros)

    # close connection since we don't use ctx manager
    # TODO: do this in a try/finally block and return before closing
    await client.aclose()

    # Filter out failed responses
    # TODO: option to raise for bad responses
    ok, failed = await _check_responses(responses, req.ignore_failed)
    scans = await _parse_scan_responses(ok, req.ignore_failed)
    coros = [log_scan(scan, req) for scan in scans]
    try:
        results = await asyncio.gather(*coros)
    except Exception as e:
        logger.exception(f"Failed to log scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to log scans: {e}")
    return results  # cast to list or change return type of func?


def get_scan_service_url(backend: str) -> str:
    """Returns the URL of the scanner service for the given backend."""
    backend = backend.lower()
    if backend not in BACKENDS:
        raise UnknownBackend(f"{backend}")
    return BACKENDS[backend]


@backoff.on_exception(
    backoff.expo,
    httpx.RequestError,
    max_tries=5,
    on_backoff=on_backoff,
    on_giveup=on_giveup,
)
async def _send_scan_request(
    client: httpx.AsyncClient, url: str, image: str, options: ScanRequest
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
    options : `ScanRequest`
        The scan options to use.

    Returns
    -------
    `httpx.Response`
        The response from the request.
    """
    req = ScanRequest.parse_obj(options)
    req.images = [image]  # only supply one image per invocation
    res = await client.post(
        f"{url}/scans",
        # TODO: use Pydantic model instead for options?
        json={"image": image, "base_vulns": options.base_vulns},
    )
    return res


async def _check_responses(
    responses: list[httpx.Response], ignore_failed: bool
) -> tuple[list[httpx.Response], list[httpx.Response]]:
    """Sorts out failed or malformed responses and returns the rest."""
    failed = [res for res in responses if res.is_error]
    ok = [res for res in responses if not res.is_error]
    await _handle_failed(failed, ignore_failed)
    return ok, failed


async def _parse_scan_responses(
    responses: list[httpx.Response], ignore_failed: bool
) -> list[ScanResults]:
    """Parses the contents of responses and returns the parsed scans.

    Splits the responses into successful and failed scans.

    Parameters
    ----------
    responses : `list[httpx.Response]`
        List of responses from the scanner service.
    ignore_failed : `bool`
        Whether to ignore failed responses or not.
        If true, failed responses raise exceptions.
    """
    scans = []  # list[ScanResults]
    failed = []
    for res in responses:
        try:
            j = res.json()
            scans.append(ScanResults(**j))
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


async def _handle_failed(failed: list[httpx.Response], ignore_failed: bool) -> None:
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
            try:
                failures = [r.json() for r in failed]
            except Exception as e:
                failures = [r.text for r in failed]
            raise HTTPException(status_code=500, detail={"failures": failures})


@app.get("/scans", response_model=list[ScanLog])
async def get_scans() -> list[ScanLog]:
    """Get all scans."""
    raise HTTPException(status_code=501, detail="Not implemented")


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


@app.head("/scans")
async def get_scans_head() -> PlainTextResponse:
    """HEAD request handler that checks if database is reachable."""
    if await check_db_exists(AppConfig().collection_scans):
        return PlainTextResponse(status_code=200)
    else:
        raise HTTPException(status_code=500, detail="Database unreachable")


@app.get("/status", response_model=ServiceStatus)
async def get_service_status(request: Request) -> ServiceStatus:
    """Get the status of the server."""
    # TODO: add more backends. We just return the status of the Snyk scanner now.
    return await _get_scanner_status(request, AppConfig().url_scanner_snyk, "Snyk")


async def _get_scanner_status(request: Request, url: str, name: str) -> ServiceStatus:
    status = partial(ServiceStatus, url=request.url)
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(f"{url}/status")
        except httpx.RequestError:
            return status(
                status=ServiceStatusCode.DOWN,
            )
        if res.is_error:
            return status(
                status=ServiceStatusCode.ERROR,
                message=f"Scanner ({name}) returned an error: {res.text}",
            )
        return status(
            status=ServiceStatusCode.OK,
        )
