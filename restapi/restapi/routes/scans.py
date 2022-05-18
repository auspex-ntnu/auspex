import asyncio
from json import JSONDecodeError
import backoff

import httpx
from auspex_core.models.api.scan import ScanRequest
from auspex_core.models.scan import ScanLog
from fastapi import APIRouter
from fastapi.exceptions import HTTPException
from loguru import logger
from auspex_core.utils.backoff import on_backoff, on_giveup

from ..config import AppConfig

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanLog)
async def get_scan(scan_id: str) -> ScanLog:
    """Get a scan by its ID."""
    async with httpx.AsyncClient(timeout=AppConfig().timeout_scanner) as client:
        res = await client.get(f"{AppConfig().url_scanner}/{scan_id}")
    res.raise_for_status()
    try:
        return res.json()
    except Exception as e:
        logger.error(f"Could not parse response: {e}")
        raise HTTPException(status_code=500, detail="Could not parse scan response.")


@router.get("", response_model=list[ScanLog])
async def get_scans() -> list[ScanLog]:
    """Get all scans."""
    # NYI
    pass


@router.post("", response_model=list[ScanLog])
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

    # send request for each image
    url = f"{AppConfig().url_scanner}/scans"
    coros = [
        _send_scan_request(client, url, image, req.backend) for image in req.images
    ]
    responses = await asyncio.gather(*coros)

    # close connection since we don't use ctx manager
    # TODO: do this in a try/finally block and return before closing
    await client.aclose()

    # Filter out failed responses
    # TODO: option to raise for bad responses
    ok, failed = await _check_responses(responses, req.ignore_failed)
    scans = await _parse_scan_responses(ok, req.ignore_failed)
    return scans


@backoff.on_exception(
    backoff.expo,
    httpx.RequestError,
    max_tries=5,
    on_backoff=on_backoff,
    on_giveup=on_giveup,
)
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
    req = ScanRequest(image=image, backend=backend)
    res = await client.post(
        url,
        json=req.dict(),
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
) -> list[ScanLog]:
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
