import os
from typing import Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from loguru import logger

from .types import ScanResultsType
from .scan import scan_container
from .exceptions import APIError, UserAPIError
import backoff
from auspex_core.models.scan import ScanOut

from pydantic import BaseModel, BaseSettings, Field, ValidationError
import httpx

if os.getenv("DEBUG") == "1":
    import debugpy

    DEBUG_PORT = 5678
    debugpy.listen(("0.0.0.0", DEBUG_PORT))
    logger.debug(f"Debugger is listening on port {DEBUG_PORT}")
    # debugpy.wait_for_client()
    # debugpy.breakpoint()

app = FastAPI()


class ScanIn(BaseModel):
    image: str
    backend: str = "snyk"


class CompletedScan(BaseModel):
    image: str
    backend: str
    scan: str


class AppSettings(BaseSettings):
    logger_url: str = Field(..., env="URL_LOGGER")


settings = AppSettings()

# TODO: improve exception handlers


@app.exception_handler(ValidationError)
async def handle_validation_error(request: Request, exc: ValidationError):
    # TODO: improve message
    logger.error("A pydantic validation error occured", exception=exc)
    return JSONResponse(
        status_code=400,
        content={"detail": exc.errors()},
    )


@app.exception_handler(APIError)
async def handle_api_error(request: Request, exc: APIError):
    # TODO: improve message
    logger.error("An exception occured", exception=exc)
    return JSONResponse(status_code=400, content=exc.args)


@app.exception_handler(UserAPIError)
async def handle_user_api_error(request: Request, exc: UserAPIError):
    logger.debug("A user API exception occured", exception=exc)
    return JSONResponse(status_code=500, content=exc.args)


def _scan_giveup_callback(details: dict[str, Any]) -> None:
    """Callback function that is fired when the results of a scan cannot be logged."""
    logger.error(
        "Gave up after {tries} tries calling function {target} "
        "with args {args} and kwargs {kwargs}".format(**details)
    )
    raise HTTPException(status_code=500, detail="Unable to log scan results.")


def _backoff_callback(details: dict[str, Any]) -> None:
    """Callback function that should be fired whenever a backoff is triggered."""
    # Directly ripped off from https://github.com/litl/backoff#event-handlers
    logger.warning(
        "Backing off {wait:0.1f} seconds after {tries} tries "
        "calling function {target} with args {args} and kwargs "
        "{kwargs}".format(**details)
    )


@backoff.on_exception(
    backoff.expo,
    exception=httpx.RequestError,
    max_tries=5,
    on_backoff=_backoff_callback,
    on_giveup=_scan_giveup_callback,
)
async def log_completed_scan(scan: ScanResultsType) -> dict[str, Any]:
    s = CompletedScan.parse_obj(scan)
    async with httpx.AsyncClient() as client:
        res = await client.post(settings.logger_url, json=s.dict())
        res.raise_for_status()
        try:
            j = res.json()  # type: dict[str, Any]
        except:  # TODO: specify which exception
            msg = "Unable to deserialize JSON response"
            logger.error(msg, res.text)
            raise APIError(
                msg
            )  # this will not be caught by backoff and abort immediately
        return j


@app.post("/scan", response_model=ScanOut)
async def scan_endpoint(scan_request: ScanIn) -> ScanOut:
    """Scans a single container image."""
    scan = await scan_container(
        image=scan_request.image,
        backend=scan_request.backend,
    )
    if not scan.ok:
        msg = f"Scan failed with the following output:\nstdout: {scan.scan}\nstderr:{scan.error}"
        logger.error(msg)
        # FIXME: add detail message
        raise HTTPException(status_code=500, detail=msg)

    s = await log_completed_scan(scan)

    # use scan
    return s
