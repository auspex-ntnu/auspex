from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from google.api_core.exceptions import BadRequest, FailedPrecondition, GoogleAPIError
from httpx import HTTPStatusError
from loguru import logger
from pylatex.errors import PyLaTeXError


class NoScoresException(Exception):
    pass


class SingleDocRetrievalError(Exception):
    pass


class MultiDocRetrievalError(Exception):
    pass


class InvalidBackend(Exception):
    pass


class LogReportError(Exception):
    pass


async def _handle_exception(
    request: Request, exc: Exception, code: int = 500, prefix: str = ""
) -> JSONResponse:
    args = getattr(exc, "args")
    a = args[0] if args else str(exc)
    p = f"{prefix}: " if prefix else ""

    # NOTE: we can't get the request body here
    #
    # See: https://github.com/tiangolo/fastapi/issues/394
    #      https://stackoverflow.com/a/71811390
    #
    # However, we can add a middleware that stores the request body
    # if really want it: https://github.com/tiangolo/fastapi/issues/394#issuecomment-994665859

    content = {
        "detail": f"{p}{a}",
    }
    return JSONResponse(status_code=code, content=content)


async def handle_FailedPrecondition(
    request: Request, exc: FailedPrecondition
) -> JSONResponse:
    """Handles FailedPrecondition exceptions which usually stem from
    failed or malformed Firestore queries."""
    logger.error(f"Firestore error: {exc}")
    return await _handle_exception(request, exc, code=500, prefix="Firestore error")


async def handle_google_BadRequest(request: Request, exc: BadRequest) -> JSONResponse:
    """Handles GoogleAPIError which stem from failed Google API requests."""
    logger.error(exc)
    return await _handle_exception(
        request, exc, code=400, prefix="Bad request to GCP service"
    )


async def handle_GoogleAPIError(request: Request, exc: GoogleAPIError) -> JSONResponse:
    """Handles GoogleAPIError which stem from failed Google API requests."""
    logger.error(exc)
    return await _handle_exception(request, exc, code=400, prefix="Google API error")


async def handle_HTTPStatusError(
    request: Request, exc: HTTPStatusError
) -> JSONResponse:
    """Handles HTTPStatusError which stem from failed HTTP requests by the httpx module."""
    logger.error(exc)
    return await _handle_exception(request, exc, code=400, prefix="HTTP error")


async def handle_PyLaTeXError(request: Request, exc: PyLaTeXError) -> JSONResponse:
    """Handles PyLaTeXError which stem from failed LaTeX rendering."""
    logger.error(exc)
    return await _handle_exception(request, exc, code=500, prefix="LaTeX error")


def install_handlers(app: FastAPI):
    """Installs custom exception handlers for the FastAPI app."""
    # TODO: find out how to type this. How to do type[generic]?
    handlers = {
        FailedPrecondition: handle_FailedPrecondition,
        HTTPStatusError: handle_HTTPStatusError,
        BadRequest: handle_google_BadRequest,
        GoogleAPIError: handle_GoogleAPIError,
        PyLaTeXError: handle_PyLaTeXError,
    }
    for exc, handler in handlers.items():
        app.add_exception_handler(exc, handler)  # type: ignore
