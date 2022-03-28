from fastapi import FastAPI, Request
from google.api_core.exceptions import FailedPrecondition
from fastapi.responses import PlainTextResponse
from loguru import logger


def handle_FailedPrecondition(
    request: Request, exc: FailedPrecondition
) -> PlainTextResponse:
    """Handles FailedPrecondition exceptions which usually stem from
    failed or malformed Firestore queries."""
    logger.error(exc)  # NOTE: can we just log the exception like this?
    return PlainTextResponse(str(exc.message), status_code=500)


def install_handlers(app: FastAPI):
    """Installs custom exception handlers for the FastAPI app."""
    handlers = {
        FailedPrecondition: handle_FailedPrecondition,
    }
    for exc, handler in handlers.items():
        app.add_exception_handler(exc, handler)
