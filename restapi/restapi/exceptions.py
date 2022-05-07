from typing import TYPE_CHECKING, Any, Callable, Type, TypeVar, Union
from fastapi import FastAPI, Request
from google.api_core.exceptions import FailedPrecondition
from fastapi.responses import PlainTextResponse
from loguru import logger
from httpx import HTTPStatusError


def handle_FailedPrecondition(
    request: Request, exc: FailedPrecondition
) -> PlainTextResponse:
    """Handles FailedPrecondition exceptions which usually stem from
    failed or malformed Firestore queries."""
    logger.error(exc)  # NOTE: can we just log the exception like this?
    return PlainTextResponse(str(exc.message), status_code=500)


def handle_HTTPStatusError(req: Request, exc: HTTPStatusError) -> PlainTextResponse:
    """Handles HTTPStatusError which stem from failed HTTP requests by the httpx module."""
    logger.error(exc)
    return PlainTextResponse(
        content=exc.response.text, status_code=exc.response.status_code
    )


def install_handlers(app: FastAPI):
    """Installs custom exception handlers for the FastAPI app."""
    # TODO: find out how to type this. How to do type[generic]?
    handlers = {
        FailedPrecondition: handle_FailedPrecondition,
        HTTPStatusError: handle_HTTPStatusError,
    }
    for exc, handler in handlers.items():
        app.add_exception_handler(exc, handler)  # type: ignore
