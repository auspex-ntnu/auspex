from fastapi import FastAPI, Request
from google.api_core.exceptions import FailedPrecondition
from fastapi.responses import PlainTextResponse


def handle_FailedPrecondition(
    request: Request, exc: FailedPrecondition
) -> PlainTextResponse:
    return PlainTextResponse(str(exc.message), status_code=500)


def install_handlers(app: FastAPI):
    handlers = {
        FailedPrecondition: handle_FailedPrecondition,
    }
    for exc, handler in handlers.items():
        app.add_exception_handler(exc, handler)
