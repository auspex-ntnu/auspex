from json import JSONDecodeError
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from auspex_core.docker.exceptions import DockerRegistryException
from loguru import logger
from fastapi.responses import JSONResponse


class HTTPNotFoundException(HTTPException):
    def __init__(self, resource: str, *args, **kwargs):
        super().__init__(404, f"{resource} not found.", *args, **kwargs)


class APIError(Exception):
    """Exception raised in response to serverside errors."""


class UserAPIError(Exception):
    """Exception raised in response to bad input from user."""


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


async def handle_DockerRegistryException(
    request: Request, exc: DockerRegistryException
):
    logger.error(f"Docker registry exception: {exc}")
    return await _handle_exception(
        request, exc, code=400, prefix="Docker registry error"
    )


async def handle_APIError(request: Request, exc: APIError):
    # TODO: improve message
    logger.error(f"An exception occured: {exc}")
    return await _handle_exception(request, exc, code=500)


async def handle_UserAPIError(request: Request, exc: UserAPIError):
    logger.debug(f"A user API exception occured: {exc}")
    return await _handle_exception(request, exc, code=400)


def install_handlers(app: FastAPI):
    """Installs custom exception handlers for the FastAPI app."""
    # TODO: find out how to type this. How to do type[generic]?
    handlers = {
        UserAPIError: handle_UserAPIError,
        APIError: handle_APIError,
        DockerRegistryException: handle_DockerRegistryException,
        Exception: _handle_exception,  # catch-all handler
    }
    for exc, handler in handlers.items():
        app.add_exception_handler(exc, handler)  # type: ignore
