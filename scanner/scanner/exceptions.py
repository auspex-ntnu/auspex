from fastapi.exceptions import HTTPException


class HTTPNotFoundException(HTTPException):
    def __init__(self, resource: str, *args, **kwargs):
        super().__init__(404, f"{resource} not found.", *args, **kwargs)


class APIError(Exception):
    """Exception raised in response to serverside errors."""


class UserAPIError(Exception):
    """Exception raised in response to bad input from user."""
