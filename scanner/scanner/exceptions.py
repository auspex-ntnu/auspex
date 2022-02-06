from fastapi.exceptions import HTTPException


class HTTPNotFoundException(HTTPException):
    def __init__(self, resource: str, *args, **kwargs):
        super().__init__(404, f"{resource} not found.", *args, **kwargs)


class APIError(Exception):
    pass
