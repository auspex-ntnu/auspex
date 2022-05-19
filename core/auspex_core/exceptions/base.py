class AuspexError(Exception):
    """Base class for Auspex exceptions."""


class ClientError(AuspexError):
    """Base class for client exceptions (4xx)"""

    status_code: int

    def __init__(self, message: str, status_code: int = 400) -> None:
        self.status_code = status_code
        super().__init__(message)


class ServerError(AuspexError):
    """Base class for server errors (5xx)"""

    status_code: int

    def __init__(self, message: str, status_code: int = 500) -> None:
        self.status_code = status_code
        super().__init__(message)
