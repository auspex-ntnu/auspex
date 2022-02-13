from enum import Enum, auto

from pydantic import BaseModel


class StatusCode(Enum):
    OK = 0
    PARTIAL_FAILURE = 1
    FAILURE = 2
    # TODO: expand


class Status(BaseModel):
    """Status of a Scanner invocation."""

    code: StatusCode
    message: str | None
