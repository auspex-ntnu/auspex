from typing import NamedTuple, Any
from datetime import datetime

from ...types.nptypes import MplRGBAColor


class TableData(NamedTuple):
    title: str
    header: list[str]  # column names
    rows: list[list[Any]]  # each row is a list of len(header)


class VulnAgePoint(NamedTuple):
    """Represents a single datapoint in a scatter plot showing
    the age of vulnerabilities."""

    timestamp: datetime
    score: float
    color: MplRGBAColor
