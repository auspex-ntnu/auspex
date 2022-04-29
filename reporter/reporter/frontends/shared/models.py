from enum import Enum, auto
from typing import NamedTuple, Any
from datetime import datetime
from pathlib import Path

from ...types.nptypes import MplRGBAColor


class PlotType(Enum):
    PIE = auto()
    BAR = auto()
    LINE = auto()
    SCATTER = auto()
    HISTOGRAM = auto()


class Hyperlink(NamedTuple):
    url: str
    text: str


# TODO: rename from <Category>Data to something more appropriate
class TableData(NamedTuple):
    title: str
    header: list[str]  # column names
    rows: list[list[Any]]  # each row is a list of len(header)
    caption: str = ""
    description: str = ""


class PlotData(NamedTuple):
    title: str
    path: Path
    caption: str
    plot_type: PlotType
    description: str = ""


class VulnAgePoint(NamedTuple):
    """Represents a single datapoint in a scatter plot showing
    the age of vulnerabilities."""

    timestamp: datetime
    score: float
    color: MplRGBAColor
