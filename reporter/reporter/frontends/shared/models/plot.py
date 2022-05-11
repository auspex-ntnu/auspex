from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import NamedTuple, Optional

from ....types.nptypes import MplRGBAColor  # should that be moved to .common?


class PlotType(Enum):
    PIE = auto()
    BAR = auto()
    LINE = auto()
    SCATTER = auto()
    HISTOGRAM = auto()


@dataclass
class PlotData:
    title: str
    plot_type: PlotType
    description: str = ""
    caption: str = ""
    path: Optional[Path] = None


class VulnAgePoint(NamedTuple):
    """Represents a single datapoint in a scatter plot showing
    the age of vulnerabilities."""

    timestamp: datetime
    score: float
    color: MplRGBAColor
