from enum import Enum
import os
from typing import Any, Iterable, NamedTuple, Optional, Union
from auspex_core.models.cve import CVSS, CVSS_MAX_SCORE, CVSS_MIN_SCORE
from pydantic import BaseModel, Field, root_validator, validator
from google.cloud import firestore
from .scan import ScanRequest


class FirestoreQuery(NamedTuple):
    field: str
    operator: str
    value: Any


class Direction(Enum):
    ASCENDING = firestore.Query.ASCENDING
    DESCENDING = firestore.Query.DESCENDING


class CVSSField(Enum):
    # NOTE: could we use the schema of auspex_core.models.cve.CVSS here?
    MEAN = "mean"
    MEDIAN = "median"
    STDEV = "stdev"
    MIN = "min"
    MAX = "max"


class OrderOption(Enum):
    NEWEST = "newest"
    OLDEST = "oldest"
    MAXSCORE = "maxscore"
    MINSCORE = "minscore"


class ReportQuery(BaseModel):
    # either image or aggregate MUST be specified
    image: str = Field("", description="Image to search for.")
    aggregate: str = Field(
        False, description="Whether or not to search for aggregate reports."
    )

    # Minimum CVSS score
    ge: Optional[Union[float, int]] = Field(
        None,
        ge=CVSS_MIN_SCORE,
        le=CVSS_MAX_SCORE,
        description="Minimum CVSS score.",
    )

    # Maximum CVSS score
    le: Optional[Union[float, int]] = Field(
        None,
        ge=CVSS_MIN_SCORE,
        le=CVSS_MAX_SCORE,
        description="Maximum CVSS score.",
    )

    field: CVSSField = Field(
        CVSSField.MEAN,
        description="Field to compare CVSS score with.",
    )

    # Limit number of results
    limit: Optional[int] = Field(
        None,
        gt=0,
        description="Limit the number of results.",
    )

    order: OrderOption = Field(
        OrderOption.NEWEST,
        description="Sort results by date.",
    )

    # TODO: add has_report
    # has_report: bool = Field(False, description="Whether or not the report has been generated.")

    # TODO: add max_age
    # max_age: Optional[int] = Field(None, gt=0, description="Maximum age of reports in days.")

    @root_validator
    def validate_values(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values["image"] and values["aggregate"]:
            raise ValueError("Cannot search for both image and aggregate.")
        if not values["image"] and not values["aggregate"]:
            raise ValueError("Must search for either image or aggregate.")
        if values["le"] is not None and values["ge"] is not None:
            if values["le"] < values["ge"]:
                raise ValueError("`le` must be greater than `ge`.")
        return values


DEFAULT_FORMAT = os.getenv("REPORTER_DEFAULT_FORMAT") or "latex"


class ReportRequest(ScanRequest):
    format: str = Field(
        default=DEFAULT_FORMAT,
        description="Format of report.",
    )  # FIXME: This should be defined in reporter's model
