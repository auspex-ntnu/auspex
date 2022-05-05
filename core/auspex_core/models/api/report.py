import os
from enum import Enum
from typing import Any, Iterable, NamedTuple, Optional, Union

from google.cloud import firestore
from pydantic import BaseModel, Field, root_validator, validator

from ..cve import CVSS, CVSS_MAX_SCORE, CVSS_MIN_SCORE
from ..scan import ReportData
from ..api.scan import ScanRequest

from typing import List
from pydantic import BaseModel, Field, validator


class ReportRequestIn(BaseModel):
    """Request body for POST /reports"""

    # TODO: ensure no duplicates
    scan_ids: list[str] = Field(..., min_items=1)
    aggregate: bool = Field(
        False, description="Aggregate results in an aggregate report."
    )
    ignore_failed: bool = Field(
        False,
        description="Ignore scans that fail to be retrieved or parsed.",
    )
    format: str = "latex"  # TODO: make use of enum to validate this
    # rename to style?

    @validator("scan_ids")
    def validate_scan_ids(cls, v: List[str]) -> List[str]:
        # Ensure no duplicates
        return list(set(v))


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
    """Query parameters used to retrieve a report."""

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

# FIXME: define default format in config
class ReportRequest(ScanRequest):
    format: str = Field(
        default=DEFAULT_FORMAT,
        description="Format of report.",
    )  # FIXME: This should be defined in reporter's model


class ReportOut(BaseModel):
    reports: list[ReportData] = Field(
        ..., min_items=1, description="List of generated reports and their metadata."
    )
    aggregate: Optional[ReportData] = Field(None, description="Aggregate report data.")
    message: str = Field(
        "",
        description="Optional message describing the data.",
    )
    failed: list[str] = Field(
        default_factory=list, description="List of failed scan IDs."
    )
