from enum import Enum
from typing import Any, Iterable, NamedTuple, Optional
from auspex_core.models.cve import CVSS, CVSS_MAX_SCORE, CVSS_MIN_SCORE
from pydantic import BaseModel, Field, root_validator, validator
from google.cloud import firestore


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


class ReportQuery(BaseModel):
    image: str = Field(..., description="Image to search for.")

    # Minimum CVSS score
    ge: Optional[float] = Field(
        None,
        ge=CVSS_MIN_SCORE,
        le=CVSS_MAX_SCORE,
        description="Minimum CVSS score.",
    )

    # Maximum CVSS score
    le: Optional[float] = Field(
        None,
        ge=CVSS_MIN_SCORE,
        le=CVSS_MAX_SCORE,
        description="Maximum CVSS score.",
    )

    field: CVSSField = Field(
        CVSSField.MEAN,
        description="Field to order results by. Defaults to CVSS mean.",
    )

    # Limit number of results
    limit: Optional[int] = Field(
        None,
        gt=0,
        description="Limit the number of results.",
    )

    # Field to order by
    order_by: Optional[str] = Field(
        None,
        description="Order results by field.",
    )

    # Order by direction
    direction: Direction = Field(
        Direction.DESCENDING,
        description="Direction of ordering. Has no effect if `order_by` is not specified.",
    )

    # TODO: add has_report
    # has_report: bool = Field(False, description="Whether or not the report has been generated.")

    # TODO: add max_age
    # max_age: Optional[int] = Field(None, gt=0, description="Maximum age of reports in days.")

    @validator("direction")
    def validate_direction(cls, v: Any) -> Direction:
        """Validator that accepts multiple values for `direction`."""
        if isinstance(v, Direction):
            return v

        valid = {
            Direction.ASCENDING: ["asc", "ascending", "ascend"],
            Direction.DESCENDING: ["desc", "descending", "descend"],
        }
        if not isinstance(v, str):
            raise TypeError("argument 'direction' must be a string")

        v = v.lower()
        if v in valid[Direction.ASCENDING]:
            return Direction.ASCENDING
        elif v in valid[Direction.DESCENDING]:
            return Direction.DESCENDING
        raise ValueError(
            f"Invalid argument for 'direction'. Accepted arguments: {valid}"
        )

    @root_validator
    def validate_le_ge(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Validator that ensures that `le` is not greater than `ge`."""
        if values["le"] is not None and values["ge"] is not None:
            if values["le"] < values["ge"]:
                raise ValueError("`le` must be greater than `ge`.")
        return values
