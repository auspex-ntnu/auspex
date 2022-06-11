from typing import Any

from auspex_core.models.api.report import ReportRequestBase
from auspex_core.models.api.scan import ScanRequest
from pydantic import Field, root_validator, validator


# TODO: add timeouts as fields?
class ScanReportRequest(ReportRequestBase, ScanRequest):
    """Model used for requesting both a scan and report for one or more images.

    Combines the fields of both ScanRequest and ReportRequestBase.

    This class facilitates a more natural user interface for the /reports endpoint,
    due to the fact that a scan and report are often requested together.

    Users are not expected to know scan IDs, but are expected to know image names.
    This model impements image names as the primary way to initiate report creation.
    """

    # FIXME: this creates a TIGHT coupling between the the gateway and the two services
    # (scanner and reporter). How can we facilitate this better?

    images: list[str] = Field(
        default_factory=list,
        description="List of image names to scan and report.",
        min_items=1,
    )

    class Config:
        extra = "allow"

    # NYI: repository

    @validator("images")
    def validate_images(cls, v: list[str]) -> list[str]:
        # Ensure no duplicates
        return list(set(v))

    @root_validator()
    def root_validator(cls, values: dict[str, Any]) -> dict[str, Any]:
        # Ensure that at at least two images are provided if aggregate is True
        if values.get("aggregate") and len(values.get("images", [])) < 2:
            raise ValueError(
                "At least two images must be provided if aggregate is True."
            )
        return values
