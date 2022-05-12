from typing import Any
from auspex_core.models.api.report import ReportRequestBase
from pydantic import Field, conlist, validator, root_validator

# TODO: add timeouts as fields?
class ScanReportRequest(ReportRequestBase):
    """Model used for requesting both a scan and report for one or more images."""

    # This clas facilitates a more natural user interface for the /reports endpoint,
    # due to the fact that a scan and report are often requested together.
    #
    # Users are not expected to know scan IDs, but are expected to know image names.
    # This model impements image names as the primary way to initiate report creation.
    #
    # The model is based on the ReportRequestBase model, which is a base model for
    # all report requests.

    images: conlist(str, min_items=1, unique_items=True,) = Field(
        default_factory=list,
        description="List of images to scan and report.",
    )

    # images: list[str] = Field(
    #     default_factory=list,
    #     description="List of image names to scan and report.",
    #     min_items=1,
    # )

    # NYI: repository

    @validator("images")
    def validate_images(cls, v: list[str]) -> list[str]:
        # Ensure no duplicates
        return list(set(v))

    @root_validator()
    def root_validator(cls, values: dict[str, Any]) -> dict[str, Any]:
        # Ensure that at at least two images are provided if aggregate is True
        if values["aggregate"] and len(values["images"]) < 2:
            raise ValueError(
                "At least two images must be provided if aggregate is True."
            )
        return values
