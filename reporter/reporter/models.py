from typing import List
from pydantic import BaseModel, Field, validator
from .frontends import SUPPORTED_FRONTENDS
from .config import AppConfig


class ReportRequestIn(BaseModel):
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

    @validator("format")
    def validate_format(cls, v: str) -> str:
        v = v.lower()
        if v not in SUPPORTED_FRONTENDS:
            raise ValueError(f"Report frontend must be one of: {SUPPORTED_FRONTENDS}")
        return v
