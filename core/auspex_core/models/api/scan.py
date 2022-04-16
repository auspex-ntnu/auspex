import os
from typing import Optional

from pydantic import BaseModel, Field


DEFAULT_FORMAT = os.getenv("REPORTER_DEFAULT_FORMAT") or "latex"

# FIXME: why is this shared
class ScanRequest(BaseModel):
    images: list[str] = Field(
        default_factory=list,
        description="List of image names to scan.",
    )

    repository: Optional[str] = Field(
        default=None,
        description="Repository name to scan images of. Supercedes images.",
    )

    format: str = Field(
        default=DEFAULT_FORMAT,
        description="Format of report.",
    )  # FIXME: This should be defined in reporter's model

    backend: str = Field(
        default="snyk",
        description="Scanning backend to use.",
    )  # FIXME: This should be defined in scanner's model

    ignore_failed: bool = Field(
        default=False,
        description="Whether or not to ignore failed scans. Failed scans raise exception if False.",
    )  # TODO: Get default value from config

    class Config:
        extra = "allow"  # allow extra fields in the request
