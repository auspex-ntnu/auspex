import os
from typing import Optional

from pydantic import BaseModel, Field


# FIXME: why is this shared


class ScanRequest(BaseModel):
    images: list[str] = Field(
        default_factory=list,
        description="List of image names to scan.",
    )

    # NYI:
    repository: Optional[str] = Field(
        default=None,
        description="Repository name to scan images of. Supercedes images.",
    )

    backend: str = Field(
        default="snyk",
        description="Scanning backend to use.",
    )

    ignore_failed: bool = Field(
        default=False,
        description="Whether or not to ignore failed scans. Failed scans raise exception if False.",
    )  # TODO: Get default value from config

    base_vulns: bool = Field(
        default=True,
        description="Whether or not to include base image vulnerabilities. See: https://docs.snyk.io/snyk-cli/commands/container#exclude-base-image-vulns",
    )

    # Currently NOT supported with Snyk JSON output as of Snyk v1.933.0
    # app_vulns: bool = Field(
    #     default=True,
    #     description="Whether or not to include application vulnerabilities. See: https://docs.snyk.io/snyk-cli/commands/container#app-vulns",
    # )

    class Config:
        extra = "allow"  # allow extra fields in the request
