import os
from typing import Optional

from pydantic import BaseModel, Field


DEFAULT_FORMAT = os.getenv("REPORTER_DEFAULT_FORMAT") or "latex"


class ScanRequest(BaseModel):
    images: list[str] = Field(default_factory=list)
    repository: Optional[str] = None
    format: str = DEFAULT_FORMAT  # support multiple formats?
    backend: str = "snyk"
    ignore_failed: bool = False
