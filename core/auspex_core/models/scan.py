from datetime import datetime
from re import S
from typing import Any
from pydantic import BaseModel
from .status import Status


class ScanReport(BaseModel):
    """Report for scan of a single container image."""

    image: str
    date: datetime
    raw: str  # URL to raw scan data (.json log file usually)
    pdf: str  # URL to PDF formatted report


class ScanIn(BaseModel):
    images: list[str]
    backend: str = "snyk"
    # pdf: bool = True # TODO: figure out if we need this switch


class ScanOut(BaseModel):
    status: Status
    summary: str | None  # URL to summary report of all images (PDF)
    reports: list[ScanReport]
