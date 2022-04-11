from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field

from .gcr import ImageInfo
from .cve import CVSS

# Very similar definition of Scan from /functions/logger/gcp/main.py
class ScanLog(BaseModel):
    """Model for documents in auspex-logs"""

    image: ImageInfo
    backend: str  # Scanner backend tool used
    id: str
    timestamp: datetime
    url: str
    blob: str
    bucket: str


class CVSSv3Distribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ParsedVulnerabilities(BaseModel):
    vulnerabilities: list[BaseModel] = Field(default=list())
    ok: bool  # Denotes whether or not storing vulnerabilities of this type was successful


class Vulnerabilities(BaseModel):
    low: ParsedVulnerabilities
    medium: ParsedVulnerabilities
    high: ParsedVulnerabilities
    critical: ParsedVulnerabilities


class ReportData(BaseModel):
    """Models a document in the reports collection."""

    id: str
    image: ImageInfo
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cvss: CVSS  # TDOO: add shared pydantic model for this field
    vulnerabilities: CVSSv3Distribution
    report_url: Optional[str]
    aggregate: bool = False  # Whether or not this report is an aggregate report
    schema_version: str = "1"  # Schema version to account for future schema changes
    historical: bool = (
        False  # Whether or not this report is historical (i.e. not the latest)
    )
    updated: datetime = Field(
        default_factory=datetime.utcnow
    )  # When the document was updated

    # Has subcollection of vulnerabilities
