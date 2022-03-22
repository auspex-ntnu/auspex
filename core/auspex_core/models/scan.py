from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


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


class ParsedScan(BaseModel):
    id: str
    image: str
    scanned: datetime = Field(default_factory=datetime.now)
    cvss_min: float
    cvss_max: float
    cvss_mean: float
    cvss_median: float
    cvss_stdev: float
    vulnerabilities: CVSSv3Distribution
    # most_common_cve: dict[str, int]  # IDs of most common vulnerabilities
    report_url: Optional[str]
    # Has subcollection

    schema_version: str = "1"  # to account for future schema changes
