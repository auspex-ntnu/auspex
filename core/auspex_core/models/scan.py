from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field

from .gcr import ImageInfo, ImageTimeMode
from .cve import CVSS

# Very similar definition of Scan from /functions/logger/gcp/main.py
class ScanLog(BaseModel):
    """Model for documents in scanner's collection"""

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
    cvss: CVSS
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
    upgrade_paths: list[str] = Field(default_factory=list)
    dockerfile_instructions: list[str] = Field(default_factory=list)

    class Config:
        schema_extra = {
            "example": {
                "id": "image_name_1",
                "image": {
                    "image_size_bytes": "12345",
                    "layerId": "sha256:12345",
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "tag": ["latest", "1.0"],
                    "timeCreatedMs": "1577836800000",  # TODO: fix these example timestamps
                    "timeUploadedMs": "1577836800000",
                },
                "timestamp": "2020-01-01T00:00:00Z",
                "cvss": {"base": 7.5, "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
                "vulnerabilities": {
                    "low": 10,
                    "medium": 15,
                    "high": 5,
                    "critical": 1,
                },
                "report_url": "https://example.com/report",
                "aggregate": True,
                "schema_version": "1",
                "historical": False,
                "updated": "2020-01-01T00:00:00Z",
                "upgrade_paths": ["libc@6.6.6"],
                "dockerfile_instructions": ["sudo apt-get install -y libc666"],
            }
        }

    # Has subcollection of vulnerabilities

    # implement Plottable protocol methods
    def get_age_and_mean_score(self) -> tuple[datetime, float]:
        return (self.timestamp, self.cvss.mean)

    def get_timestamp(
        self, image: bool = True, mode: ImageTimeMode = ImageTimeMode.CREATED
    ) -> datetime:
        if image:
            ts = self.image.get_timestamp(mode=mode)
        else:
            ts = self.timestamp
        if not ts.tzinfo:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts


class ReportDataCollection(BaseModel):
    """Collection of ReportData objects"""

    __root__: list[ReportData] = Field(default_factory=list)

    def get_age_and_mean_score(self) -> list[tuple[datetime, float]]:
        d: list[tuple[datetime, float]] = []
        for r in self.__root__:
            d.append((r.timestamp, r.cvss.mean))
        d.sort(key=lambda x: x[0])
        return d
