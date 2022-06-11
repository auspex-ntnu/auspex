from typing import Optional

from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    url_scanner_snyk: str = Field(..., env="URL_SCANNER_SNYK")
    collection_scans: str = Field(..., env="COLLECTION_SCANS")
    bucket_scans: str = Field(..., env="BUCKET_SCANS")
    timeout_scanner: Optional[float] = Field(600, env="TIMEOUT_SCANNER")
