from typing import Optional
from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    url_reporter: str = Field(..., env="URL_REPORTER")
    url_scanner: str = Field(..., env="URL_SCANNER")
    collection_reports: str = Field(..., env="COLLECTION_REPORTS")
    timeout_reporter: Optional[float] = Field(None, env="TIMEOUT_REPORTER")
    timeout_scanner: Optional[float] = Field(None, env="TIMEOUT_SCANNER")
