from typing import Optional

from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    url_reporter: str = Field(..., env="URL_REPORTER")
    url_scanner: str = Field(..., env="URL_SCANNER")
    timeout_reporter: Optional[float] = Field(600, env="TIMEOUT_REPORTER")
    timeout_scanner: Optional[float] = Field(600, env="TIMEOUT_SCANNER")
