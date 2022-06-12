from typing import Optional

from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    project: str = Field(..., env="GOOGLE_CLOUD_PROJECT")
    google_credentials: str = Field(..., env="GOOGLE_APPLICATION_CREDENTIALS")
