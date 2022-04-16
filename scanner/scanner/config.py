from typing import Optional
from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    collection_scans: str = Field(..., env="COLLECTION_SCANS")
    bucket_scans: str = Field(..., env="BUCKET_SCANS")
    project: str = Field(..., env="GOOGLE_CLOUD_PROJECT")
    google_credentials: Optional[str] = Field(
        None, env="GOOGLE_APPLICATION_CREDENTIALS"
    )
