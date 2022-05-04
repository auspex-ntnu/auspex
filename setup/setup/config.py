from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    collection_reports: str = Field(..., env="COLLECTION_REPORTS")
    project_id: str = Field(..., env="GOOGLE_CLOUD_PROJECT")
    bucket_scans: str = Field(..., env="BUCKET_SCANS")
    bucket_reports: str = Field(..., env="BUCKET_REPORTS")
    credentials: str = Field("", env="GOOGLE_APPLICATION_CREDENTIALS")
