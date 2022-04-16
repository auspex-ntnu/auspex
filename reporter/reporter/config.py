from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    bucket_scans: str = Field(..., env="BUCKET_SCANS")
    bucket_reports: str = Field(..., env="BUCKET_REPORTS")
    collection_scans: str = Field(..., env="COLLECTION_SCANS")
    collection_reports: str = Field(..., env="COLLECTION_REPORTS")
    trend_weeks: int = Field(24, env="REPORTER_TREND_WEEKS")
