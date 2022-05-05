from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    bucket_reports: str = Field(..., env="BUCKET_REPORTS")
    collection_reports: str = Field(..., env="COLLECTION_REPORTS")
    url_scanner: str = Field(..., env="URL_SCANNER")
    trend_weeks: int = Field(26, env="REPORTER_TREND_WEEKS")
    debug: bool = Field(False, env="DEBUG")
