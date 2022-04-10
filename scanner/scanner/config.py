from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    logger_url: str = Field(..., env="URL_LOGGER")
    project: str = Field(..., env="GCP_PROJECT")
