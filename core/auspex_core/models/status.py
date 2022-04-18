from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field, validator
from starlette.datastructures import URL


class ServiceStatusCode(Enum):
    OK = "OK"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DOWN = "DOWN"
    # TODO: expand


class ServiceStatus(BaseModel):
    status: ServiceStatusCode = Field(..., description="The status of the service.")
    message: Optional[str] = Field(
        None, description="Additional information about the status."
    )
    url: str = Field(..., description="URL of the service.")
    # additional fields ...
    class Config:
        extra = "allow"
        schema_extra = {
            "example": {
                "status": "OK",
                "message": "Service is running",
                "url": "http://localhost:5000",
            }
        }

    @validator("url", pre=True)
    def coerce_url_str(cls, v: Union[str, URL]) -> str:
        if isinstance(v, str):
            return v
        return str(v)


class ServiceStatusAggregate(BaseModel):
    __root__: dict[str, ServiceStatus]

    class Config:
        extra = "allow"
        schema_extra = {
            "example": {
                "reporter": {
                    "status": "OK",
                    "message": "Service is running",
                    "url": "http://localhost:5000",
                },
                "restapi": {
                    "status": "OK",
                    "message": "Service is running",
                    "url": "http://localhost:5001",
                },
                "scanner": {
                    "status": "ERROR",
                    "message": "Snyk executable not found",
                    "url": "http://localhost:5002",
                },
            }
        }
