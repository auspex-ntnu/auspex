from typing import List
from pydantic import BaseModel, Field, validator
from .frontends import SUPPORTED_FRONTENDS
from .config import AppConfig


class ReportRequestIn(BaseModel):
    document_id: list[str] = Field(..., min_items=1)
    ignore_failed: bool = False
    format: str = "latex"
    # rename to style?

    @validator("format")
    def validate_format(cls, v: str) -> str:
        v = v.lower()
        if v not in SUPPORTED_FRONTENDS:
            raise ValueError(f"Report frontend must be one of: {SUPPORTED_FRONTENDS}")
        return v
