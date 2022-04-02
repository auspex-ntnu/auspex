from datetime import datetime
from enum import Enum
import os
from typing import Any, Iterable, NamedTuple, Optional
from pydantic import BaseModel, Field, validator
from google.cloud import firestore


class FirestoreQuery(NamedTuple):
    field: str
    operator: str
    value: Any


class Direction(Enum):
    ASCENDING = firestore.Query.ASCENDING
    DESCENDING = firestore.Query.DESCENDING


class OrderBy(BaseModel):
    field: str
    direction: Direction = Direction.DESCENDING  # TODO: decide on default direction

    @validator("direction", pre=True)
    def validate_direction(cls, v: Any) -> str:
        valid = {
            Direction.ASCENDING: ["asc", "ascending", "ascend"],
            Direction.DESCENDING: ["desc", "descending", "descend"],
        }
        if not isinstance(v, str):
            raise TypeError("argument 'direction' must be a string")

        v = v.lower()
        if v in valid[Direction.ASCENDING]:
            return Direction.ASCENDING.value
        elif v in valid[Direction.DESCENDING]:
            return Direction.DESCENDING.value
        raise ValueError(
            f"Invalid argument for 'direction'. Accepted arguments: {valid}"
        )


class Filter(BaseModel):
    cvss_mean: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_median: Optional[float] = Field(None, ge=0.0, le=10.0)
    critical: Optional[int] = Field(None, ge=0)

    def get_filters(self) -> Iterable[tuple[str, Any]]:
        """Generator that yields all attributes whose values are not None."""
        for k, v in self.dict().items():
            if v is not None:
                yield (k, v)


class ReportRequest(BaseModel):
    image: str
    filter: Optional[Filter] = None
    limit: Optional[int] = Field(None, gt=0)
    order_by: Optional[OrderBy] = None

    @validator("image")
    def ensure_not_empty(cls, v: str) -> str:
        if len(v) == 0:
            raise ValueError("Image cannot be an empty string.")
        return v

    def get_query(self) -> FirestoreQuery:
        return FirestoreQuery(field="image", operator="==", value=self.image)
