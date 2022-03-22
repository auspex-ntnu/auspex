from datetime import datetime
from enum import Enum
from typing import Any, NamedTuple, Optional
from pydantic import BaseModel, validator
from google.cloud import firestore


class InvalidQueryString(Exception):
    pass


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


class Limit(BaseModel):
    limit: int
    last: bool = False


class ParsedScanRequest(BaseModel):
    where: list[str]
    limit: Optional[Limit] = None
    order_by: Optional[OrderBy] = None

    def get_queries(self) -> list[FirestoreQuery]:
        res = [q.split(" ", 3) for q in self.where]
        rtn = []  # type: list[FirestoreQuery]
        for q in res:
            if len(q) != 3 or not all(token for token in q):
                raise InvalidQueryString(f"{q} is not a valid query.")
            rtn.append(FirestoreQuery(field=q[0], operator=q[1], value=q[2]))
        return rtn
