# TODO: rename from <Category>Data to something more appropriate
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TableData:
    title: str
    header: list[str] = field(default_factory=list)  # column names
    rows: list[list[Any]] = field(
        default_factory=list
    )  # each row is a list of len(header)
    caption: str = ""
    description: str = ""
    # TODO: add rich description class

    @property
    def empty(self) -> bool:
        return len(self.rows) == 0
