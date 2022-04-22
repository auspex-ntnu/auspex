from typing import NamedTuple, Any


class TableData(NamedTuple):
    title: str
    header: list[str]  # column names
    rows: list[list[Any]]  # each row is a list of len(header)
