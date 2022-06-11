from typing import Any, Literal, Optional, Sequence, Union

from pylatex import LongTable, LongTabu, LongTabularx, MultiColumn, NoEscape

from ..shared.models import Hyperlink
from .utils import hyperlink

LongTableType = Union[LongTable, LongTabu, LongTabularx]

AlignValues = Literal["l", "c", "r"]


def init_longtable(
    table: LongTableType,
    columns: Sequence[Any],
    align: AlignValues = "r",
    footer_text: str = "Continued on Next Page",
    end_footer_text: Optional[str] = None,
) -> LongTableType:
    """Initializes a longtable with header, footer and last footer."""
    table.add_hline()
    table.add_row(*columns)
    table.add_hline()
    table.end_table_header()
    table.add_hline()
    table.add_row((MultiColumn(len(columns), align=align, data=footer_text),))
    table.add_hline()
    table.end_table_footer()
    if end_footer_text:
        table.add_hline()
        table.add_row((MultiColumn(len(columns), align=align, data=end_footer_text),))
    table.add_hline()
    table.end_table_last_footer()
    return table


def add_row(table: LongTableType, row: Sequence[Any]) -> LongTableType:
    """Adds a row to a longtable and wraps each cell text in a `pylatex.NoEscape`."""
    r = []
    for cell in row:
        if isinstance(cell, Hyperlink):
            r.append(hyperlink(cell.url, cell.text))
        # TODO: add support for other types of cells
        else:
            r.append(NoEscape(cell))
    table.add_row(r)
    return table
