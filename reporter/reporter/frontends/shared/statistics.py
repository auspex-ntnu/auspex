from typing import Union, Any
from .models import TableData

from ...types.protocols import ScanTypeSingle, ScanTypeAggregate
from .format import format_decimal


def statistics_box(report: Union[ScanTypeSingle, ScanTypeAggregate]) -> TableData:
    columns = [
        "Median CVSS Score",
        "Mean CVSS Score",
        "Standard Deviation",
        "Max CVSS Score",
        "Highest Severity",
    ]
    if isinstance(report, ScanTypeAggregate):
        columns.insert(0, "Image")

    dist = report.get_distribution_by_severity()
    prio = ["critical", "high", "medium", "low"]
    # This is flimsy and should be refactored and moved to
    # a separate function.
    # We rely on the order defined in the list `prio` above.
    highest_severity = "low"  # default to low
    for p in prio:
        if dist.get(p):
            highest_severity = p
            break

    highest_severity = highest_severity.title()
    rows = []
    if isinstance(report, ScanTypeAggregate):
        for r in report.reports:
            row = _get_singlereport_statistics_row(r)
            row.insert(0, r.image.image)
    else:
        rows.append(_get_singlereport_statistics_row(report))

    return TableData(
        title="Statistics",
        header=columns,
        rows=rows,
    )


def _get_singlereport_statistics_row(report: ScanTypeSingle) -> list[Any]:

    dist = report.get_distribution_by_severity()
    prio = ["critical", "high", "medium", "low"]
    # This is flimsy and should be refactored and moved to
    # a separate function.
    # We rely on the order defined in the list `prio` above.
    highest_severity = "low"  # default to low
    for p in prio:
        if dist.get(p):
            highest_severity = p
            break

    highest_severity = highest_severity.title()
    row = [
        format_decimal(report.cvss.median),
        format_decimal(report.cvss.mean),
        format_decimal(report.cvss.stdev),
        format_decimal(report.cvss.max),
        highest_severity,
    ]
    return row
