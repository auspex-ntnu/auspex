"""
This module implements functions that are used to generate the data
used to display vulnerability tables in reports.
"""

from typing import Any, NamedTuple, Union

from ...types.protocols import ScanTypeAggregate, ScanTypeSingle

from .format import format_decimal
from .models import TableData


def top_vulns_table(
    report: Union[ScanTypeSingle, ScanTypeAggregate], upgradable: bool, maxrows: int
) -> TableData:
    """Generates the data used to display the top vulnerabilities in a report.

    Parameters
    ----------
    report : `Union[ScanTypeSingle, ScanTypeAggregate]`
        A report, either a single report or an aggregate report.
    upgradable : `bool`
        Whether or not to only display upgradable vulnerabilities.
    maxrows : `int`
        Maximum number of rows to return.

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the top vulnerabilities.
    """
    header = [
        "Vulnerability",  # Name
        "CVSS ID",  # ID
        "CVSS Score",  # 0-10
        "Severity",
        "Upgradable",  # Yes/No
    ]

    # Add image column if we have an aggregated report
    aggregate = isinstance(report, ScanTypeAggregate)
    if aggregate:
        header.insert(0, "Image")

    rows = []
    most_severe = report.most_severe_n(maxrows, upgradable)
    for vuln in most_severe:
        row = [
            vuln.title,
            vuln.get_id(),
            format_decimal(vuln.cvssScore),  # TODO: format
            vuln.severity.title(),
            vuln.is_upgradable,
        ]
        if aggregate:
            # TODO: add image name
            # we currently don't return image name along with the vulnerability
            # Find a way to do this without breaking the current interface
            row.insert(0, "IMAGE GOES HERE")
        rows.append(row)
    if upgradable:
        title = f"Top {len(most_severe)} Most Critical Upgradable Vulnerabilities"
    else:
        title = f"Top {len(most_severe)} Most Critical Vulnerabilities"
    return TableData(title, header, rows)


def statistics_table(report: Union[ScanTypeSingle, ScanTypeAggregate]) -> TableData:
    columns = [
        "Median CVSS",
        "Mean CVSS",
        "CVSS Stdev",
        "Max CVSS",
        "L",
        "M",
        "H",
        "C",
        "# Vulns",
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

    assert len(rows[0]) == len(columns)

    return TableData(
        title="Statistics",
        header=columns,
        rows=rows,
    )


def _get_singlereport_statistics_row(report: ScanTypeSingle) -> list[Any]:
    dist = report.get_distribution_by_severity()
    row = [
        format_decimal(report.cvss.median),
        format_decimal(report.cvss.mean),
        format_decimal(report.cvss.stdev),
        format_decimal(report.cvss.max),
        dist["low"],
        dist["medium"],
        dist["high"],
        dist["critical"],
        dist["low"] + dist["medium"] + dist["high"] + dist["critical"],
    ]
    return row
