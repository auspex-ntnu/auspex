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
