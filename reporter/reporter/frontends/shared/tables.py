"""
This module implements functions that are used to generate the data
used to display vulnerability tables in reports.
"""

from typing import Any, NamedTuple, Optional, Union

from auspex_core.models.cve import CVESeverity
from auspex_core.models.gcr import ImageInfo
from loguru import logger

from ...types.protocols import ScanType, VulnerabilityType
from ...backends.aggregate import AggregateReport

from .format import format_decimal
from .models import Hyperlink, TableData


def top_vulns_table(report: ScanType, upgradable: bool, maxrows: int) -> TableData:
    """Generates the data used to display the top vulnerabilities in a report.

    Parameters
    ----------
    report : `ScanType`
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
    aggregate = isinstance(report, AggregateReport)
    if aggregate:
        header.insert(0, "Image")

    rows = []
    most_severe = report.most_severe_n(maxrows, upgradable)
    for vuln in most_severe:
        row = [
            vuln.title,
            Hyperlink(text=vuln.get_id(), url=vuln.url),
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


def severity_vulns_table(
    report: ScanType, severity: CVESeverity, maxrows: Optional[int] = None
) -> TableData:
    """Generates the table data used to display the vulnererabilites of
    a specific severity in a report.

    Parameters
    ----------
    report : `ScanType`
        A report, either a single report or an aggregate report.
    severity : `CVESeverity`
        The severity of vulnerabilities to display.
    maxrows : `Optional[int]`
        Maximum number of rows to return, if None, all rows are returned.

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the vulnerabilities by severity.
    """
    header = [
        "Vulnerability",  # Name
        "CVSS ID",  # ID
        "CVSS Score",  # 0-10
        "Severity",
        "Upgradable",  # Yes/No
        "Year",
    ]

    # Add image column if we have an aggregated report
    aggregate = isinstance(report, AggregateReport)
    if aggregate:
        header.insert(0, "Image")

    # Get list of vulnerabilities
    # TODO: add method to get vulnerabilities by severity
    vulns = list(report.get_vulnerabilities_by_severity(severity))
    vulns.sort(key=lambda x: x.cvssScore, reverse=True)

    if maxrows is not None and len(vulns) > maxrows:
        vulns = vulns[:maxrows]

    rows = []
    for vuln in vulns:
        row = [
            vuln.title,
            Hyperlink(text=vuln.get_id(), url=vuln.url),
            format_decimal(vuln.cvssScore),  # TODO: format
            vuln.severity.title(),
            vuln.is_upgradable,
            vuln.get_year(),
        ]
        if aggregate:
            row.insert(0, "Image")
        rows.append(row)

    sev = severity.name.title()
    if maxrows:
        title = f"Top {len(rows)} {sev} Vulnerabilities"
    else:
        title = f"All {sev} Vulnerabilities"
    return TableData(title, header, rows)


def statistics_table(report: ScanType) -> TableData:
    """Generates the table data used to display the statistics of a report.

    Parameters
    ----------
    report : `ScanType`
        The report to display statistics for.

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the statistics.
    """
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
    # Always add Image as 1st column if we have an aggregated report
    if isinstance(report, AggregateReport):
        columns.insert(0, "Image")

    dist = report.get_distribution_by_severity()
    prio = ["critical", "high", "medium", "low"]
    # This is flimsy and should be refactored and moved to
    # a separate function.
    # We rely on the order defined in the list `prio` above.
    # TODO: use CVESeverity to define the order
    highest_severity = "low"  # default to low
    for p in prio:
        if dist.get(p):
            highest_severity = p
            break

    highest_severity = highest_severity.title()
    rows = []
    if isinstance(report, AggregateReport):
        for r in report.reports:
            row = _get_report_statistics_row(r)
            row.insert(0, r.image.image)
    elif isinstance(report, ScanType):
        rows.append(_get_report_statistics_row(report))
    else:
        raise ValueError("report must be a ScanType or AggregateReport")

    assert len(rows[0]) == len(columns)

    return TableData(
        title="Statistics",
        header=columns,
        rows=rows,
        caption="",
        description="Where: L = Low (0.1 - 3.9), M = Medium, (4.0 - 6.9), H = High (7.0 - 8.9), C = Critical (9.0 - 10.0)",
    )


def _get_report_statistics_row(report: ScanType) -> list[Any]:
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


def cvss_intervals() -> TableData:
    """Generates the table data used to display the CVSSv3 severity intervals.

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the CVSSv3 severity intervals.
    """
    columns = [
        "Low",
        "Medium",
        "High",
        "Critical",
    ]

    intervals = [
        [
            "0.1 - 3.9",
            "4.0 - 6.9",
            "7.0 - 8.9",
            "9.0 - 10.0",
        ]
    ]

    return TableData(
        title="CVSS Intervals",
        header=columns,
        rows=intervals,
        caption="",
        description="",
    )


def image_info(report: ScanType, digest_limit: int = 8) -> TableData:
    """Generates the table data used to display the info for an image.

    Parameters
    ----------
    image : `ImageInfo`
        The report to display image statistics for.
    digest_limit : `int`, optional
        Maximum displayed sha256 digest length, by default 8

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the statistics of an image.
    """
    columns = [
        "Image",
        "Created",
        "Tags",
        "Digest",
    ]

    rows = []  # type: list[list[str]]
    if isinstance(report, AggregateReport):
        for r in report.reports:
            rows.append(_get_image_info_row(r.image, digest_limit))
    else:
        rows.append(_get_image_info_row(report.image, digest_limit))

    return TableData(
        title="Image Statistics",
        header=columns,
        rows=rows,
        caption="",
        description="",
    )


def _get_image_info_row(image: ImageInfo, digest_limit: int = 8) -> list[str]:
    # Move this to ImageInfo.get_digest(maxlen=8)?
    digest = "-"
    if image.digest is not None:
        if ":" in image.digest:
            digest = image.digest.split(":")[1]
        if digest_limit and len(digest) > digest_limit:
            digest = digest[:digest_limit]  # + "..."

    # Move to ImageInfo.get_tags()?
    if image.tag:
        tags = ", ".join(image.tag)
    else:
        tags = "-"

    if not image.image:
        # This should NEVER happen, but just in case
        logger.warning(f"No image name for image with digest {image.digest}")

    return [
        image.image or "-",
        image.created.strftime("%Y-%m-%d %H:%M:%S"),
        tags,
        digest,
    ]


def exploitable_vulns(report: ScanType) -> TableData:
    """Generates the table data used to display the exploitable vulnerabilities.

    Parameters
    ----------
    report : `ScanType`
        The report to display exploitable vulnerabilities for.

    Returns
    -------
    `TableData`
        A named tuple containing the data used to display the exploitable vulnerabilities.
    """
    columns = [
        "Title",
        "CVSS ID",
        "CVSS Score",
        "Severity",
        "Upgradable",
    ]

    rows = []
    for vuln in report.get_exploitable():
        row = [
            vuln.title,
            Hyperlink(text=vuln.get_id(), url=vuln.url),
            format_decimal(vuln.cvssScore),  # TODO: format
            vuln.severity.title(),
            vuln.is_upgradable,
        ]
        rows.append(row)

    return TableData(
        title="Exploitable Vulnerabilities",
        header=columns,
        rows=rows,
        caption="",
        description="",
    )
