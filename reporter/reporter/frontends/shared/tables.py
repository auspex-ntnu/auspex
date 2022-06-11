"""
This module implements functions that are used to generate the data
used to display vulnerability tables in reports.
"""

from typing import Any, Optional, cast

from auspex_core.docker.models import ImageInfo
from auspex_core.models.cve import CVESeverity
from loguru import logger

from ...backends.aggregate import AggregateReport
from ...types.protocols import ScanType
from .format import format_decimal
from .models import Hyperlink, TableData


def top_vulns_table(
    report: ScanType, upgradable: bool, maxrows: Optional[int]
) -> TableData:
    """Generates the data used to display the top vulnerabilities in a report.

    Parameters
    ----------
    report : `ScanType`
        A report, either a single report or an aggregate report.
    upgradable : `bool`
        Whether or not to only display upgradable vulnerabilities.
    maxrows : `Optional[int]`
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

    is_aggregate = isinstance(report, AggregateReport)

    # Add image column if we have an aggregated report
    if is_aggregate:
        header.insert(0, "Image")

    # HACK: this is a workaround for the fact that ScanType.most_severe_n
    # does not provide us with any information about the image the vulnerability
    # is associated with.
    #
    # This means that running AggregateReport.most_severe_n gives us a list
    # of vulnerabilities without including which image they are associated with.
    #
    # We therefore simply iterate through all reports and get the top N vulnerabilties
    # for each one. This is quite clunky, as it would have been better to use the
    # same interface for both ScanType and AggregateReport.
    #
    # However, it means that we can make sure we display at least N vulnerabilties
    # from each image, and that we don't omit any image completely because it didn't
    # make the `maxrows` cutoff, and that we also are able to include the image the
    # vulnerability is associated with.

    rows = []
    reports = []
    if isinstance(report, AggregateReport):
        # We have to run isinstance here, lest mypy freaks out
        reports = report.reports
    else:
        reports = [report]

    # Get list of vulnerabilities per image
    for r in reports:
        most_severe = r.most_severe_n(maxrows, upgradable)
        for vuln in most_severe:
            row = [
                vuln.title,
                Hyperlink(text=vuln.get_id(), url=vuln.url),
                format_decimal(vuln.cvssScore),  # TODO: format
                vuln.severity.title(),
                vuln.is_upgradable,
            ]
            if is_aggregate:
                row.insert(0, r.image.image_name)
            rows.append(row)

    up = " Upgradable " if upgradable else " "
    ag = " by Image" if is_aggregate else ""
    title = f"Most Critical{up}Vulnerabilities{ag}"
    description = (
        "Lists the found vulnerabilities with highest CVSS scores. "
        "The CVSS ID is a hyperlink to official documentation for that vulnerability. "
        "'Upgradeable' denotes whether the found vulnerability has a known fix ie. a new version of a package or library. "
    )
    if upgradable:
        description += "Only vulnerabilities that are upgradable are listed."

    return TableData(title, header, rows, description=description)


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
    # TODO: consolidate this method with `top_vulns_table``
    #       they basically do the same thing
    rows = []
    reports = []
    if isinstance(report, AggregateReport):
        reports = report.reports
    else:
        reports = [report]

    for r in reports:
        vulns = list(r.get_vulnerabilities_by_severity(severity))
        vulns.sort(key=lambda x: x.cvssScore, reverse=True)

        if maxrows is not None and len(vulns) > maxrows:
            vulns = vulns[:maxrows]

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
                row.insert(0, r.image.image_name)
            rows.append(row)

    sev = severity.name.title()
    if maxrows:
        title = f"Top {len(rows)} {sev} Vulnerabilities"
        vuln_scope = f"the top {len(rows)}"
    else:
        title = f"All {sev} Vulnerabilities"
        vuln_scope = "all"

    description = (
        f"Lists {vuln_scope} discovered {severity.name.lower()} vulnerabilities. "
        "'Upgradeable' denotes whether the found vulnerability has a known fix ie. a new version of a package or library. "
        "Year represents the publication year of the vulnerability."
    )
    return TableData(title, header, rows, description=description)


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

    # FIXME: we don't seem to use this value?
    highest_severity = highest_severity.title()

    rows = []
    if isinstance(report, AggregateReport):
        for r in report.reports:
            row = _get_report_statistics_row(r)
            row.insert(0, r.image.image_name)
            rows.append(row)
    else:
        rows.append(_get_report_statistics_row(report))

    return TableData(
        title="Statistics",
        header=columns,
        rows=rows,
        caption="",
        description=(
            "The statistics is based on the scanned image(s) and denotes the Median, Mean and Standard deviation (Stdev) score of all vulnerabilities found. "
            "Additionally it showcases the single highest score of a vulnerability for this scan. 'L', 'M', 'H' and 'C' denote the severity categories, with the corresponding number of vulnerabilities for each category. "
            "'#Vulns' denotes the total number of vulnerabilities found. "
            "\n\nWhere: L = Low (0.1 - 3.9), M = Medium, (4.0 - 6.9), H = High (7.0 - 8.9), C = Critical (9.0 - 10.0)"
        ),
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
        title="CVSSv3 Scoring System",
        header=columns,
        rows=intervals,
        caption="CVSSv3 Severity Intervals",
        description=(
            "The following intervals are used to define the severity of a vulnerability. "
            "Scoring interval is based on the CVSSv3 scoring system, "
            "rating vulnerabilities from 0.0 to 10.0 and ranking them by severity, "
            "'Low'  to 'Critical' according to their score."
        ),
    )


def image_info(report: ScanType, digest_limit: Optional[int] = 8) -> TableData:
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

    if isinstance(report, AggregateReport):
        title = "Images in This Report"
    else:
        title = "Image Information"
    return TableData(
        title=title,
        header=columns,
        rows=rows,
        caption="",
        description="",
    )


def _get_image_info_row(image: ImageInfo, digest_limit: Optional[int]) -> list[str]:
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
        image.image_name or "-",
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
    td = TableData(
        title="Exploitable Vulnerabilities",
    )

    td.header = [
        "Title",
        "CVSS ID",
        "CVSS Score",
        "Severity",
        "Upgradable",
    ]

    for vuln in report.get_exploitable():
        row = [
            vuln.title,
            Hyperlink(text=vuln.get_id(), url=vuln.url),
            format_decimal(vuln.cvssScore),  # TODO: format
            vuln.severity.title(),
            vuln.is_upgradable,
        ]
        td.rows.append(row)

    if not td.rows:
        td.description = "No exploitable vulnerabilities found."
    else:
        td.description = (
            "The following vulnerabilities are exploitable. "
            "An exploitable vulnerability has a known working exploit that can be abused."
        )
    return td
