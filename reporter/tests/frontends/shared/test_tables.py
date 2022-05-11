"""This module tests that table data is generated correctly.

While high coverage is good, the most important thing to test
is that the data is structured as expected. This means testing that
the number of rows is correct, headers match number of columns, etc.

Furthermore, we have to test for multiple scenarios:
- Single report
- Single report with 0 vulnerabilities
- Aggregate report
- Aggregate report with 0 reports
- Aggregate report where none of the reports have vulnerabilities
- + more
"""

from typing import Optional
from auspex_core.models.cve import SEVERITIES, CVESeverity
from hypothesis import HealthCheck, given, settings, strategies as st
import pytest
from reporter.backends.aggregate import AggregateReport
from reporter.backends.snyk.model import SnykContainerScan, SnykVulnerability
from reporter.frontends.shared.models import TableData
from reporter.frontends.shared.tables import (
    cvss_intervals,
    exploitable_vulns,
    image_info,
    severity_vulns_table,
    statistics_table,
    top_vulns_table,
)
from reporter.types.protocols import ScanType
from ...strategies import REPORT_STRATEGY


# def _test_table_structure(report: ScanType, table: TableData, maxrows: int) -> None:


# Test this function with both aggregate report and single report
@pytest.mark.parametrize("upgradable", [True, False])
@pytest.mark.parametrize(
    "maxrows",
    [0, None, 1, 10],
)
@given(REPORT_STRATEGY)
@settings(
    max_examples=10, suppress_health_check=[HealthCheck.too_slow]
)  # Find a good number for this. Default is too slow.
def test_top_vulns_table(
    upgradable: bool, maxrows: Optional[int], report: ScanType
) -> None:
    # Test max row length
    table = top_vulns_table(report, upgradable, maxrows=maxrows)
    if maxrows:
        if len(list(report.vulnerabilities)) <= maxrows:
            assert len(table.rows) <= maxrows

    # Test header vs rows
    headerlen = len(table.header)
    for row in table.rows:
        assert len(row) == headerlen

    # Test title
    if upgradable:
        assert "upgradable" in table.title.lower()

    # Test aggregate special case
    if isinstance(report, AggregateReport):
        assert "image" in [h.lower() for h in table.header]
        assert table.header[0].lower() == "image"


@pytest.mark.parametrize(
    "severity",
    [CVESeverity.LOW, CVESeverity.MEDIUM, CVESeverity.HIGH, CVESeverity.CRITICAL],
)
@pytest.mark.parametrize(
    "maxrows",
    [0, None, 1, 10],
)
@given(REPORT_STRATEGY)
@settings(
    max_examples=10, suppress_health_check=[HealthCheck.too_slow]
)  # Find a good number for this. Default is too slow.
def test_severity_vulns_table(
    severity: CVESeverity, maxrows: Optional[int], report: ScanType
) -> None:
    # Test max row length
    if isinstance(report, SnykContainerScan) and report.vulnerabilities:
        for vuln in report.vulnerabilities:
            vuln.severity = severity.name.lower()

    table = severity_vulns_table(report, severity, maxrows=maxrows)
    if maxrows:
        if len(list(report.vulnerabilities)) <= maxrows:
            assert len(table.rows) <= maxrows

    # Test header vs rows
    headerlen = len(table.header)
    for row in table.rows:
        assert len(row) == headerlen

    # Assert all vulnerabilities are of the correct severity
    for row in table.rows:
        assert severity.name.title() in row

    # Test title
    assert severity.name.lower() in table.title.lower()


def test_cvss_intervals() -> None:
    """Sanity testing only."""
    table = cvss_intervals()
    assert len(table.header) == len(table.rows[0])
    assert len(table.rows) == 1
    assert len(table.header) == len(SEVERITIES)
    for severity in table.header:
        assert severity.lower() in SEVERITIES


@given(REPORT_STRATEGY)
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_image_info(report: ScanType) -> None:
    table = image_info(report)

    # Test header vs rows length
    headerlen = len(table.header)
    for row in table.rows:
        assert len(row) == headerlen

    if isinstance(report, AggregateReport):
        assert len(table.rows) == len(report.reports)
    else:
        assert len(table.rows) == 1


@given(REPORT_STRATEGY)
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_exploitable_vulns(report: ScanType) -> None:
    table = exploitable_vulns(report)
    for row in table.rows:
        assert len(row) == len(table.header)
    # TODO: expand with more tests


@given(REPORT_STRATEGY)
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_statistics_table(report: ScanType) -> None:
    table = statistics_table(report)
    for row in table.rows:
        assert len(row) == len(table.header)
    if len(table.rows) == 0:
        # assert table.title == "No statistics available"
        pass  # implement this
    else:
        assert int(table.rows[0][-1]) == len(list(report.vulnerabilities))

    if isinstance(report, AggregateReport):
        assert len(table.rows) == len(report.reports)
    else:
        assert len(table.rows) == 1
    # TODO: add more tests to ensure the table data is correct
