from auspex_core.models.cve import SEVERITIES, CVESeverity
from hypothesis import HealthCheck, given, settings, strategies as st
import pytest
from reporter.backends.aggregate import AggregateReport
from reporter.backends.snyk.model import SnykContainerScan
from reporter.frontends.shared.models import TableData
from reporter.frontends.shared.tables import (
    cvss_intervals,
    exploitable_vulns,
    image_info,
    severity_vulns_table,
    top_vulns_table,
)
from reporter.types.protocols import ScanType


# def _test_table_structure(report: ScanType, table: TableData, maxrows: int) -> None:


# Test this function with both aggregate report and single report
@pytest.mark.parametrize("upgradable", [True, False])
@given(
    st.one_of(
        st.builds(SnykContainerScan),
        st.builds(AggregateReport, reports=st.lists(st.builds(SnykContainerScan))),
    )
)
@settings(max_examples=10)  # Find a good number for this. Default is too slow.
def test_top_vulns_table(upgradable: bool, report: ScanType) -> None:
    # Test max row length
    MAXROWS = 10
    table = top_vulns_table(report, upgradable, maxrows=MAXROWS)
    if len(list(report.vulnerabilities)) <= MAXROWS:
        assert len(table.rows) <= MAXROWS

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
@given(
    st.one_of(
        st.builds(SnykContainerScan),
        st.builds(AggregateReport, reports=st.lists(st.builds(SnykContainerScan))),
    )
)
@settings(max_examples=10)  # Find a good number for this. Default is too slow.
def test_severity_vulns_table(severity: CVESeverity, report: ScanType) -> None:
    # Test max row length
    MAXROWS = 10
    table = severity_vulns_table(report, severity, maxrows=MAXROWS)
    if len(list(report.vulnerabilities)) <= MAXROWS:
        assert len(table.rows) <= MAXROWS

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


@given(
    st.one_of(
        st.builds(SnykContainerScan),
        st.builds(AggregateReport, reports=st.lists(st.builds(SnykContainerScan))),
    )
)
@settings(max_examples=10)  # Find a good number for this. Default is too slow.
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


@given(
    st.one_of(
        st.builds(SnykContainerScan),
        st.builds(AggregateReport, reports=st.lists(st.builds(SnykContainerScan))),
    )
)
@settings(max_examples=10)  # Find a good number for this. Default is too slow.
def test_exploitable_vulns(report: ScanType) -> None:
    table = exploitable_vulns(report)
    for row in table.rows:
        assert len(row) == len(table.header)
    # TODO: expand with more tests
