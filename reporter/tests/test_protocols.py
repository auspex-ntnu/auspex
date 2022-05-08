from reporter.types.protocols import (
    ScanType,
    VulnerabilityType,
)
from reporter.backends.snyk.model import SnykContainerScan, SnykVulnerability
from reporter.backends.aggregate import AggregateReport

from hypothesis import strategies as st, given, settings, HealthCheck


@given(st.builds(SnykContainerScan))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_snykcontainerscan_protocol(scan: SnykContainerScan) -> None:
    takes_scantype(scan)
    assert isinstance(scan, ScanType)
    assert isinstance(scan, ScanType)


@given(st.builds(AggregateReport, reports=st.lists(st.builds(SnykContainerScan))))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_aggregatereport_protocol(report: AggregateReport) -> None:
    ag = AggregateReport(reports=[])
    takes_scantype(report)
    assert isinstance(report, ScanType)


# Just so mypy can give intellisense warnings about missing attrs/methods
def takes_scantype(scan: ScanType) -> None:
    assert isinstance(scan, ScanType)


@given(st.builds(SnykVulnerability))
@settings(max_examples=5, suppress_health_check=[HealthCheck.too_slow])
def test_snykvulnerability_protocol(vuln: VulnerabilityType) -> None:
    takes_vulntype(vuln)
    assert isinstance(vuln, VulnerabilityType)


def takes_vulntype(scan: VulnerabilityType) -> None:
    assert isinstance(scan, VulnerabilityType)
