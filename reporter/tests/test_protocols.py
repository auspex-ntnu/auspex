from reporter.types.protocols import (
    ScanType,
    ScanTypeAggregate,
    ScanTypeSingle,
    VulnerabilityType,
)
from reporter.backends.snyk.model import SnykContainerScan, SnykVulnerability
from reporter.backends.snyk.aggregate import AggregateScan

from hypothesis import strategies as st, given, settings, HealthCheck


@given(st.builds(SnykContainerScan))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_snykcontainerscan_protocol(scan: SnykContainerScan) -> None:
    takes_scantype(scan)
    assert isinstance(scan, ScanType)
    assert isinstance(scan, ScanTypeSingle)


@given(st.builds(AggregateScan))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_aggregatescan_protocol(scan: AggregateScan) -> None:
    takes_scantype(scan)
    assert isinstance(scan, ScanType)
    assert isinstance(scan, ScanTypeAggregate)


# Just so mypy can give intellisense warnings about missing attrs/methods
def takes_scantype(scan: ScanType) -> None:
    assert isinstance(scan, ScanType)


@given(st.builds(SnykVulnerability))
@settings(max_examples=1, suppress_health_check=[HealthCheck.too_slow])
def test_snykvulnerability_protocol(vuln: VulnerabilityType) -> None:
    takes_vulntype(vuln)
    assert isinstance(vuln, VulnerabilityType)


def takes_vulntype(scan: VulnerabilityType) -> None:
    assert isinstance(scan, VulnerabilityType)
