from reporter.types.protocols import ScanType
from reporter.backends.snyk.model import SnykContainerScan
from reporter.backends.snyk.aggregate import AggregateScan

from hypothesis import strategies as st, given, settings, HealthCheck


@given(st.builds(SnykContainerScan))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_snykcontainerscan_protocol(scan: SnykContainerScan) -> None:
    assert isinstance(scan, ScanType)


@given(st.builds(AggregateScan))
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_aggregatescan_protocol(scan: AggregateScan) -> None:
    assert isinstance(scan, ScanType)
