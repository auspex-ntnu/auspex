from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from reporter.backends.snyk.aggregate import AggregateScan


@settings(max_examples=10)
@given(st.builds(AggregateScan))
def test_fuzz_AggregateScan(ag: AggregateScan) -> None:
    N = 5
    most_severe = ag.most_severe(n=N)
    assert len(most_severe) <= N
    assert most_severe == sorted(most_severe, key=lambda v: v.cvssScore)

    assert ag.cvss_max >= ag.cvss_min
    if any(score != 0.0 for score in ag.cvss_scores):
        assert ag.cvss_mean != 0.0

    # Check that these properties simply don't throw an exception
    # TODO: add deterministic testing of these properties
    for prop in [ag.cvss_median, ag.cvss_mean, ag.cvss_stdev]:
        v = prop
        assert v is not None

    # Test retrieving all vulnerabilities by severity
    props = {
        "low": ag.low,
        "medium": ag.medium,
        "high": ag.high,
        "critical": ag.critical,
    }
    for severity, prop in props.items():
        for scan in prop:
            assert scan.severity == severity

    # Test retrieving number of vulnerabilities by severity
    sevvulns = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for severity in sevvulns:
        for scan in ag.scans:
            for vuln in scan.vulnerabilities:
                try:
                    sevvulns[vuln.severity] += 1
                except:
                    pass
    assert ag.n_low == sevvulns["low"]
    assert ag.n_medium == sevvulns["medium"]
    assert ag.n_high == sevvulns["high"]
    assert ag.n_critical == sevvulns["critical"]

    if len(ag.scans) > 0:
        with pytest.raises(ValueError):
            ag._get_vulnerabilities_by_severity("invalid_severity")

    # Test that correct number of scan IDs are retrieved
    assert len(ag.get_scan_ids()) == len(list(ag.scans))

    # Test that AggregateScan.vulnerabilities retrieves all vulnerabilities
    # (or at least the correct number.)
    # TODO: Ensure contents are equal
    n = 0
    for scan in ag.scans:
        n += len(scan.vulnerabilities)
    assert n == len(list(ag.vulnerabilities))

    # Test capability as a generator
    for vuln in ag.vulnerabilities:
        assert vuln is not None
