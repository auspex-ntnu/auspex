from pathlib import Path
from auspex_core.models.cve import SEVERITIES
from auspex_core.models.gcr import ImageTimeMode
from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from reporter.backends.aggregate import AggregateReport
from reporter.backends.snyk.model import VulnerabilityList, SnykContainerScan


def test_AggregateReport_from_file() -> None:
    scan = SnykContainerScan.parse_file(
        Path(__file__).parent / "../_static/vulhub_php_5.4.1_cgi.json"
    )
    ag = AggregateReport(reports=[scan])
    assert len(list(ag.vulnerabilities)) == len(scan.vulnerabilities)


@settings(max_examples=10)
@given(st.builds(AggregateReport, reports=st.lists(st.builds(SnykContainerScan))))
def test_fuzz_AggregateReport(ag: AggregateReport) -> None:
    N = 5
    most_severe = ag.most_severe_n(n=N)
    assert len(most_severe) <= N
    assert most_severe == sorted(most_severe, key=lambda v: v.cvssScore)

    most_severe_upg = ag.most_severe_n(n=N, upgradable=True)
    assert all(v.is_upgradable for v in most_severe_upg)
    assert len(most_severe_upg) <= N
    assert most_severe_upg == sorted(most_severe_upg, key=lambda v: v.cvssScore)

    assert ag.cvss_max >= ag.cvss_min
    if any(score != 0.0 for score in ag.cvss_scores()):
        assert ag.cvss_mean != 0.0

    # Check that these properties simply don't throw an exception
    # TODO: add deterministic testing of these properties
    for score_prop in [ag.cvss_median, ag.cvss_mean, ag.cvss_stdev]:
        v = score_prop
        assert v is not None

    # Test retrieving all vulnerabilities by severity
    props = {
        "low": ag.low,
        "medium": ag.medium,
        "high": ag.high,
        "critical": ag.critical,
    }
    for severity, vuln_prop in props.items():
        for vuln in vuln_prop:
            assert vuln.severity == severity

    # Test retrieving number of vulnerabilities by severity
    sevvulns = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for severity in sevvulns:
        for scan in ag.reports:
            for vuln in scan.vulnerabilities:
                try:
                    sevvulns[vuln.severity] += 1
                except:
                    pass
    assert ag.n_low == sevvulns["low"]
    assert ag.n_medium == sevvulns["medium"]
    assert ag.n_high == sevvulns["high"]
    assert ag.n_critical == sevvulns["critical"]

    # Test that correct number of scan IDs are retrieved
    assert len(ag.get_report_ids()) == len(list(ag.reports))

    # Test that AggregateReport.vulnerabilities retrieves all vulnerabilities
    # (or at least the correct number.)
    # TODO: Ensure contents are equal
    n = 0
    for report in ag.reports:
        n += len(list(report.vulnerabilities))
    assert n == len(list(ag.vulnerabilities))

    # Test capability as a generator
    for vuln in ag.vulnerabilities:
        assert vuln is not None

    # Test most severe vulnerability per scan
    most_severe_per_scan = ag.most_severe_per_scan()
    assert len(most_severe_per_scan) == len(ag.reports)
    assert all(scan_id in ag.get_report_ids() for scan_id in most_severe_per_scan)
    # TODO: ensure output of method is correct

    # Test most common vulnerability
    # TODO: Test expected content
    n = 5
    mc = ag.most_common_cve(n=n)
    assert len(mc) <= n

    # Test age, score, color retrieval
    asc = ag.get_vulns_age_score_color()
    assert len(asc) == len(list(ag.vulnerabilities))

    # Test timestamp (just invoke the method)
    ag.get_timestamp()
    # Test that parameters do nothing for this method
    assert ag.get_timestamp(image=False) == ag.get_timestamp()
    assert ag.get_timestamp(image=True) == ag.get_timestamp()
    assert (
        ag.get_timestamp(image=False, mode=ImageTimeMode.UPLOADED) == ag.get_timestamp()
    )
    assert ag.get_timestamp(mode=ImageTimeMode.UPLOADED) == ag.get_timestamp(
        mode=ImageTimeMode.CREATED
    )

    # Distribution by severity
    distrib = ag.get_distribution_by_severity()

    # Skip until we can be certain value of "severity" for vulnerabilities
    # conform to the CVE severity scale. Hypothesis will assign random values.
    #
    # total = sum(distrib.values())
    # assert total == len(list(ag.vulnerabilities))

    for severity, count in distrib.items():
        assert severity in SEVERITIES
        assert count <= len(list(ag.vulnerabilities))
        assert count >= 0

    # Test len of get_exploitable() does not exceed total len
    assert len(list(ag.get_exploitable())) <= len(list(ag.vulnerabilities))
