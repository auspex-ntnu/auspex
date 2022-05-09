# from typing import Any
from datetime import datetime
import math
from pathlib import Path
from typing import Any
from auspex_core.models.cve import CVESeverity

from hypothesis import HealthCheck, given, settings, strategies as st
from reporter.cve import CVETimeType, DateDescription, UpgradabilityCounter
from reporter.backends.snyk.model import (
    Identifiers,
    Semver,
    SnykContainerScan,
    VulnerabilityList,
    SnykVulnerability,
)
import pytest

from ..strategies import CLASS_STRATEGIES


def test_SnykContainerScan_from_file() -> None:
    scan = SnykContainerScan.parse_file(
        Path(__file__).parent / "../_static/vulhub_php_5.4.1_cgi.json"
    )
    assert scan is not None
    assert math.isclose(scan.cvss_mean, 6.535999999999999)
    assert math.isclose(scan.cvss_median, 6.5)  # probably don't need isclose here?
    assert math.isclose(scan.cvss_stdev, 1.8512989051916053)


# Fuzzing test with hypothesis
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
@given(CLASS_STRATEGIES[SnykContainerScan])
def test_fuzz_SnykContainerScan(scan: SnykContainerScan) -> None:
    # CVSS sanity tests
    assert scan.cvss_max >= scan.cvss_min
    if scan.cvss_max != 0.0:
        assert scan.cvss_mean != 0.0
        assert scan.cvss_stdev != 0.0
    assert scan.cvss_mean is not None
    assert scan.cvss_median is not None
    assert scan.cvss_stdev is not None
    assert scan.architecture in scan.platform  # NOTE: remove?

    if len(scan.vulnerabilities) > 0:
        methods = [scan.severity_v2, scan.severity_v3]
        for meth in methods:
            mc = meth()
            assert mc is not None
            assert isinstance(mc, list)

    # Test properties returning least and most severe vulnerabilities
    if len(scan.vulnerabilities) > 0:
        assert scan.most_severe is not None
        assert scan.least_severe is not None
        assert scan.most_severe.cvssScore >= scan.least_severe.cvssScore
    else:
        assert scan.most_severe is None
        assert scan.least_severe is None

    # Test properties that return vulnerabilities of a given severity
    sev_vulns = {
        CVESeverity.LOW.name.lower(): scan.low,
        CVESeverity.MEDIUM.name.lower(): scan.medium,
        CVESeverity.HIGH.name.lower(): scan.high,
        CVESeverity.CRITICAL.name.lower(): scan.critical,
    }
    for severity, vulns in sev_vulns.items():
        for vuln in vulns:  # type: SnykVulnerability
            assert vuln.severity == severity

    # Test properties that return UpgradabilityCounter
    for upg in [
        scan.low_by_upgradability,
        scan.medium_by_upgradability,
        scan.high_by_upgradability,
        scan.critical_by_upgradability,
    ]:
        assert upg.is_upgradable >= 0
        assert upg.not_upgradable >= 0
    upg = scan.all_by_upgradability
    assert upg.is_upgradable + upg.not_upgradable == len(scan.vulnerabilities)

    props = {
        "low": "scan.low_by_upgradability",
        "medium": "scan.medium_by_upgradability",
        "high": "scan.high_by_upgradability",
        "critical": "scan.critical_by_upgradability",
    }
    if len(scan.vulnerabilities) > 0:
        for severity, prop in props.items():
            scan.vulnerabilities[0].severity = severity
            scan.vulnerabilities[0].isUpgradable = True
            assert eval(prop).is_upgradable >= 1

    # Test distribution of vulnerabilities by severity
    severities = ["low", "medium", "high", "critical"]
    distrib = scan.get_distribution_by_severity()
    for sev in severities:
        assert sev in distrib
        assert isinstance(distrib[sev], int)
        assert distrib[sev] >= 0

    # Test distribution of vulnerabilities by severity and upgradability status
    distrib_upg = scan.get_distribution_by_severity_and_upgradability()
    for sev in severities:
        assert sev in distrib_upg
        assert isinstance(distrib_upg[sev], UpgradabilityCounter)
        assert distrib_upg[sev].is_upgradable >= 0
        assert distrib_upg[sev].not_upgradable >= 0

    # Test malicious (remove?)
    for vuln in scan.malicious:
        assert vuln.malicious

    # Vulnerability by date
    # TODO: test returned data
    # TODO:
    if len(scan.vulnerabilities) > 0:
        for t in CVETimeType:
            n = 0
            by_date = scan.get_vulns_by_date(t)
            for bracket, vulns in by_date.items():
                n += len(vulns)
                assert isinstance(bracket, DateDescription)
            assert n == len(
                [vuln for vuln in scan.vulnerabilities if getattr(vuln, t.value)]
            )

    if len(scan.vulnerabilities) > 0:
        scan.vulnerabilities[0].cvssScore = 0.0
        scores = scan.cvss_scores(ignore_zero=True)
        assert 0.0 not in scores
        scores = scan.cvss_scores(ignore_zero=False)
        assert 0.0 in scores

    # assert len(list(scan.scores())) == len(scan.vulnerabilities)  # __len__


# TODO: Create strategy for constructing SnykVulnerability objects


@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
@given(st.builds(VulnerabilityList))
def test_fuzz_VulnerabilityList(v: VulnerabilityList) -> None:
    # Test dunder methods
    assert iter(v)  # __iter__
    if len(v) > 0:  # __getitem__
        for i in range(len(v)):
            assert v[i] is not None
    assert repr(v) is not None  # __repr__


@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
@given(CLASS_STRATEGIES[SnykVulnerability])
def test_fuzz_SnykVulnerability(vuln: SnykVulnerability) -> None:
    assert vuln.get_numpy_color() is not None
    assert len(vuln.get_numpy_color()) == 4
    for color in vuln.get_numpy_color():
        assert 0 <= color <= 1

    assert all(x is not None for x in vuln.get_age_score_color())
    age, score, color = vuln.get_age_score_color()
    assert age is not None
    assert age <= datetime.now().replace(tzinfo=age.tzinfo)
    assert score is not None
    assert 0.0 <= score <= 10.0
    assert color is not None

    vuln.creationTime = datetime.now()
    vuln.disclosureTime = datetime.now()
    vuln.publicationTime = datetime.now()
    vuln.modificationTime = datetime.now()

    for val in CVETimeType:
        age, score, color = vuln.get_age_score_color(val)


def test_SnykVulnerability_validator_cvssScore(
    snykvulnerability_data: dict[str, Any]
) -> None:
    severities = {"low": 3.9, "medium": 6.9, "high": 8.9, "critical": 10.0}
    # Test that absence of cvssScore defaults to upper threshold of severity
    for severity, score in severities.items():
        d = dict(snykvulnerability_data)
        d["severity"] = severity
        d["severityWithCritical"] = severity
        d["nvdSeverity"] = severity
        d["cvssScore"] = None
        v = SnykVulnerability.parse_obj(d)
        assert math.isclose(v.cvssScore, score)

    # Test scenario where severity is an invalid value and cvssScore is None
    d = dict(snykvulnerability_data)
    d["severity"] = "unknown"
    d["severityWithCritical"] = "unknown"
    d["nvdSeverity"] = "unknown"
    d["cvssScore"] = None
    v = SnykVulnerability.parse_obj(d)
    assert v.cvssScore == 0.0


def test_SnykVulnerability_validator_severity(
    snykvulnerability_data: dict[str, Any],
    cve_levels: list[str],
) -> None:
    for level in cve_levels:
        d = dict(snykvulnerability_data)
        # Test severityWithCritical
        d["severity"] = "unknown"
        d["nvdSeverity"] = "low"
        d["severityWithCritical"] = level
        v = SnykVulnerability.parse_obj(d)
        assert v.severity == level
        # Test nvdSeverity
        d["nvdSeverity"] = level
        d["severityWithCritical"] = "low"
        v = SnykVulnerability.parse_obj(d)
        assert v.severity == level
