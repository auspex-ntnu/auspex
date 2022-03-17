# from typing import Any
from datetime import datetime

from hypothesis import HealthCheck, given, settings, strategies as st
from reporter.backends.shared import CVSSTimeType
from reporter.backends.snyk.model import (
    SnykContainerScan,
    VulnerabilityList,
    SnykVulnerability,
)
import pytest


# st.register_type_strategy(Any, st.text())  # type: ignore


# Fuzzing test with hypothesis
@settings(max_examples=1)
@given(st.builds(SnykContainerScan))
def test_fuzz_SnykContainerScan(scan: SnykContainerScan) -> None:
    # CVSS sanity checks
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


# TODO: Create strategy for constructing SnykVulnerability objects

# Fuzzing test with hypothesis
@settings(max_examples=5, suppress_health_check=[HealthCheck.too_slow])
@given(st.builds(VulnerabilityList))
def test_fuzz_VulnerabilityList(v: VulnerabilityList) -> None:
    # Test dunder methods
    assert len(list(v.scores())) == len(v)  # __len__
    assert iter(v)  # __iter__
    if len(v) > 0:  # __getitem__
        for i in range(len(v)):
            assert v[i] is not None
    assert repr(v) is not None  # __repr__

    # Test properties returning least and most severe vulnerabilities
    if len(v) > 0:
        assert v.most_severe is not None
        assert v.least_severe is not None
        assert v.most_severe.cvssScore >= v.least_severe.cvssScore
    else:
        assert v.most_severe is None
        assert v.least_severe is None

    # Test properties that return vulnerabilities of a given severity
    # TODO: custom strategy for `severity` attribute so we know these lists are populated
    levels = [v.low, v.medium, v.high, v.critical]
    for level in levels:
        for vuln in level:  # type: SnykVulnerability
            assert vuln.severity == level

    # Test properties that return UpgradabilityCounter
    for upg in [
        v.low_by_upgradability,
        v.medium_by_upgradability,
        v.high_by_upgradability,
        v.critical_by_upgradability,
    ]:
        assert upg.is_upgradable >= 0
        assert upg.not_upgradable >= 0
    upg = v.all_by_upgradability
    assert upg.is_upgradable + upg.not_upgradable == len(v)

    props = {
        "low": "v.low_by_upgradability",
        "medium": "v.medium_by_upgradability",
        "high": "v.high_by_upgradability",
        "critical": "v.critical_by_upgradability",
    }
    if len(v) > 0:
        for severity, prop in props.items():
            v[0].severity = severity
            v[0].isUpgradable = True
            assert eval(prop).is_upgradable >= 1

    # Test distribution of vulnerabilities by severity
    severities = ["low", "medium", "high", "critical"]
    distrib = v.get_distribution_by_severity()
    for sev in severities:
        assert sev in distrib
        assert isinstance(distrib[sev], int)
        assert distrib[sev] >= 0

    # Test distribution of vulnerabilities by severity and upgradability status
    distrib_upg = v.get_distribution_by_severity_and_upgradability()
    for sev in severities:
        assert sev in distrib_upg
        assert isinstance(distrib_upg[sev], UpgradabilityCounter)
        assert distrib_upg[sev].is_upgradable >= 0
        assert distrib_upg[sev].not_upgradable >= 0

    # Test malicious (remove?)
    for vuln in v.malicious:
        assert vuln.malicious

    # Vulnerability by date
    # TODO: test returned data
    # TODO:
    if len(v) > 0:
        for t in CVSSTimeType:
            n = 0
            by_date = v.get_vulns_by_date(t)
            for bracket, vulns in by_date.items():
                n += len(vulns)
                assert isinstance(bracket, DateDescription)
            assert n == len([vuln for vuln in v if getattr(vuln, t.value)])

    if len(v) > 0:
        v[0].cvssScore = 0.0
        scores = v.get_cvss_scores(ignore_zero=True)
        assert 0.0 not in scores
        scores = v.get_cvss_scores(ignore_zero=False)
        assert 0.0 in scores


@settings(max_examples=5, suppress_health_check=[HealthCheck.too_slow])
@given(st.builds(SnykVulnerability))
def test_fuzz_SnykVulnerability(vuln: SnykVulnerability) -> None:
    assert vuln.get_numpy_color() is not None
    assert len(vuln.get_numpy_color()) == 4
    for color in vuln.get_numpy_color():
        assert 0 <= color <= 1

    assert all(x is not None for x in vuln.get_age_score_color())
    age, score, color = vuln.get_age_score_color()
    assert age is not None
    assert age >= 0
    assert score is not None
    assert 0.0 <= score <= 10.0
    assert color is not None

    vuln.creationTime = datetime.now()
    vuln.disclosureTime = datetime.now()
    vuln.publicationTime = datetime.now()
    vuln.modificationTime = datetime.now()

    for val in CVSSTimeType:
        age, score, color = vuln.get_age_score_color(val)


@pytest.mark.skip
def test_SnykVulnerability_validator_cvssScore() -> None:
    # TODO: need to mock SnykVulnerability objects with cvssScore None
    # and test that each one's score matches the upper threshold of that CVSS severity
    pass
