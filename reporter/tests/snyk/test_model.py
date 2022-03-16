# from typing import Any
from hypothesis import HealthCheck, given, settings, strategies as st
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
    assert scan.architecture in scan.platform  # NOTE: remove?


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


@pytest.mark.skip
def test_SnykVulnerability_validator_cvssScore() -> None:
    # TODO: need to mock SnykVulnerability objects with cvssScore None
    # and test that each one's score matches the upper threshold of that CVSS severity
    pass
