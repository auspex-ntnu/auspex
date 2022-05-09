from auspex_core.models.cve import CVESeverity
from auspex_core.models.gcr import ImageInfo
from hypothesis import strategies as st
from reporter.backends.aggregate import AggregateReport
from reporter.backends.snyk.model import SnykContainerScan, SnykVulnerability


# Snyk data structure strategies
_SEVERITY_SAMPLE = [
    CVESeverity.LOW.name.lower(),
    CVESeverity.MEDIUM.name.lower(),
    CVESeverity.HIGH.name.lower(),
    CVESeverity.CRITICAL.name.lower(),
]
# Vulnerabilities with only valid severities
_SNYKVULNERABILITY_VALID_SEVERITY = st.builds(
    SnykVulnerability,
    severity=st.sampled_from(_SEVERITY_SAMPLE),
    exploit=st.one_of(
        st.sampled_from(["Not Defined", "Functional", ""]),
        st.text(),
    ),
)
# Vulnerabilities with valid and invalid severities
_SNYKVULNERABILITY_MIXED_SEVERITY = st.builds(
    SnykVulnerability,
    severity=st.sampled_from(
        _SEVERITY_SAMPLE + [CVESeverity.UNDEFINED.name.lower(), "", " "],
    ),
)

_IMAGEINFO = st.builds(
    ImageInfo,
    digest=st.one_of(
        st.sampled_from(
            [
                "sha256:32b68b650a3eaacc620c872e62350eafe8c1afdeaa1afe313b75d11a3b6b7541",
                "sha256:c90e6f935ba93786d4e6e49406d3f22cad196b54c195c8218209a0f63af2e648",
                "c90e6f935ba93786d4e6e49406d3f22cad196b54c195c8218209a0f63af2e648",
            ],
        ),
        st.none(),
        st.text(),
    ),
    tag=st.one_of(
        st.lists(
            st.sampled_from(
                [
                    "latest",
                    "v1.0.0",
                    "v1.0.1",
                    "v1.0.2",
                    "test",
                    "test:latest",
                    "test:v1.0.0",
                    "test:v1.0.1",
                    "dev",
                    "dev:latest",
                    "",
                ],
            ),
            min_size=1,
        ),
        st.lists(st.text(), min_size=0),
    ),
)


def _snykcontainerscan_strategy(
    vulnerabilities: st.SearchStrategy[list[SnykVulnerability]],
) -> st.SearchStrategy[SnykContainerScan]:
    return st.builds(
        SnykContainerScan,
        vulnerabilities=vulnerabilities,
        image=_IMAGEINFO,
    )


# SnykContainerScan
_SNYKCONTAINERSCAN = _snykcontainerscan_strategy(
    vulnerabilities=st.lists(
        _SNYKVULNERABILITY_VALID_SEVERITY, min_size=10, max_size=20
    )
)
_SNYKCONTAINERSCAN_MINSIZE_0 = _snykcontainerscan_strategy(
    vulnerabilities=st.lists(_SNYKVULNERABILITY_VALID_SEVERITY, min_size=0)
)


# Aggregate reort strategy
_AGGREGATEREPORT = st.builds(
    AggregateReport, reports=st.lists(_SNYKCONTAINERSCAN, min_size=1)
)
_AGGREGATEREPORT_MINSIZE_0 = st.builds(
    AggregateReport, reports=st.lists(_SNYKCONTAINERSCAN, min_size=0)
)

# Strategy that generates a ScanType object using various strategies
REPORT_STRATEGY = st.one_of(
    _SNYKCONTAINERSCAN,
    _SNYKCONTAINERSCAN_MINSIZE_0,
    _AGGREGATEREPORT,
    _AGGREGATEREPORT_MINSIZE_0,
)

# Strategies that can be used to test specific classes
CLASS_STRATEGIES = {
    SnykContainerScan: _SNYKCONTAINERSCAN,
    AggregateReport: _AGGREGATEREPORT,
    SnykVulnerability: _SNYKVULNERABILITY_VALID_SEVERITY,
}
