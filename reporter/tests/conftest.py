import os


# TODO fix this
os.environ.setdefault(
    "GOOGLE_APPLICATION_CREDENTIALS",
    "/Volumes/GoogleDrive/My Drive/Skole/2022V/Bachelor/repo/.keys/reporter_local.json",
)
os.environ.setdefault("LOGS_COLLECTION_NAME", "auspex-logs")
os.environ.setdefault("SCANS_BUCKET_NAME", "auspex-scans")
os.environ.setdefault("GCP_PROJECT", "ntnu-student-project")
os.environ.setdefault("REPORTS_COLLECTION_NAME", "auspex-reports")
os.environ.setdefault("SCANS_COLLECTION_NAME", "auspex-scans")
os.environ.setdefault("PARSED_COLLECTION_NAME", "auspex-parsed")
os.environ.setdefault("AGGREGATE_COLLECTION_NAME", "auspex-aggregate")


from typing import Any

from hypothesis import strategies as st
import pytest

from reporter.backends.snyk.model import Identifiers, Semver


# Hypothesis strategies:

# Variables annotated with Any will be assigned text
st.register_type_strategy(Any, st.text())  # type: ignore


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="function")
def snykvulnerability_data() -> dict[str, Any]:
    d = dict(
        title="Some Vulnerability",
        credit=[],
        language="linux",
        packageName="Some Package",
        packageManager="pacman",
        description="Description",
        identifiers=Identifiers(
            ALTERNATIVE=[],
            CVE=["CVE_1", "CVE_2"],
            CWE=["CWE_1", "CWE_2"],
        ),
        severityWithCritical="critical",
        nvdSeverity="critical",
        severity="critical",
        socialTrendAlert=False,
        cvssScore=10.0,
        CVSSv3="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        patches=[],
        references=[],
        creationTime=None,
        modificationTime=None,
        publicationTime=None,
        disclosureTime=None,
        id="SNYK-ARCH-BTW",
        malicious=False,
        relativeImportance=None,
        semver=Semver(vulnerable=["1.2.3"]),
        exploit="Out-of-bounds read",
        upgradePath=[],
        isUpgradable=True,
        isPatchable=False,
        name="archbtw",
        version="1.2.3",
        nearestFixedInVersion="1.2.4",
        dockerFileInstruction="apt-get install -y fix_my_software",
        dockerBaseImage="archlinux:btw",
    )
    # Set value for reserved keyword using string key
    d["from"] = [
        "docker-image|vulhub/php@5.4.1-cgi",
        "init-system-helpers/init@1.22",
        "systemd/systemd-sysv@215-17+deb8u7",
        "systemd@215-17+deb8u7",
        "systemd/udev@215-17+deb8u7",
        "systemd/libudev1@215-17+deb8u7",
    ]
    # For some reason Pydantic won't accept SnykVulnerability(..., from_=[...],)
    return d


@pytest.fixture(scope="session")
def cve_levels() -> list[str]:
    return ["low", "medium", "high", "critical"]
