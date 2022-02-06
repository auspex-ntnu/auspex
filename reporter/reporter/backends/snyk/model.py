from datetime import datetime
from collections import Counter
from functools import cache
import json
from os import PathLike
from typing import Any, List, Optional, Tuple
from pydantic import BaseModel, Field

# JSON: .vulnerabilities[n].identifiers
class Identifiers(BaseModel):
    ALTERNATIVE: List[str]
    CVE: List[str]
    CWE: List[str]


# JSON: .vulnerabilities[n].references[n]
class Reference(BaseModel):
    title: str
    url: str


# JSON: .vulnerabilities[n].semver
class Semver(BaseModel):
    vulnerable: List[str]


# JSON: .vulnerabilities[n]
class SnykVulnerability(BaseModel):
    title: str
    credit: List[str]
    packageName: str
    language: str
    packageManager: str
    description: str
    identifiers: Identifiers
    severity: str
    severityWithCritical: str
    socialTrendAlert: bool
    cvssScore: Optional[float]
    CVSSv3: Optional[str]
    patches: List[Any]  # we don't know what this can contain
    references: List[Reference]
    creationTime: datetime
    modificationTime: datetime
    publicationTime: datetime
    disclosureTime: datetime
    id: str
    malicious: bool
    nvdSeverity: str
    relativeImportance: Any  # we don't know
    semver: Semver
    exploit: str
    from_: List[str] = Field(..., alias="from")
    upgradePath: List[Any]  # don't know
    isUpgradable: bool
    isPatchable: bool
    name: str
    version: str
    # dockerFileInstruction: str
    dockerFileInstruction: Optional[str]
    dockerBaseImage: str

    # TODO: determine if vulnerability is related to Docker


# JSON: .docker.baseImageRemediation[n]
class RemediationAdvice(BaseModel):
    message: str
    bold: Optional[bool] = False
    color: Optional[str] = None


# JSON: .docker.baseImageRemediation
class BaseImageRemediation(BaseModel):
    code: str
    advice: List[RemediationAdvice] = Field(default_factory=list)


# JSON: .docker
class SnykDocker(BaseModel):
    baseImage: str
    baseImageRemediation: BaseImageRemediation


# JSON: .filtered.ignore[n]
class FilteredIgnore(BaseModel):
    pass


# JSON: .filtered.patch[n]
class FilteredPatch(BaseModel):
    pass


# JSON: .filtered
class SnykFiltered(BaseModel):
    ignore: List[FilteredIgnore]
    patch: List[FilteredPatch]


# JSON: .
class SnykContainerScan(BaseModel):
    """Represents the output of `snyk container scan --json`"""

    vulnerabilities: List[SnykVulnerability]
    ok: bool
    dependencyCount: int
    org: str
    policy: str
    isPrivate: bool
    licensesPolicy: dict
    packageManager: str
    ignoreSettings: Any
    docker: SnykDocker
    summary: str
    filesystemPolicy: bool
    filtered: dict  # TODO: use SnykFiltered
    uniqueCount: int
    projectName: str
    platform: str
    path: str

    class Config:
        extra = "allow"  # should we allow or disallow this?
        validate_assignment = True

    def mean_cvss_score(self) -> float:
        """Retrieves mean CVSS v3.0 score of all CVEs."""
        scores = [
            vuln.cvssScore
            for vuln in self.vulnerabilities
            if vuln.cvssScore is not None
        ]
        return sum(scores) / len(scores) if len(scores) > 0 else 0

    def __hash__(self) -> int:
        """Returns ID of self. Required to add object to dict."""
        return id(self)

    @property
    def architecture(self) -> str:
        r = self.platform.split("/")
        return r[1] if len(r) > 1 else r[0]

    def most_common_cve(self, max_n: Optional[int] = 5) -> List[Tuple[str, int]]:
        return self._get_cve_counter().most_common(n=max_n)

    @cache
    def _get_cve_counter(self) -> Counter[str]:
        c: Counter[str] = Counter()
        for vuln in self.vulnerabilities:
            for cve in vuln.identifiers.CVE:
                c[cve] += 1
        return c

    def severity_v3(self) -> list[tuple[str, int]]:
        return self._get_severity_counter().most_common()

    def severity_v2(self) -> List[Tuple[str, int]]:
        """
        WARNING: does not work as intended.
        `severity` can still include `"critical"` even though only
        `severityWithCritical` should be able to do that.
        """
        return self._get_severity_counter(v2=True).most_common()

    def _get_severity_counter(self, v2: bool = False) -> Counter[str]:
        c: Counter[str] = Counter()

        # sanity check before we do getattr (disabled in production with -O)
        assert hasattr(self, "severity")
        assert hasattr(self, "severityWithCritical")

        attr = "severity" if v2 else "severityWithCritical"
        for vuln in self.vulnerabilities:
            severity = getattr(vuln, attr)  # type: Optional[str]
            if severity is None:
                severity = "unknown"
            c[severity] += 1
        return c


def parse_file(fp: PathLike) -> SnykContainerScan:
    with open(fp, "r") as f:
        j = json.load(f)
        # TODO: handle JSON parsing error
    return SnykContainerScan.parse_obj(j)
