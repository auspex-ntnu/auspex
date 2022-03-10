import json
from collections import Counter
from datetime import datetime
from functools import cached_property
from os import PathLike
from typing import Any, List, Optional, Tuple

import numpy as np
from loguru import logger
from numpy.typing import NDArray
from pydantic import BaseModel, Field

from ..shared import (
    CVSS_DATE_BRACKETS,
    DEFAULT_CVSS_TIMETYPE,
    CVSSTimeType,
    DateDescription,
    UpgradabilityCounter,
)
from ...utils.matplotlib import get_cvss_color


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
    # TODO: find out which of these dates Snyk can ommit
    creationTime: Optional[datetime]
    modificationTime: Optional[datetime]
    publicationTime: Optional[datetime]
    disclosureTime: Optional[datetime]  # Can be omitted by Snyk
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
    nearestFixedInVersion: Optional[str]
    dockerFileInstruction: Optional[str]  # how to fix vuln
    dockerBaseImage: str

    def get_numpy_color(self) -> np.ndarray:
        return get_cvss_color(self.cvssScore)

    def get_age_score_color(
        self,
        timetype: CVSSTimeType = DEFAULT_CVSS_TIMETYPE,
    ) -> tuple[int, float, NDArray]:
        """
        Retrieves the vulnerability's age, score and numpy color (determined by its CVSS score).

        Used for displaying vulnerabilities in scatter plots.
        """
        attr = getattr(self, timetype.value)  # type: datetime
        age_days = 0
        if attr is not None:
            age_days = (datetime.now(attr.tzinfo) - attr).days
        return age_days, self.cvssScore, self.get_numpy_color()

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


# FIXME: vvvv SPAGHETTI BOLOGNESE vvvv
class VulnerabilityList(BaseModel):
    __root__: list[SnykVulnerability]

    def __iter__(self):
        return iter(self.__root__)

    def __getitem__(self, item) -> SnykVulnerability:
        return self.__root__[item]

    def get_vulns_by_date(
        self, time_type: CVSSTimeType
    ) -> dict[DateDescription, list[SnykVulnerability]]:
        """
        Retrieves all vulnerabilities grouped by time period.

        Parameters
        ----------
        time_type : `CVSSTimeType`
           Which CVE time to group by.
           See `CVSSTimeType` for possible options.

        Returns
        -------
        dict[DateDescription, list[SnykVulnerability]]
            A dict where each key denotes a specific time period and the
            value is a list of vulnerabilities that were
            created/modified/published/disclosed within that time period.
        """

        # Instantiate dict of lists
        vulns: dict[DateDescription, list[SnykVulnerability]] = {
            k: [] for k in CVSS_DATE_BRACKETS
        }
        attr = time_type.value
        for vuln in self:
            # Put guards around our unsafe metaprogramming
            assert hasattr(vuln, attr)
            try:
                t = getattr(vuln, attr)  # type: datetime
            except AttributeError:
                logger.exception(
                    f"Vulnerability {vuln.identifiers} has no attribute {attr}"
                )
                continue

            # Handle falsey time value
            if not t:
                logger.warning(
                    # TODO: fix wording. Find better word than "falsey"
                    f"Vulnerability {vuln.identifiers} has a falsey value for attribute {attr}: '{t}'"
                )
                continue

            # Put vulnerability into correct time bracket
            now = datetime.now(t.tzinfo)
            for bracket in CVSS_DATE_BRACKETS:
                if now - bracket.date > t:
                    vulns[bracket].append(vuln)
                    break
            else:
                vulns[bracket].append(vuln)  # default to last bracket

        return vulns

    def get_cvss_scores(self) -> NDArray:
        """Retrieves an NDArray of all vulnerability scores."""
        return np.array([vuln.cvssScore for vuln in self if vuln.cvssScore is not None])

    def _get_vulns_by_severity_level(self, level: str) -> list[SnykVulnerability]:
        return [v for v in self if v.severityWithCritical == level]

    def _get_vuln_upgradability_distribution(
        self, vulns: list[SnykVulnerability]
    ) -> UpgradabilityCounter:
        c = UpgradabilityCounter()
        for vuln in vulns:
            if vuln.isUpgradable:
                c.is_upgradable += 1
            else:
                c.not_upgradable += 1
        return c

    @property
    def low(self) -> list[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of low."""
        return self._get_vulns_by_severity_level("low")

    @property
    def medium(self) -> list[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of medium."""
        return self._get_vulns_by_severity_level("medium")

    @property
    def high(self) -> list[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of high."""
        return self._get_vulns_by_severity_level("high")

    @property
    def critical(self) -> list[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of critical."""
        return self._get_vulns_by_severity_level("critical")

    @property
    def low_by_upgradability(self) -> UpgradabilityCounter:
        """Distribution of upgradable to non-upgradable vulnerabilties
        with a rating of low."""
        return self._get_vuln_upgradability_distribution(self.low)

    @property
    def medium_by_upgradability(self) -> UpgradabilityCounter:
        """
        Distribution of upgradable to non-upgradable vulnerabilties
        with a rating of medium.
        """
        return self._get_vuln_upgradability_distribution(self.medium)

    @property
    def high_by_upgradability(self) -> UpgradabilityCounter:
        """
        Distribution of upgradable to non-upgradable vulnerabilties
        with a rating of high.
        """
        return self._get_vuln_upgradability_distribution(self.high)

    @property
    def critical_by_upgradability(self) -> UpgradabilityCounter:
        """
        Distribution of upgradable to non-upgradable vulnerabilties
        with a rating of critical.
        """
        return self._get_vuln_upgradability_distribution(self.critical)

    def get_distribution_by_upgradability(self) -> UpgradabilityCounter:
        """
        Retrieves distribution upgradable to non-upgradable vulnerabilities
        for all severity levels combined.

        TODO: should return dict instead of UpgradabilityCounter?
        """
        return self._get_vuln_upgradability_distribution(self.__root__)

    def get_distribution_by_severity(self) -> dict[str, int]:
        """Retrieves distribution of vulnerabiltiies grouped by their
        CVSS severity level.

        Returns
        -------
        `dict[str, int]`
            Dict where keys are CVSS severity levels and values are the
            number of vulnerabilities associated with each severity.

        Example return value
        --------------------
        ```py
        {'low': 88, 'medium': 659, 'high': 457, 'critical': 171}
        ```
        """
        return {
            "low": len(self.low),
            "medium": len(self.medium),
            "high": len(self.high),
            "critical": len(self.critical),
        }

    def get_distribution_by_severity_and_upgradability(
        self,
    ) -> dict[str, dict[str, int]]:
        """Retrieves the upgradability status of all vulnerabilities,
        grouped by their CVSS severity level.

        Returns
        -------
        `dict[str, dict[str, int]]`
            Dict where keys are CVSS severity levels and values are dicts denoting
            the upgradability status of all vulnerabilities of the given severity.

        Example return value
        --------------------
        ```py
        {
            'low': {'is_upgradable': 1, 'not_upgradable': 87},
            'medium': {'is_upgradable': 10, 'not_upgradable': 649}
            'high': {'is_upgradable': 18, 'not_upgradable': 439},
            'critical': {'is_upgradable': 7, 'not_upgradable': 164},
        }
        ```
        """
        return {
            "low": self.low_by_upgradability.dict(),
            "medium": self.medium_by_upgradability.dict(),
            "high": self.high_by_upgradability.dict(),
            "critical": self.critical_by_upgradability.dict(),
        }


# JSON: .
class SnykContainerScan(BaseModel):
    """Represents the output of `snyk container scan --json`"""

    vulnerabilities: VulnerabilityList
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
        keep_untouched = (cached_property,)

    def __hash__(self) -> int:
        """Returns ID of self. Required to add object to dict."""
        return id(self)

    def __repr__(self) -> str:
        return f"SnykVulnerabilityScan(path={self.path}, platform={self.platform})"

    @property
    def architecture(self) -> str:
        r = self.platform.split("/")
        return r[1] if len(r) > 1 else r[0]

    # TODO: use @computed_field when its PR is merged into pydantic
    @cached_property
    def mean_cvss_score(self) -> float:
        """Retrieves mean CVSS v3.0 score of all CVEs."""
        scores = self.vulnerabilities.get_cvss_scores()
        return scores.mean()

    @cached_property
    def median_cvss_score(self) -> float:
        scores = self.vulnerabilities.get_cvss_scores()
        try:
            return float(np.median(scores))
        except Exception as e:
            logger.error(f"Failed to get median CVSS score for {self}", e)
            return 0.0

    @cached_property
    def std_cvss_score(self) -> float:
        scores = self.vulnerabilities.get_cvss_scores()
        try:
            return float(np.std(scores))
        except Exception as e:
            logger.error(
                f"Failed to get standard deviation for CVSS scores for {self}", e
            )
            return 0.0

    def most_common_cve(self, max_n: Optional[int] = 5) -> List[Tuple[str, int]]:
        # TODO: most common per severity
        return self._get_cve_counter().most_common(n=max_n)

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
        `severityWithCritical` should be able to do that if we assume
        "severity" represents CVSS v2.0.
        """
        return self._get_severity_counter(v2=True).most_common()

    def _get_severity_counter(self, v2: bool = False) -> Counter[str]:
        c: Counter[str] = Counter()

        for vuln in self.vulnerabilities:
            severity = vuln.severity if v2 else vuln.severityWithCritical
            if severity is None:
                severity = "unknown"
            c[severity] += 1
        return c


def parse_file(fp: PathLike) -> SnykContainerScan:
    with open(fp, "r") as f:
        j = json.load(f)
        # TODO: handle JSON parsing error
    return SnykContainerScan.parse_obj(j)
