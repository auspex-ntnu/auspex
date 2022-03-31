# TODO: Rewrite methods that return lists as generators in order to optimize memory usage.

import json
import time
from collections import Counter
from datetime import datetime
from functools import _lru_cache_wrapper, cache, cached_property
from os import PathLike
from typing import Any, Iterator, Optional, Union

import numpy as np
from loguru import logger
from numpy.typing import NDArray
from pydantic import BaseModel, Field, root_validator, validator
from pydantic.fields import ModelField

from ...types.cvss import CVSS
from ...types.nptypes import MplRGBAColor
from ...utils.matplotlib import get_cvss_color
from ...cve import (
    CVSS_DATE_BRACKETS,
    DEFAULT_CVSS_TIMETYPE,
    CVSSTimeType,
    DateDescription,
    UpgradabilityCounter,
    CVESeverity,
)

from ...utils import npmath

# JSON: .vulnerabilities[n].identifiers
class Identifiers(BaseModel):
    ALTERNATIVE: list[str] = Field(default=[])
    CVE: list[str] = Field(default=[])
    CWE: list[str] = Field(default=[])


# JSON: .vulnerabilities[n].references[n]
class Reference(BaseModel):
    title: str
    url: str


# JSON: .vulnerabilities[n].semver
class Semver(BaseModel):
    vulnerable: list[str]


# JSON: .vulnerabilities[n]
class SnykVulnerability(BaseModel):
    title: str
    credit: list[str] = Field(..., exclude=True)
    packageName: str
    language: str
    packageManager: str
    description: str
    identifiers: Identifiers
    severity: str
    severityWithCritical: Optional[str]
    nvdSeverity: Optional[str]
    socialTrendAlert: bool
    cvssScore: float = Field(ge=0.0, le=10.0)  # CVSS v3 scores are between 0.0 and 10.0
    CVSSv3: Optional[str]
    patches: list[Any]  # we don't know what this can contain
    references: list[Reference] = Field(..., exclude=True)
    # TODO: find out which of these dates Snyk can ommit
    creationTime: Optional[datetime]
    modificationTime: Optional[datetime]
    publicationTime: Optional[datetime]
    disclosureTime: Optional[datetime]  # Can be omitted by Snyk
    id: str
    malicious: bool
    relativeImportance: Optional[
        str
    ]  # observed values: {'negligible', None, 'low', 'medium', 'high'}
    semver: Semver
    exploit: str
    from_: list[str] = Field(..., alias="from")
    upgradePath: list[Any]  # don't know
    isUpgradable: bool
    isPatchable: bool
    name: str
    version: str
    nearestFixedInVersion: Optional[str]
    dockerFileInstruction: Optional[str]  # how to fix vuln
    dockerBaseImage: Optional[str]

    @root_validator
    def use_highest_severity_value(cls, values: dict[str, Any]) -> dict[str, Any]:
        """
        Some vulnerabilities have multiple severity values.
        For some reason, Snyk sometimes omits nvdSeverity and/or severityWithCritical.
        Other times, the values of these fields are inconsistent.

        This validator sets the value of 'severity' to the highest severity value among the three.
        """
        severities: dict[str, int] = {
            "severity": CVESeverity.get(values.get("severity", "")),
            "severityWithCritical": CVESeverity.get(
                values.get("severityWithCritical", "")
            ),
            "nvdSeverity": CVESeverity.get(values.get("nvdSeverity", "")),
        }
        max_severity_key = max(severities, key=severities.get)  # type: ignore
        values["severity"] = values[max_severity_key]
        return values

    @validator("cvssScore", pre=True)
    def cvssScore_defaults_to_0(
        cls, v: Optional[float], values: dict[str, Any]
    ) -> float:
        """
        Some CVEs have not been assigned a score, and thus Snyk reports
        their score as `None`.

        Predefined default scores are used for these cases based on the
        vulnerability's severity level.
        """
        # TODO: use validator to set score to 0
        # then use root validator to set score based on severity?
        # Right now, we use the severity value _before_ the root validator for severity runs.

        # XXX: Document behavior and/or clarify whether we need to make up these numbers
        severity_scores = {"low": 3.9, "medium": 6.9, "high": 8.9, "critical": 10.0}
        if v is None:
            # TODO: decide whether we interpret None as number rounded up to vulnerability's
            # severity level or as 0.0
            return severity_scores.get(values.get("severity", ""), 0.0)
        return v

    def get_numpy_color(self) -> MplRGBAColor:
        return get_cvss_color(self.cvssScore)

    def get_age_score_color(
        self,
        timetype: CVSSTimeType = DEFAULT_CVSS_TIMETYPE,
    ) -> tuple[int, float, MplRGBAColor]:
        """
        Retrieves the vulnerability's age (in days), score and numpy color (determined by its CVSS score).

        Used for displaying vulnerabilities in scatter plots.
        """
        # NOTE: catch AttributeError?
        vuln_date = getattr(self, timetype.value)  # type: datetime
        age_days = 0
        if vuln_date is not None:
            age_days = (datetime.now(vuln_date.tzinfo) - vuln_date).days
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
    advice: list[RemediationAdvice] = Field(
        default=[]
    )  # TODO: why does default_factory=list break hypothesis test?


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
    ignore: list[Any]  # unknown contents
    patch: list[Any]


class OrgLicenseRule(BaseModel):
    licenseType: str
    severity: str
    instructions: str


class LicensesPolicy(BaseModel):
    severities: dict[Any, Any]  # unknown contents; can't type
    orgLicenseRules: dict[str, OrgLicenseRule]  # key: name of license


class VulnerabilityList(BaseModel):
    __root__: list[SnykVulnerability]

    class Config:
        keep_untouched = (_lru_cache_wrapper,)

    def __iter__(self):
        return iter(self.__root__)

    def __getitem__(self, item) -> SnykVulnerability:
        return self.__root__[item]

    def __repr__(self) -> str:
        return f"VulnerabilityList(len={len(self.__root__)})"

    def __len__(self) -> int:
        return len(self.__root__)

    def __hash__(self) -> int:
        return id(self)


# JSON: .
class SnykContainerScan(BaseModel):
    """Represents the output of `snyk container test --json`"""

    vulnerabilities: VulnerabilityList  # TODO: just use list[SnykVulnerability] instead?
    ok: bool
    dependencyCount: int
    org: str
    policy: str
    isPrivate: bool
    licensesPolicy: LicensesPolicy
    packageManager: str
    ignoreSettings: Any
    docker: SnykDocker
    summary: str
    filesystemPolicy: bool
    filtered: SnykFiltered
    uniqueCount: int
    projectName: str
    platform: str
    path: str
    id: str = ""  # Not snyk-native
    timestamp: datetime = Field(default_factory=datetime.now)  # Not snyk-native
    image: str = ""  # Not snyk-native

    class Config:
        extra = "allow"  # should we allow or disallow this?
        validate_assignment = True
        keep_untouched = (cached_property, _lru_cache_wrapper)

    @validator("timestamp", pre=True)
    def ensure_default_factory(
        cls, v: Optional[datetime], field: ModelField
    ) -> Optional[datetime]:
        """Hypothesis seems to pass `None` to this attribute even though
        it's not specified as Optional[datetime]. To make tests pass, we have to
        add this validator to ensure passing `None` to `"timestamp"` runs default factory."""
        if v is None and field.default_factory is not None:
            return field.default_factory()
        return v

    @validator("id", always=True)  # use Pre=True instead?
    def assign_default_id(cls, v: str, values: dict[str, Any]) -> str:
        """Fall back on autogenerating an ID if Google Cloud Storage
        does not provide us with an ID from its blob metadata.
        Should never happen, but we leave it here as a failsafe."""
        if v:
            return v
        id = f"{values['path']}{time.time()}"
        logger.debug(
            f"Creating autogenerated ID for scan with path {values['path']}: {id}"
        )
        return id

    @validator("image", always=True)
    def use_path_if_not_image(cls, v: str, values: dict[str, Any]) -> str:
        return v or values["path"]

    def __hash__(self) -> int:
        """Returns ID of self. Required to add object to dict."""
        return id(self)

    def __repr__(self) -> str:
        return f"SnykVulnerabilityScan(path={self.path}, platform={self.platform})"

    @property
    def architecture(self) -> str:
        # TODO: add docstring
        r = self.platform.split("/")
        return r[1] if len(r) > 1 else r[0]

    @property
    def cvss_min(self) -> float:
        """Lowest CVSS score of the identified vulnerabilities"""
        return min((vuln.cvssScore for vuln in self.vulnerabilities), default=0.0)

    @property
    def cvss_max(self) -> float:
        return max((vuln.cvssScore for vuln in self.vulnerabilities), default=0.0)

    # TODO: use @computed_field when its PR is merged into pydantic
    @property
    def cvss_mean(self) -> float:
        return npmath.mean(self.cvss_scores())

    @property
    def cvss_median(self) -> float:
        return npmath.median(self.cvss_scores())

    @property
    def cvss_stdev(self) -> float:
        return npmath.stdev(self.cvss_scores())

    @property
    def cvss(self) -> CVSS:
        return CVSS(
            mean=self.cvss_mean,
            median=self.cvss_median,
            stdev=self.cvss_stdev,
            min=self.cvss_min,
            max=self.cvss_max,
        )

    @property
    def most_severe(self) -> Optional[SnykVulnerability]:
        """The most severe vulnerability (if any)"""
        return max(
            self.vulnerabilities,
            default=None,
            # mypy doesn't understand that None takes presedence over key (?)
            # hence the guard against None here
            key=lambda v: v.cvssScore if v is not None else 0.0,
        )

    def most_severe_n(self, n: Optional[int] = 5) -> list[SnykVulnerability]:
        v = sorted(self.vulnerabilities, key=lambda v: v.cvssScore, reverse=True)
        if n and len(v) > n:
            return v[:n]
        return v

    @property
    def least_severe(self) -> Optional[SnykVulnerability]:
        """The least severe vulnerability (if any)"""
        return min(
            self.vulnerabilities,
            default=None,
            key=lambda v: v.cvssScore if v is not None else 0.0,
        )

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
    def n_low(self) -> int:
        """All vulnerabilities with a CVSS rating of low."""
        return len(self.low)

    @property
    def n_medium(self) -> int:
        """All vulnerabilities with a CVSS rating of medium."""
        return len(self.medium)

    @property
    def n_high(self) -> int:
        """All vulnerabilities with a CVSS rating of high."""
        return len(self.high)

    @property
    def n_critical(self) -> int:
        """All vulnerabilities with a CVSS rating of critical."""
        return len(self.critical)

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

    @property
    def all_by_upgradability(self) -> UpgradabilityCounter:
        """
        Distribution of upgradable to non-upgradable vulnerabilities
        for all severity levels combined.
        """
        return self._get_vuln_upgradability_distribution(self.vulnerabilities.__root__)

    # NOTE: remain a property or be a function named get_malicious?
    @property
    def malicious(self) -> list[SnykVulnerability]:
        return [v for v in self.vulnerabilities if v.malicious]

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
        attr = time_type.value  # type: str
        for vuln in self.vulnerabilities:
            # Put guards around our unsafe metaprogramming
            try:
                t = getattr(vuln, attr)  # type: datetime
            except AttributeError:
                logger.exception(
                    f"Vulnerability {vuln.identifiers} has no attribute {attr}"
                )
                continue

            # Handle falsey time value
            if not t:
                # TODO: find out what to do with these vulnerabilities
                logger.warning(
                    # TODO: fix wording. Find better word than "falsey"
                    f"Cannot sort vulnerability {vuln.identifiers}. "
                    f"Vulnerability has a falsey value for attribute {attr}: '{t}'."
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

    def get_vulns_age_score_color(
        self,
    ) -> list[tuple[int, float, MplRGBAColor]]:
        return [vuln.get_age_score_color() for vuln in self.vulnerabilities]

    @cache
    def cvss_scores(self, ignore_zero: bool = True) -> list[float]:
        """Retrieves an NDArray of all vulnerability scores."""
        # TODO: rewrite without list comp to avoid extra allocation
        if ignore_zero:
            return [
                vuln.cvssScore for vuln in self.vulnerabilities if vuln.cvssScore != 0.0
            ]

        else:
            return [vuln.cvssScore for vuln in self.vulnerabilities]
        # vulns = self.scores()
        # if ignore_zero:
        #     vulns = filter(lambda score: score != 0.0, vulns)
        # return np.fromiter(vulns)

    # def scores(self) -> Iterator[float]:
    #     for vuln in self.vulnerabilities:
    #         yield vuln.cvssScore

    def _get_vulns_by_severity_level(self, level: str) -> list[SnykVulnerability]:
        return [v for v in self.vulnerabilities if v.severity == level]

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

    def get_distribution_by_severity(self) -> dict[str, int]:
        """Retrieves distribution of vulnerabilities grouped by their
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
            "low": self.n_low,
            "medium": self.n_medium,
            "high": self.n_high,
            "critical": self.n_critical,
        }

    def get_distribution_by_severity_and_upgradability(
        self,
    ) -> dict[str, UpgradabilityCounter]:
        """Retrieves the upgradability status of all vulnerabilities,
        grouped by their CVSS severity level.

        Returns
        -------
        `dict[str, dict[str, int]]`
            Dict where keys are CVSS severity levels and values are dicts denoting
            the upgradability status of all vulnerabilities of the given severity.

        Example return value
        --------------------
        TODO: UPDATE THIS EXAMPLE
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
            "low": self.low_by_upgradability,
            "medium": self.medium_by_upgradability,
            "high": self.high_by_upgradability,
            "critical": self.critical_by_upgradability,
        }

    def most_common_cve(self, max_n: Optional[int] = 5) -> list[tuple[str, int]]:
        # TODO: most common per severity
        return self._get_cve_counter().most_common(n=max_n)

    # TODO: add def _get_vulnerabilities_with_cve(self) -> list[SnykVulnerability]

    def _get_cve_counter(self) -> Counter[str]:
        c: Counter[str] = Counter()
        for vuln in self.vulnerabilities:
            for cve in vuln.identifiers.CVE:
                c[cve] += 1
        return c

    def severity_v3(self) -> list[tuple[str, int]]:
        return self._get_severity_counter().most_common()

    def severity_v2(self) -> list[tuple[str, int]]:
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


def parse_file(fp: Union[str, PathLike[str]]) -> SnykContainerScan:
    with open(fp, "r") as f:
        j = json.load(f)
        # TODO: handle JSON parsing error
    return SnykContainerScan.parse_obj(j)
