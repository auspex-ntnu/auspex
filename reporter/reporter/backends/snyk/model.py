# TODO: Rewrite methods that return lists as generators in order to optimize memory usage.

import json
import time
from collections import Counter
from datetime import datetime, timezone
from functools import _lru_cache_wrapper, cache, cached_property
from os import PathLike
from typing import Any, Iterable, Iterator, Optional, Sequence, Union
from auspex_core.models.gcr import ImageInfo, ImageTimeMode

import numpy as np
from loguru import logger
from numpy.typing import NDArray
from pydantic import BaseModel, Field, root_validator, validator
from pydantic.fields import ModelField
from more_itertools import ilen
from auspex_core.models.cve import CVETimeType, CVESeverity, CVSS

from ...types.nptypes import MplRGBAColor
from ...types.protocols import VulnerabilityType
from ...utils.matplotlib import get_cvss_color
from ...cve import (
    CVSS_DATE_BRACKETS,
    DEFAULT_CVE_TIMETYPE,
    DateDescription,
    UpgradabilityCounter,
)
from ...utils import npmath
from ...frontends.shared.models import VulnAgePoint

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
    upgradePath: list[Any]  # don't know (seems to be tuple[bool, str])
    isUpgradable: bool
    isPatchable: bool
    name: str
    version: str
    nearestFixedInVersion: Optional[str]
    dockerfileInstruction: Optional[str]  # how to fix vuln
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

    @property
    def is_upgradable(self) -> bool:
        return self.isUpgradable

    @property
    def exploitable(self) -> bool:
        return True if self.exploit and self.exploit != "Not Defined" else False

    def get_id(self) -> str:
        # TODO: Add support for multiple prios
        # This is extremely hacky!
        prios = ["CVE", "CWE", "ALTERNATIVE"]
        for prio in prios:
            if not hasattr(self.identifiers, prio):
                continue
            ids = getattr(self.identifiers, prio)
            if len(ids) > 0:
                return ids[0]
        return self.id  # fall back on Snyk ID

    @property
    def url(self) -> str:
        """Attempts to return the cve.mitre.org URL for the vulnerability.
        Falls back on the Snyk URL if no URL is found."""
        for reference in self.references:
            if reference.url.startswith("https://cve.mitre.org"):
                return reference.url
        return f"https://snyk.io/vuln/{self.id}"  # id is Snyk's vulnerability ID

    def get_numpy_color(self) -> MplRGBAColor:
        return get_cvss_color(self.cvssScore)

    def get_upgrade_path(self) -> Optional[str]:
        if len(self.upgradePath) == 2:
            return self.upgradePath[1]
        return None

    def get_year(self, timetype: CVETimeType = DEFAULT_CVE_TIMETYPE) -> Optional[int]:
        """
        Returns the year of the vulnerability.
        """
        try:
            vuln_date = getattr(self, timetype.value)  # type: datetime
            if vuln_date is not None:
                return vuln_date.year
        except AttributeError:
            pass
        return None

    def get_age_score_color(
        self,
        timetype: CVETimeType = DEFAULT_CVE_TIMETYPE,
    ) -> VulnAgePoint:
        """
        Retrieves the vulnerability's age (in days), score and numpy color (determined by its CVSS score).

        Used for displaying vulnerabilities in scatter plots.
        """
        # NOTE: catch AttributeError?
        vuln_date = getattr(self, timetype.value)  # type: datetime
        if vuln_date is None:
            vuln_date = datetime.utcnow()
        return VulnAgePoint(
            timestamp=vuln_date, score=self.cvssScore, color=self.get_numpy_color()
        )

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
    timestamp: datetime = Field(default_factory=datetime.utcnow)  # Not snyk-native
    image: ImageInfo = Field(default_factory=ImageInfo.init_empty)

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

    @validator("image", always=True, pre=True)
    def ensure_image_info(
        cls, v: Optional[dict[str, Any]], field: ModelField
    ) -> ImageInfo:
        """Fix for hypothesis failing to call default factory properly when nesting models."""
        if not v and field.default_factory:
            return field.default_factory()
        return v

    def __hash__(self) -> int:
        """Returns ID of self. Required to add object to dict."""
        return id(self)

    def __repr__(self) -> str:
        return f"SnykVulnerabilityScan(path={self.path}, platform={self.platform})"

    def get_timestamp(
        self, image: bool = True, mode: ImageTimeMode = ImageTimeMode.CREATED
    ) -> datetime:
        """Returns the timestamp of the scan.

        Parameters
        ----------
        image : `bool`, optional
            If True, the timestamp of the scan's image is returned.
            If False, the timestamp of the scan is returned.
        mode : `ImageTimeMode`, optional
            The mode of the timestamp to retrieve. Only applies if `image` is True.

        Returns
        -------
        `datetime`
            The timestamp of the scan (or image).
        """
        # TODO: ensure UTC somewhere else?
        if image:
            ts = self.image.get_timestamp(mode)
        else:
            ts = self.timestamp
        ts = ts.replace(tzinfo=timezone.utc)
        return ts

    @property
    def title(self) -> str:
        """Returns the title of the report. The title is the scanned image."""
        return self.image.image

    @property
    def is_aggregate(self) -> bool:
        return False

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

    def most_severe_n(
        self, n: Optional[int] = 5, upgradable: bool = False
    ) -> list[SnykVulnerability]:
        """Returns the `n` most severe vulnerabilities (if any), optionally only upgradable ones.

        Parameters
        ----------
        n : `int`, optional
            The number of vulnerabilities to return.
        upgradable : `bool`, optional
            If True, only upgradable vulnerabilities are returned.

        Returns
        -------
        `list[SnykVulnerability]`
            The `n` most severe vulnerabilities (if any), optionally only upgradable ones.
        """
        # TODO: optimize memory usage by utilizing generators better
        # We can limit a generator by doing takewhile(lambda x: x < n, v)
        #
        # Then again, what's the point?
        # We need to collect all to sort anyway... We don't actually save any memory.
        #
        # Actually trying to save memory here would require a pretty complex
        # function to do the filtering.
        v = sorted(self.vulnerabilities, key=lambda v: v.cvssScore, reverse=True)
        if upgradable:
            v = list(filter(lambda v: v.isUpgradable, v))
        if n and len(v) > n:
            return v[:n]
        return v

    # def most_severe_of_severity(self, severity: Severity) -> Optional[SnykVulnerability]:

    @property
    def least_severe(self) -> Optional[SnykVulnerability]:
        """The least severe vulnerability (if any)"""
        return min(
            self.vulnerabilities,
            default=None,
            key=lambda v: v.cvssScore if v is not None else 0.0,
        )

    @property
    def low(self) -> Iterable[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of low."""
        return self.get_vulnerabilities_by_severity(CVESeverity.LOW)

    @property
    def medium(self) -> Iterable[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of medium."""
        return self.get_vulnerabilities_by_severity(CVESeverity.MEDIUM)

    @property
    def high(self) -> Iterable[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of high."""
        return self.get_vulnerabilities_by_severity(CVESeverity.HIGH)

    @property
    def critical(self) -> Iterable[SnykVulnerability]:
        """All vulnerabilities with a CVSS rating of critical."""
        return self.get_vulnerabilities_by_severity(CVESeverity.CRITICAL)

    def get_vulnerabilities_by_severity(
        self, severity: CVESeverity
    ) -> Iterable[SnykVulnerability]:
        sev = severity.name.lower()
        for v in self.vulnerabilities:
            if v.severity == sev:
                yield v

    @property
    def n_low(self) -> int:
        """All vulnerabilities with a CVSS rating of low."""
        return ilen(self.low)

    @property
    def n_medium(self) -> int:
        """All vulnerabilities with a CVSS rating of medium."""
        return ilen(self.medium)

    @property
    def n_high(self) -> int:
        """All vulnerabilities with a CVSS rating of high."""
        return ilen(self.high)

    @property
    def n_critical(self) -> int:
        """All vulnerabilities with a CVSS rating of critical."""
        return ilen(self.critical)

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

    @property
    def upgrade_paths(self) -> list[str]:
        """
        Return a list of upgrade paths for all vulnerabilities with
        duplicates removed.
        """
        return list(  # cast to list
            set(  # remove duplicates
                filter(  # filter out empty strings
                    None.__ne__,
                    (p.get_upgrade_path() for p in self.vulnerabilities),
                )
            )
        )

    @property
    def dockerfile_instructions(self) -> list[str]:
        """
        Return a list of dockerfile instructions for all vulnerabilities with
        duplicates removed.
        """
        return list(  # cast to list
            set(  # remove duplicates
                filter(  # filter out empty strings
                    None.__ne__,
                    (p.dockerfileInstruction for p in self.vulnerabilities),
                )
            )
        )

    def get_exploitable(self) -> Iterable[SnykVulnerability]:
        """
        Return a list of vulnerabilities that are exploitable.
        """
        for v in self.vulnerabilities:
            if v.exploitable:
                yield v

    def get_vulns_by_date(
        self, time_type: CVETimeType
    ) -> dict[DateDescription, list[SnykVulnerability]]:
        """
        Retrieves all vulnerabilities grouped by time period.

        Parameters
        ----------
        time_type : `CVETimeType`
           Which CVE time to group by.
           See `CVETimeType` for possible options.

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
    ) -> list[VulnAgePoint]:
        """Returns a list of `VulnAgePoint` objects for all vulnerabilities."""
        l = [vuln.get_age_score_color() for vuln in self.vulnerabilities]
        return sorted(l, key=lambda v: v.timestamp)

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

    def _get_vuln_upgradability_distribution(
        self, vulns: Iterable[SnykVulnerability]
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
