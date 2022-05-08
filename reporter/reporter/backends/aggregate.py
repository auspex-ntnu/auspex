from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from functools import _lru_cache_wrapper, cache, cached_property
from itertools import chain
import itertools
from typing import Iterable, Iterator, Optional, TypeVar
from auspex_core.models.cve import CVESeverity
from auspex_core.models.gcr import ImageInfo, ImageTimeMode

import numpy as np
from loguru import logger
from pydantic import BaseModel, Field, validator
from more_itertools import ilen

from ..types.nptypes import MplRGBAColor
from auspex_core.models.cve import CVSS

# from .snyk.model import SnykContainerScan, SnykVulnerability
from ..utils import npmath
from ..types.protocols import ScanType, ScanType, VulnerabilityType
import time
from ..frontends.shared.models import VulnAgePoint

# TODO: move this out the snyk module
class AggregateReport(BaseModel):
    reports: list[ScanType]
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    # OR
    # scans: list[ScanType]

    class Config:
        # arbitrary_types_allowed = True
        extra = "allow"  # should we allow or disallow this?
        validate_assignment = True
        keep_untouched = (cached_property, _lru_cache_wrapper)
        arbitrary_types_allowed = True

    @validator("id", always=True)
    def set_id(cls, v: str) -> str:
        if v:
            return v
        return f"AggregateReport_{int(time.time())}"

    # FIXME: remove. Only in place to make tests pass for now
    @property
    def scans(self) -> list[ScanType]:
        return self.reports

    @property
    def title(self) -> str:
        return f"Aggregate Report"

    @property
    def image(self) -> ImageInfo:
        return ImageInfo(
            image_size_bytes="",  # we have to verify these values are numeric before we can use them
            layer_id="",
            tag=list(
                set(chain.from_iterable([report.image.tag for report in self.reports]))
            ),
            created=min(
                [r.image.created for r in self.reports],
                default=datetime.utcnow(),
            ),
            uploaded=min(
                [r.image.uploaded for r in self.reports],
                default=datetime.utcnow(),
            ),
            digest="",  # NOTE: hash digests of all reports?
            image=", ".join([r.image.image for r in self.reports if r.image.image]),
            media_type="",
        )

    @property
    def is_aggregate(self) -> bool:
        return True

    def __hash__(self) -> int:
        return id(self)

    def get_timestamp(
        self, image: bool = True, mode: ImageTimeMode = ImageTimeMode.CREATED
    ) -> datetime:
        """Returns timestamp of when aggregate scan was created.
        Parameters `image` and `mode` have no effect, and are implemented
        to conform to `ScanType` protocol."""
        return self.timestamp

    @property
    def cvss_max(self) -> float:
        return max(self.cvss_scores(), default=0.0)
        # return 0.0

    @property
    def cvss_min(self) -> float:
        # return min((scan.cvss_min for scan in self.reports), default=0.0)
        return min(self.cvss_scores(), default=0.0)
        # return 0.0

    @property
    def cvss_median(self) -> float:
        return npmath.median(self.cvss_scores())

    @property
    def cvss_mean(self) -> float:
        return npmath.mean(self.cvss_scores())

    @property
    def cvss_stdev(self) -> float:
        return npmath.stdev(self.cvss_scores())

    @property
    def cvss(self) -> CVSS:
        return CVSS(
            mean=self.cvss_mean,
            median=self.cvss_median,
            stdev=self.cvss_stdev,
            max=self.cvss_max,
            min=self.cvss_min,
        )

    @property
    def low(self) -> Iterable[VulnerabilityType]:
        return self.get_vulnerabilities_by_severity(CVESeverity.LOW)

    @property
    def medium(self) -> Iterable[VulnerabilityType]:
        return self.get_vulnerabilities_by_severity(CVESeverity.MEDIUM)

    @property
    def high(self) -> Iterable[VulnerabilityType]:
        return self.get_vulnerabilities_by_severity(CVESeverity.HIGH)

    @property
    def critical(self) -> Iterable[VulnerabilityType]:
        return self.get_vulnerabilities_by_severity(CVESeverity.CRITICAL)

    @property
    def n_low(self) -> int:
        return ilen(self.low)

    @property
    def n_medium(self) -> int:
        return ilen(self.medium)

    @property
    def n_high(self) -> int:
        return ilen(self.high)

    @property
    def n_critical(self) -> int:
        """Number of critical vulnerabilities."""
        return ilen(self.critical)

    @cache
    def cvss_scores(self, ignore_zero: bool = True) -> list[float]:
        scores: list[float] = []
        for scan in self.reports:
            scores.extend(scan.cvss_scores(ignore_zero))

        if not scores:
            scores = [0.0]
            logger.warning(
                "Unable to retrieve scores when creating aggregate report for "
                f"the following scans: {self.reports}"
            )
        return scores

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

    def get_vulnerabilities_by_severity(
        self, severity: CVESeverity
    ) -> Iterable[VulnerabilityType]:
        for scan in self.reports:
            yield from scan.get_vulnerabilities_by_severity(severity)

    def get_exploitable(self) -> Iterable[VulnerabilityType]:
        """Returns vulnerabilities that are exploitable.

        Returns
        -------
        `Iterable[VulnerabilityType]`
            Iterable of vulnerabilities that are exploitable.
        """
        for report in self.reports:
            yield from report.get_exploitable()

    def get_report_ids(self) -> list[str]:
        """Retrieves IDs of all reports."""
        return [report.id for report in self.reports]

    @property
    def vulnerabilities(self) -> Iterable[VulnerabilityType]:
        """Generator that yields vulnerabilities from all scans."""
        for scan in self.reports:
            yield from scan.vulnerabilities

    @property
    def most_severe(self) -> Optional[VulnerabilityType]:
        """The most severe vulnerability (if any)"""
        return max(
            self.most_severe_n(),
            default=None,
            # mypy doesn't understand that None takes presedence over key (?)
            # hence the guard against None here
            key=lambda v: v.cvssScore if v is not None else 0.0,
        )

    def most_severe_n(
        self, n: Optional[int] = 5, upgradable: bool = False
    ) -> list[VulnerabilityType]:
        """Retrieves the N most severe vulnerabilities across all images scanned.

        Parameters
        ----------
        n : int, optional
            Number of vulnerabilities to return, by default 5

        Returns
        -------
        list[SnykVulnerability]
            List of vulnerabilities
        """
        vulns = list(self.vulnerabilities)
        vulns.sort(key=lambda v: v.cvssScore, reverse=True)
        if upgradable:
            vulns = list(filter(lambda v: v.is_upgradable, vulns))
        if n and n > len(vulns):  # make sure we don't go out of bounds
            n = len(vulns)
        return vulns[:n]

    # BACKLOG: add n argument so we can get multiple per image?
    def most_severe_per_scan(self) -> dict[str, Optional[VulnerabilityType]]:
        """Retrieves the most severe vulnerability from each scanned image.

        Returns
        -------
        list[SnykVulnerability]
            Dictionary where keys are image names and values are scans
        """
        vulns = {}  # type: dict[str, Optional[VulnerabilityType]]
        for scan in self.reports:
            most_severe = scan.most_severe
            if not most_severe:
                logger.info(f"Scan {scan.id} has no vulnerabilities.")
            # TECHNICALLY we could run into an issue where two scans somehow have the same ID
            # and will overwrite each other in this mapping, but that's such an unlikely edge-case
            # that we simply ignore it.
            vulns[scan.id] = most_severe
        return vulns

    @property
    def upgrade_paths(self) -> list[str]:
        """Retrieves upgrade paths for all vulnerabilities in all scans."""
        # BACKLOG: could make this more efficient with a chain.from_iterable() call
        u = []  # type: list[str]
        for scan in self.reports:
            u.extend(scan.upgrade_paths)
        return u
        # return list(chain(scan.upgrade_paths for scan in self.reports))

    @property
    def dockerfile_instructions(self) -> list[str]:
        """Retrieves Dockerfile instructions for all vulnerabilities in all scans."""
        # BACKLOG: could make this more efficient with a chain.from_iterable() call
        d = []  # type: list[str]
        for scan in self.reports:
            d.extend(scan.dockerfile_instructions)
        return d
        # return list(chain(scan.dockerfile_instructions for scan in self.reports))

    def most_common_cve(self, n: Optional[int] = 5) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for report in self.reports:
            # we need to retrieve all CVEs, so we don't pass the n arg here
            mc = report.most_common_cve()
            c.update(mc)
        return c.most_common(n)  # only here do we use n

    def get_vulns_age_score_color(self) -> list[VulnAgePoint]:
        """Retrieves vulnerability age, score and color for all vulnerabilities in all reports."""
        l = []  # type: list[VulnAgePoint]
        for report in self.reports:
            l.extend(report.get_vulns_age_score_color())
        return sorted(l, key=lambda v: v.timestamp)
