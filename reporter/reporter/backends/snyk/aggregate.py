from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from functools import _lru_cache_wrapper, cache, cached_property
from itertools import chain
from typing import Iterator, Optional, TypeVar
from auspex_core.models.gcr import ImageInfo, ImageTimeMode

import numpy as np
from loguru import logger
from pydantic import BaseModel, Field, validator

from ...types.nptypes import MplRGBAColor
from ...types.cvss import CVSS
from .model import SnykContainerScan, SnykVulnerability
from ...utils import npmath
from ...types.protocols import ScanTypeSingle
import time
from ...frontends.shared.models import VulnAgePoint

# TODO: move this out the snyk module
class AggregateScan(BaseModel):
    scans: list[SnykContainerScan]
    id: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    # OR
    # scans: list[ScanType]

    class Config:
        # arbitrary_types_allowed = True
        extra = "allow"  # should we allow or disallow this?
        validate_assignment = True
        keep_untouched = (cached_property, _lru_cache_wrapper)

    @validator("id", always=True)
    def set_id(cls, v: str) -> str:
        if v:
            return v
        return f"AggregateScan_{int(time.time())}"

    @property  # workaround until we rename everything to "report"
    def reports(self) -> list[SnykContainerScan]:
        return self.scans

    def __hash__(self) -> int:
        return id(self)

    def get_timestamp(
        self, image: bool = True, mode: ImageTimeMode = ImageTimeMode.CREATED
    ) -> datetime:
        """Returns timestamp of when aggregate scan was created.
        Parameters `image` and `mode` have no effect, and are implemented
        to conform to `ScanType` protocol."""
        return self.timestamp

    # @cached_property
    # def image(self) -> ImageInfo:
    #     return ImageInfo(
    #         image_size_bytes=np.mean([s.image.imageSizeBytes for s in self.scans]),
    #         layer_id="",
    #         media_type="",
    #         tag=[],
    #         uploaded=datetime.utcnow(),
    #         created=datetime.utcnow(),
    #         digest=None,
    #         image=None,
    #     )

    @property
    def cvss_max(self) -> float:
        return max(self.cvss_scores(), default=0.0)
        # return 0.0

    @property
    def cvss_min(self) -> float:
        # return min((scan.cvss_min for scan in self.scans), default=0.0)
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
    def low(self) -> list[SnykVulnerability]:
        return self._get_vulnerabilities_by_severity("low")

    @property
    def medium(self) -> list[SnykVulnerability]:
        return self._get_vulnerabilities_by_severity("medium")

    @property
    def high(self) -> list[SnykVulnerability]:
        return self._get_vulnerabilities_by_severity("high")

    @property
    def critical(self) -> list[SnykVulnerability]:
        return self._get_vulnerabilities_by_severity("critical")

    # BACKLOG: optimize these n_<severity> methods
    @property
    def n_low(self) -> int:
        return len(self.low)

    @property
    def n_medium(self) -> int:
        return len(self.medium)

    @property
    def n_high(self) -> int:
        return len(self.high)

    @property
    def n_critical(self) -> int:
        """Number of critical vulnerabilities."""
        return len(self.critical)

    @cache
    def cvss_scores(self, ignore_zero: bool = True) -> list[float]:
        scores: list[float] = []
        for scan in self.scans:
            scores.extend(scan.cvss_scores(ignore_zero))

        if not scores:
            scores = [0.0]
            logger.warning(
                "Unable to retrieve scores when creating aggregate report for "
                f"the following scans: {self.scans}"
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

    def _get_vulnerabilities_by_severity(
        self, severity: str
    ) -> list[SnykVulnerability]:
        # FIXME: will not raise exception on invalid severity if aggregate report has no scans

        l = []
        for scan in self.scans:
            attrs = {
                "low": scan.low,
                "medium": scan.medium,
                "high": scan.high,
                "critical": scan.critical,
            }
            vulns = attrs.get(severity)
            if vulns is None:
                raise ValueError(f"Unknown severity: '{severity}'")
            l.extend(vulns)
        return l

    def get_scan_ids(self) -> list[str]:
        """Retrieves IDs of all scans."""
        return [scan.id for scan in self.scans]

    @property
    def vulnerabilities(self) -> Iterator[SnykVulnerability]:
        """Generator that yields vulnerabilities from all scans."""
        for scan in self.scans:
            for vuln in scan.vulnerabilities:
                yield vuln

    @property
    def most_severe(self) -> Optional[SnykVulnerability]:
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
    ) -> list[SnykVulnerability]:
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
    def most_severe_per_scan(self) -> dict[str, Optional[SnykVulnerability]]:
        """Retrieves the most severe vulnerability from each scanned image.

        Returns
        -------
        list[SnykVulnerability]
            Dictionary where keys are image names and values are scans
        """
        vulns = {}  # type: dict[str, Optional[SnykVulnerability]]
        for scan in self.scans:
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
        for scan in self.scans:
            u.extend(scan.upgrade_paths)
        return u
        # return list(chain(scan.upgrade_paths for scan in self.scans))

    @property
    def dockerfile_instructions(self) -> list[str]:
        """Retrieves Dockerfile instructions for all vulnerabilities in all scans."""
        # BACKLOG: could make this more efficient with a chain.from_iterable() call
        d = []  # type: list[str]
        for scan in self.scans:
            d.extend(scan.dockerfile_instructions)
        return d
        # return list(chain(scan.dockerfile_instructions for scan in self.scans))

    def most_common_cve(self, n: int) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for scan in self.scans:
            # we need to retrieve all CVEs, so we don't pass the n arg here
            mc = scan.most_common_cve()
            c.update(mc)
        return c.most_common(n)  # only here do we use n

    def get_vulns_age_score_color(self) -> list[VulnAgePoint]:
        """Retrieves vulnerability age, score and color for all vulnerabilities in all reports."""
        l = []  # type: list[VulnAgePoint]
        for scan in self.scans:
            l.extend(scan.get_vulns_age_score_color())
        return sorted(l, key=lambda v: v.timestamp)
