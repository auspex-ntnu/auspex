from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from functools import _lru_cache_wrapper, cache, cached_property
from typing import Iterator, Optional, TypeVar

import numpy as np
from loguru import logger
from pydantic import BaseModel, Field, validator

from ...types.nptypes import MplRGBAColor
from ...types.cvss import CVSS
from .model import SnykContainerScan, SnykVulnerability
from ...utils import npmath
from ...types.protocols import ScanTypeSingle
import time

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

    def most_severe(self, n: int = 5) -> list[SnykVulnerability]:
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
        if n > len(vulns):  # make sure we don't go out of bounds
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
        paths = []
        for scan in self.scans:
            paths.extend(scan.upgrade_paths())
        return paths

    def most_common_cve(self, n: int) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for scan in self.scans:
            # we need to retrieve all CVEs, so we don't pass the n arg here
            mc = scan.most_common_cve()
            c.update(mc)
        return c.most_common(n)  # only here do we use n

    def get_vuln_age_score_color(self) -> list[tuple[int, float, MplRGBAColor]]:
        l: list[tuple[int, float, MplRGBAColor]] = []
        for scan in self.scans:
            l.extend(scan.get_vulns_age_score_color())
        return l
