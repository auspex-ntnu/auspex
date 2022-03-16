from collections import Counter
from dataclasses import dataclass
from functools import cached_property
from typing import Iterator

import numpy as np
from loguru import logger

from .model import SnykContainerScan, SnykVulnerability
from ..._types import MplRGBAColor


# Use dataclass here since we don't need validation
@dataclass
class AggregateScan:
    scans: list[SnykContainerScan]

    @property
    def cvss_max(self) -> float:
        return max(scan.cvss_max for scan in self.scans)

    @property
    def cvss_min(self) -> float:
        return min(scan.cvss_min for scan in self.scans)

    @property
    def cvss_median(self) -> float:
        return float(np.median(self.cvss_scores))

    @property
    def cvss_mean(self) -> float:
        return float(np.mean(self.cvss_scores))

    @property
    def cvss_stdev(self) -> float:
        return float(np.std(self.cvss_scores))

    # TODO: Add caching!
    @property
    def cvss_scores(self) -> list[float]:
        scores: list[float] = []
        for scan in self.scans:
            scores.extend(scan.vulnerabilities.get_cvss_scores())

        if not scores:
            scores = [0.0]
            logger.info(
                "Unable to fetch scores when creating aggregate report for "
                f"the following scans: {self.scans}"
            )
        return scores

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

    # TODO: optimize these n_<severity> methods
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

    def _get_vulnerabilities_by_severity(
        self, severity: str
    ) -> list[SnykVulnerability]:
        # FIXME: will not raise exception on invalid severity if aggregate report has no scans

        l = []
        for scan in self.scans:
            attrs = {
                "low": scan.vulnerabilities.low,
                "medium": scan.vulnerabilities.medium,
                "high": scan.vulnerabilities.high,
                "critical": scan.vulnerabilities.critical,
            }
            vulns = attrs.get(severity)
            if vulns is None:
                raise ValueError(f"Unknown severity: '{severity}'")
            l.extend(vulns)
        return l

    def get_scan_ids(self) -> list[str]:
        return [scan.id for scan in self.scans]

    def vulnerabilities(self) -> Iterator[SnykVulnerability]:
        """Generator that yields vulnerabilities from all scans."""
        for scan in self.scans:
            for vuln in scan.vulnerabilities:
                yield vuln

    # TODO: Exception handling for median, mean and std

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
            l.extend(scan.vulnerabilities.get_vulns_age_score_color())
        return l
