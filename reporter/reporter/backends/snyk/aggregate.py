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
    def cvss_sd(self) -> float:
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
