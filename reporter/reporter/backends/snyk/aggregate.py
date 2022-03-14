from collections import Counter
from dataclasses import dataclass
from loguru import logger
import numpy as np

from functools import cached_property
from .model import SnykContainerScan

from numpy.typing import NDArray

# Use dataclass here since we don't need validation
@dataclass
class AggregateScan:
    scans: list[SnykContainerScan]

    def get_scan_ids(self) -> list[str]:
        return [scan.id for scan in self.scans]

    # TODO: Add caching!
    @cached_property
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

    # TODO: Exception handling for median, mean and std

    @cached_property
    def cvss_median(self) -> float:
        return float(np.median(self.cvss_scores))

    @cached_property
    def cvss_mean(self) -> float:
        return float(np.mean(self.cvss_scores))

    @cached_property
    def cvss_sd(self) -> float:
        return float(np.std(self.cvss_scores))

    def most_common_cve(self, n: int) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for scan in self.scans:
            # we need to fetch all CVEs so we don't pass the n arg here
            mc = scan.most_common_cve()
            c.update(mc)
        return c.most_common(n)  # only here do we use n

    def get_vuln_age_score_color(self) -> list[tuple[int, float, NDArray]]:
        l: list[tuple[int, float, NDArray]] = []
        for scan in self.scans:
            l.extend(scan.vulnerabilities.get_vulns_age_score_color())
        return l