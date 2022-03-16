from collections import Counter
from dataclasses import dataclass
from functools import cached_property
from typing import Iterator, Optional

import numpy as np
from loguru import logger

from ..._types import MplRGBAColor
from .model import SnykContainerScan, SnykVulnerability


# Use dataclass here since we don't need validation
@dataclass
class AggregateScan:
    scans: list[SnykContainerScan]

    @property
    def cvss_max(self) -> float:
        return max(self.cvss_scores)

    @property
    def cvss_min(self) -> float:
        # return min((scan.cvss_min for scan in self.scans), default=0.0)
        return min(self.cvss_scores)

    @property
    def cvss_median(self) -> float:
        return float(np.median(self.cvss_scores))

    @property
    def cvss_mean(self) -> float:
        return float(np.mean(self.cvss_scores))

    @property
    def cvss_stdev(self) -> float:
        return float(np.std(self.cvss_scores))

    @cached_property
    def cvss_scores(self) -> list[float]:
        scores: list[float] = []
        for scan in self.scans:
            scores.extend(scan.vulnerabilities.get_cvss_scores())

        if not scores:
            scores = [0.0]
            logger.warning(
                "Unable to retrieve scores when creating aggregate report for "
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

    # TODO: add n argument so we can get multiple per image?
    def most_severe_per_scan(self) -> dict[str, Optional[SnykVulnerability]]:
        """Retrieves the most severe vulnerability from each scanned image.

        Returns
        -------
        list[SnykVulnerability]
            Dictionary where keys are image names and values are scans
        """
        vulns = {}  # type: dict[str, Optional[SnykVulnerability]]
        for scan in self.scans:
            most_severe = scan.vulnerabilities.most_severe
            if not most_severe:
                logger.info(f"Scan {scan.id} has no vulnerabilities.")
            # TECHNICALLY we could run into an issue where two scans somehow have the same ID
            # and will overwrite each other in this mapping, but that's such an unlikely edge-case
            # that we simply ignore it.
            vulns[scan.id] = most_severe
        return vulns

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
