# certain attribute names use the camelCase naming convention due to
# data structures originally adhering to the naming scheme defined by Snyk
# for their scans. In order to not break compatibility with existing
# snyk classes, we maintain camelCase names.
#
# Protocol classes can switch to snake_case if snyk classes implement
# properties with snake_case names that retrieve the original camelCase attribute values.

from datetime import datetime
from typing import (
    Iterable,
    Optional,
    Protocol,
    Any,
    Sequence,
    runtime_checkable,
    TYPE_CHECKING,
)

from .nptypes import MplRGBAColor

from auspex_core.models.gcr import ImageInfo, ImageTimeMode
from auspex_core.models.cve import CVSS, CVETimeType

if TYPE_CHECKING:
    from ..frontends.shared.models import VulnAgePoint


@runtime_checkable
class VulnerabilityType(Protocol):
    @property
    def cvssScore(self) -> float:
        ...

    @property
    def title(self) -> str:
        ...

    @property
    def severity(self) -> str:
        ...

    @property
    def is_upgradable(self) -> bool:
        ...

    def get_numpy_color(self) -> MplRGBAColor:
        ...

    def get_age_score_color(self, timetype: CVETimeType) -> "VulnAgePoint":
        ...

    def get_id(self) -> str:
        ...


# TODO: Use generics to annotate list contents
@runtime_checkable
class ScanType(Protocol):
    """
    Base interface type for scans produced by any scanning backend.

    Both single image scans and aggregate scans should implement this interface.
    """

    # This is not read-only so that it can be replaced by a timezone-aware datetime
    timestamp: datetime  # MUST be UTC timestamp.
    # TODO: implement init check to ensure datetime timezone

    @property
    def id(self) -> str:
        ...

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
        ...

    @property
    def cvss(self) -> CVSS:
        """CVSS object for the scan."""
        ...

    @property
    def low(self) -> Sequence[VulnerabilityType]:
        """Vulnerabilities with a severity of 'low'."""
        ...

    @property
    def medium(self) -> Sequence[VulnerabilityType]:
        """Vulnerabilities with a severity of 'medium'."""
        ...

    @property
    def high(self) -> Sequence[VulnerabilityType]:
        """Vulnerabilities with a severity of 'high'."""
        ...

    @property
    def critical(self) -> Sequence[VulnerabilityType]:
        """Vulnerabilities with a severity of 'critical'."""
        ...

    @property
    def vulnerabilities(self) -> Iterable[VulnerabilityType]:
        """All vulnerabilities."""
        ...

    @property
    def n_low(self) -> int:
        """Number of vulnerabilities with a severity of 'low'."""
        ...

    @property
    def n_medium(self) -> int:
        """Number of vulnerabilities with a severity of 'medium'."""
        ...

    @property
    def n_high(self) -> int:
        """Number of vulnerabilities with a severity of 'high'."""
        ...

    @property
    def n_critical(self) -> int:
        """Number of vulnerabilities with a severity of 'critical'."""
        ...

    def most_common_cve(self, n: int) -> list[tuple[str, int]]:
        """Sorted list of tuples of CVE IDs and number of occurences."""
        ...

    @property
    def most_severe(self) -> Any:  # TODO: decide on return type
        """Get most severe vulnerability"""
        ...

    def most_severe_n(
        self, n: Optional[int] = 5, upgradable: bool = False
    ) -> list[VulnerabilityType]:
        """Returns the `n` most severe vulnerabilities (if any), optionally only upgradable ones."""

        ...

    @property
    def upgrade_paths(self) -> list[str]:
        """
        Return a list of upgrade paths for all vulnerabilities.
        """
        ...

    @property
    def dockerfile_instructions(self) -> list[str]:
        """Get list of Dockerfile instructions for all vulnerabilities."""
        ...

    def cvss_scores(self, ignore_zero: bool) -> list[float]:
        """Get list of CVSSv3 scores of all vulnerabilities."""
        ...

    def get_distribution_by_severity(self) -> dict[str, int]:
        """Retrieves distribution of vulnerabiltiies grouped by their
        CVSS severity level."""
        ...

    def get_vulns_age_score_color(
        self,
    ) -> list["VulnAgePoint"]:
        """Creates list of tuples representing vulnerabilities,
        to be used as datapoints in a plot.

        Each tuple contains the vulnerability's timestamp, its CVSS score, and its color.
        The color is determined by the vulnerability's CVSS score.

        The list is sorted by timestamp.

        Returns
        -------
        list[VulnAgePoint]
            List of tuples representing a datapoint for each vulnerability to be used in a plot.
        """
        ...


@runtime_checkable
class ScanTypeSingle(ScanType, Protocol):
    """Specialization of ScanType for single image scans."""

    # id: str
    @property
    def image(self) -> ImageInfo:
        ...


@runtime_checkable
class ScanTypeAggregate(ScanType, Protocol):
    """Specialization of ScanType for aggregate scans."""

    @property
    def scans(self) -> list[ScanTypeSingle]:
        ...

    @property  # bandaid until everything is renamed from "scan" to "report"
    def reports(self) -> list[ScanTypeSingle]:
        ...


@runtime_checkable
class Plottable(Protocol):
    """
    Interface for objects that can be plotted.
    """

    def get_age_and_mean_score(self) -> tuple[datetime, float]:
        ...
