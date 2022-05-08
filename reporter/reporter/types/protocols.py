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
    runtime_checkable,
    TYPE_CHECKING,
    Collection,
)

from .nptypes import MplRGBAColor

from auspex_core.models.gcr import ImageInfo, ImageTimeMode
from auspex_core.models.cve import CVSS, CVESeverity, CVETimeType
from ..cve import DEFAULT_CVE_TIMETYPE

if TYPE_CHECKING:
    from ..frontends.shared.models import VulnAgePoint  # pragma: no cover


@runtime_checkable
class VulnerabilityType(Protocol):
    @property
    def cvssScore(self) -> float:
        """CVSSv3 score of the vulnerability."""

    @property
    def title(self) -> str:
        """Title of the vulnerability."""

    @property
    def severity(self) -> str:
        """CVSSv3 severity of the vulnerability."""

    @property
    def exploitable(self) -> bool:
        """Whether the vulnerability is exploitable."""

    @property
    def is_upgradable(self) -> bool:
        """Whether or not the vulnerability can be mitigated by upgrading."""

    @property
    def url(self) -> str:
        """Get the URL of the vulnerability."""

    @property
    def exploit(self) -> str:
        """Get the exploit of the vulnerability.
        Should only be used if the `self.exploitable==True`.
        """

    def get_year(self, timetype: CVETimeType = DEFAULT_CVE_TIMETYPE) -> Optional[int]:
        """Get the year of the vulnerability.
        (We account for not all vulnerabilities having a date.)
        """

    def get_numpy_color(self) -> MplRGBAColor:
        """Get the numpy color for the vulnerability - determined by its score."""

    def get_age_score_color(
        self, timetype: CVETimeType = DEFAULT_CVE_TIMETYPE
    ) -> "VulnAgePoint":
        """Get the age, score and color of the vulnerability."""

    def get_id(self) -> str:
        """Get the unique ID of the vulnerability."""


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
        """The unique ID of the report."""

    @property
    def title(self) -> str:
        """Get the title of the scan."""

    @property
    def image(self) -> ImageInfo:
        """ImageInfo object for the report."""

    @property
    def is_aggregate(self) -> bool:
        """Whether the report is an aggregate report."""

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

    @property
    def cvss(self) -> CVSS:
        """CVSS object for the scan, containing CVSS metrics."""

    @property
    def low(self) -> Iterable[VulnerabilityType]:
        """Vulnerabilities with a severity of 'low'."""

    @property
    def medium(self) -> Iterable[VulnerabilityType]:
        """Vulnerabilities with a severity of 'medium'."""

    @property
    def high(self) -> Iterable[VulnerabilityType]:
        """Vulnerabilities with a severity of 'high'."""

    @property
    def critical(self) -> Iterable[VulnerabilityType]:
        """Vulnerabilities with a severity of 'critical'."""

    @property
    def vulnerabilities(self) -> Iterable[VulnerabilityType]:
        """All vulnerabilities."""

    def get_vulnerabilities_by_severity(
        self, severity: CVESeverity
    ) -> Iterable[VulnerabilityType]:
        """Returns a list of vulnerabilities with the given severity."""

    @property
    def n_low(self) -> int:
        """Number of vulnerabilities with a severity of 'low'."""

    @property
    def n_medium(self) -> int:
        """Number of vulnerabilities with a severity of 'medium'."""

    @property
    def n_high(self) -> int:
        """Number of vulnerabilities with a severity of 'high'."""

    @property
    def n_critical(self) -> int:
        """Number of vulnerabilities with a severity of 'critical'."""

    def most_common_cve(self, n: Optional[int] = 5) -> list[tuple[str, int]]:
        """Sorted list of tuples of CVE IDs and number of occurences."""

    @property
    def most_severe(self) -> Any:  # TODO: decide on return type
        """Get most severe vulnerability"""

    def most_severe_n(
        self, n: Optional[int] = 5, upgradable: bool = False
    ) -> Collection[VulnerabilityType]:
        """Returns the `n` most severe vulnerabilities (if any), optionally only upgradable ones."""

    @property
    def upgrade_paths(self) -> list[str]:
        """
        Return a list of upgrade paths for all vulnerabilities.
        """

    @property
    def dockerfile_instructions(self) -> list[str]:
        """Get list of Dockerfile instructions for all vulnerabilities."""

    def cvss_scores(self, ignore_zero: bool) -> list[float]:
        """Get list of CVSSv3 scores of all vulnerabilities."""

    def get_distribution_by_severity(self) -> dict[str, int]:
        """Retrieves distribution of vulnerabiltiies grouped by their
        CVSS severity level."""

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

    def get_exploitable(self) -> Iterable[VulnerabilityType]:
        """Get list of vulnerabilities that are exploitable."""


@runtime_checkable
class ScanTypeSingle(ScanType, Protocol):
    """Specialization of ScanType for single image scans."""


@runtime_checkable
class ScanTypeAggregate(ScanType, Protocol):
    """Specialization of ScanType for aggregate scans."""

    @property
    def scans(self) -> list[ScanTypeSingle]:
        """All reports in the aggregate."""

    @property  # bandaid until everything is renamed from "scan" to "report"
    def reports(self) -> list[ScanTypeSingle]:
        """All reports in the aggregate (alias)."""


@runtime_checkable
class Plottable(Protocol):
    """
    Interface for objects that can be plotted.
    """

    def get_age_and_mean_score(self) -> tuple[datetime, float]:
        """Get age and mean score for the object."""
