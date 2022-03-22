from typing import Protocol, Any, runtime_checkable


# Use generics to annotate list contents
@runtime_checkable
class ScanType(Protocol):
    @property
    def cvss_max(self) -> float:
        """Maximum CVSS score."""
        ...

    @property
    def cvss_min(self) -> float:
        """Minimum CVSS score."""
        ...

    @property
    def cvss_median(self) -> float:
        """Median of all CVSS scores."""
        ...

    @property
    def cvss_mean(self) -> float:
        """Mean of all CVSS scores."""
        ...

    @property
    def cvss_stdev(self) -> float:
        """Standard deviation of all CVSS scores."""
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

    def cvss_scores(self, ignore_zero: bool) -> list[float]:
        """Get list of CVSSv3 scores of all vulnerabilities."""
        ...


# class AggregateScanType(ScanTypeBase):
#     pass


# class ScanType(ScanTypeBase):
#     pass
