from abc import ABC, abstractmethod

from pydantic import BaseModel


class ScanResults(BaseModel, ABC):
    """Abstract base class for scan results from any backend."""

    @abstractmethod
    def ok(self) -> bool:
        """Returns success status of scan."""
        ...

    @abstractmethod
    def get_results(self) -> str:
        """Returns scan results as a JSON-encoded string."""
        ...

    @abstractmethod
    def get_error(self) -> str:
        """Returns error message for scan (if any)."""
        ...
