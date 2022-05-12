from abc import ABC, abstractmethod
from typing import Any, Protocol

from pydantic import BaseModel


class ScanResultsType(Protocol):
    """Abstract base class for scan results from any backend."""

    @property
    def ok(self) -> bool:
        """Returns success status of scan."""
        ...

    @property
    def scan(self) -> str:
        """Returns scan results as a JSON-encoded string."""
        ...

    @property
    def error(self) -> dict[str, Any]:
        """Returns error message for scan (if any)."""
        ...

    @property
    def backend(self) -> str:
        ...

    def dict(self, *args, **kwargs) -> dict[str, Any]:
        ...
