from typing import Any, Callable

from auspex_core.models.scan import ScanLog

from ..cve import *
from ..exceptions import InvalidBackend
from ..types.protocols import ScanType
from .snyk import *
from .snyk import parse_snyk_scan

ParseFunc = Callable[[ScanLog, dict[str, Any]], ScanType]

BACKENDS: dict[str, ParseFunc] = {
    "snyk": parse_snyk_scan,
}


def get_backend(backend: str) -> ParseFunc:
    """Get the backend parser function for the given backend."""
    try:
        return BACKENDS[backend]
    except KeyError:
        raise InvalidBackend(f"Backend {backend} not supported")
