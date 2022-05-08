from typing import Callable, Any
from ..types.protocols import ScanType
from .snyk import *
from ..cve import *
from auspex_core.models.scan import ScanLog
from .snyk import parse_snyk_scan
from ..exceptions import InvalidBackend

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
