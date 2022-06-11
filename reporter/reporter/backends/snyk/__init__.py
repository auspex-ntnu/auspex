import time
from typing import Any

from auspex_core.models.scan import ScanLog

from .model import SnykContainerScan


def parse_snyk_scan(scan: ScanLog, raw_scan: dict[str, Any]) -> SnykContainerScan:
    """Parse a scan from the scanner service.

    Parameters
    ----------
    scan : `ScanLog`
        The scan metadata.
    raw_scan : `dict`
        The raw scan data from the scanner service.

    Returns
    -------
    `SnykContainerScan`
        The parsed scan.
    """
    # Generate a unique ID for the scan
    id = f"{scan.id}-{int(time.time())}"
    return SnykContainerScan(
        **raw_scan,
        id=id,
        image=scan.image,
    )
