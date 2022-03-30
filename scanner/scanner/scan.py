import asyncio

from loguru import logger

from .backends.snyk import run_snyk_scan
from .exceptions import UserAPIError
from .types import ScanResultsType

BACKENDS = {"snyk": run_snyk_scan}


async def scan_container(image: str, backend: str) -> ScanResultsType:
    """Scans a container image using the selected scanning backend."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do_scan_container, image, backend)


def _do_scan_container(image: str, backend: str) -> ScanResultsType:
    scan_func = BACKENDS.get(backend)
    if not scan_func:
        raise UserAPIError(f"Unknown container analysis backend: '{backend}'")
    logger.debug(f"Starting scan of image '{image}'")
    return scan_func(image)
