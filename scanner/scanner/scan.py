import asyncio
from auspex_core.docker.models import ImageInfo
from auspex_core.models.api.scan import ScanRequest

from loguru import logger

from .backends.snyk import run_snyk_scan
from .exceptions import UserAPIError
from .types import ScanResultsType

BACKENDS = {"snyk": run_snyk_scan}


async def scan_container(image: ImageInfo, options: ScanRequest) -> ScanResultsType:
    """Scans a container image using the selected scanning backend."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do_scan_container, image, options)


def _do_scan_container(image: ImageInfo, options: ScanRequest) -> ScanResultsType:
    scan_func = BACKENDS.get(options.backend)
    if not scan_func:
        raise UserAPIError(f"Unknown container analysis backend: '{options.backend}'")
    logger.debug(f"Starting scan of image '{image.image}'")
    return scan_func(image, options)
