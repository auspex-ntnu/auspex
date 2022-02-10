import docker
import asyncio
from loguru import logger

from .backends.snyk import run_snyk_scan
from .docker import pull_docker_image
from .exceptions import APIError
from .types import ScanResults

backends = {"snyk": run_snyk_scan}


async def scan_container(image: str, backend: str) -> ScanResults:
    """Scans a container image using the selected scanning backend."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _scan_container, image, backend)


def _scan_container(image: str, backend: str) -> ScanResults:
    # TODO: pull docker image, verify that it exists
    try:
        pull_docker_image(image)
    except docker.errors.APIError as e:
        raise APIError(e.explanation)

    scan_func = backends.get(backend)
    if not scan_func:
        raise APIError(f"Unknown container analysis backend: '{backend}'")

    logger.info(f"Starting scan of image '{image}'")
    return scan_func(image)
