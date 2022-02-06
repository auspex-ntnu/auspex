__version__ = "0.1.0"


from .backends.snyk import run_snyk_scan
from .types import ScanResults
from .docker import pull_docker_image
import docker
from .exceptions import APIError

backends = {"snyk": run_snyk_scan}


def scan_container(image_name: str, backend: str = "snyk") -> ScanResults:
    # TODO: pull docker image, verify that it exists
    try:
        pull_docker_image(image_name)
    except docker.errors.APIError as e:
        raise APIError(e.explanation)

    scan_func = backends.get(backend)
    if not scan_func:
        raise APIError(f"Unknown container analysis backend: '{backend}'")
    return scan_func(image_name)
