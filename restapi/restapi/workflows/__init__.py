import os
from typing import Type

from loguru import logger
from .gcp.runner import GCPRunner
from .azure.runner import AzureRunner
from .base import WorkflowRunner, WorkflowRunner

_RUNNERS: dict[str, Type[WorkflowRunner]] = {
    "gcp": GCPRunner,
    "azure": AzureRunner,
}
_DEFAULT_PLATFORM = "gcp"
_DEFAULT_RUNNER: WorkflowRunner = GCPRunner()  # default to GCP


def get_runner_default() -> WorkflowRunner:
    return _DEFAULT_RUNNER


def set_runner_default(runner: str) -> None:
    global _DEFAULT_RUNNER
    r = _RUNNERS.get(runner)
    if not r:
        raise ValueError("Unknown workflow runner platform.")
    _DEFAULT_RUNNER = r()
    logger.debug(f"Setting '{r}' as default workflow runner platform.")


def get_runner(platform: str = None) -> WorkflowRunner:
    if not platform:
        platform = determine_cloud_platform()
        logger.debug(f"Detected {platform} as workflow runner platform.")
    return _RUNNERS[platform]()


def determine_cloud_platform() -> str:
    # TODO: handle local deployments
    # User-injected env var takes precedence
    if p := os.getenv("CLOUD_PLATFORM"):
        if p in _RUNNERS:
            return p
        logger.warning(
            f"Unknown value for environment variable 'CLOUD_PLATFORM': {p}. "
            "Falling back on platform auto detection."
        )
    # Fall back on platform-injected env vars
    # TODO: find out if these are vars stable and not just implementation details we shouldn't rely on
    if os.getenv("GCP_PROJECT"):
        return "gcp"
    elif os.getenv("WEBSITE_SITE_NAME"):
        return "azure"
    return _DEFAULT_PLATFORM
