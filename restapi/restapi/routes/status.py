from functools import partial
from typing import Optional
import backoff

import httpx
from auspex_core.models.status import (
    ServiceStatus,
    ServiceStatusAggregate,
    ServiceStatusCode,
)
from fastapi import APIRouter
from loguru import logger

from ..config import AppConfig

from auspex_core.utils.backoff import on_giveup, on_backoff

router = APIRouter(prefix="/status", tags=["status"])


@router.get("/", response_model=ServiceStatusAggregate)
async def get_status() -> ServiceStatusAggregate:
    """Retrieves the status of all services."""
    services = {
        "scanner": AppConfig().url_scanner,
        "reporter": AppConfig().url_reporter,
        # BACKLOG: can we populate this dict automatically?
    }
    # TODO: use asyncio.gather to perform requests in parallel
    responses = {name: await get_service_status(url) for name, url in services.items()}
    return responses


@backoff.on_exception(
    backoff.expo,
    httpx.RequestError,
    max_tries=5,
    on_backoff=on_backoff,
    on_giveup=on_giveup,
)
async def get_service_status(url: str, timeout: Optional[float] = 300) -> ServiceStatus:
    """Get the status of a service.

    Parameters
    ----------
    url : `str`
        The URL of the service.
    timeout: `Optional[float]`
        The timeout for the request.

    Returns
    -------
    `ServiceStatus`
        The status of the service.
    """
    # bake in the URL of the service
    url = f"{url}/status"
    status = partial(ServiceStatus, url=url)
    async with httpx.AsyncClient(timeout=timeout) as client:
        # Guard against timeouts and other errors
        # Return a default "DOWN" status if the request fails
        try:
            res = await client.get(url)
            res.raise_for_status()
        except Exception as e:
            logger.error(f"Could not get status for {url}")
            logger.exception(e)
            return status(
                status=ServiceStatusCode.DOWN, message="Service is down or unreachable."
            )

        # Response was successful
        # Now try to parse its content
        try:
            return ServiceStatus(**(res.json()))
        except Exception as e:
            logger.error(f"Could not parse response: {res.text}")
            logger.exception(e)
            return status(
                status=ServiceStatusCode.ERROR,
                message="Could not parse response.",
            )
