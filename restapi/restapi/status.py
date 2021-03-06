from functools import partial
from typing import Optional

import httpx
from auspex_core.models.status import (
    ServiceStatus,
    ServiceStatusAggregate,
    ServiceStatusCode,
)
from loguru import logger


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
    status = partial(ServiceStatus, url=url)
    async with httpx.AsyncClient(timeout=timeout) as client:
        # Guard against timeouts and other errors
        # Return a default "DOWN" status if the request fails
        try:
            res = await client.get(f"{url}/status")
        except:
            return status(status=ServiceStatusCode.DOWN, message="Service is down.")

        # Response was successful
        # Now try to parse its content
        try:
            return ServiceStatus(**(res.json()))
        except Exception as e:
            logger.error(f"Could not parse response: {res.text}")
            return status(
                status=ServiceStatusCode.ERROR,
                message="Could not parse response.",
            )
