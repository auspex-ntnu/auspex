from typing import Any

from loguru import logger


def on_backoff(details: dict[str, Any]) -> None:
    """Generic callback function that can be fired whenever a backoff is triggered."""
    # Directly ripped off from https://github.com/litl/backoff#event-handlers
    logger.debug(
        "Backoff triggered after {tries} tries calling function {target} "
        "with args {args} and kwargs {kwargs}".format(**details)
    )
