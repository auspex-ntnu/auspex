from typing import Any

from loguru import logger

MAX_LEN_ARGS = 250
MAX_LEN_KWARGS = 250


def on_backoff(details: dict[str, Any]) -> None:
    """Generic callback function that can be fired whenever a backoff is triggered."""
    args = str(details["args"])
    if len(args) > MAX_LEN_ARGS:
        args = args[:MAX_LEN_ARGS] + "..."
    kwargs = str(details["args"])
    if len(kwargs) > MAX_LEN_KWARGS:
        kwargs = kwargs[:MAX_LEN_KWARGS] + "..."
    logger.debug(
        (
            "Backoff triggered after {tries} tries calling function {target}"
            "with args {args} and kwargs {kwargs}"
        ).format(**details, args=args, kwargs=kwargs)
    )
