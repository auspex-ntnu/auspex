from typing import Any, TypedDict

from loguru import logger

MAX_LEN_ARGS = 250
MAX_LEN_KWARGS = 250


class HandlerDict(TypedDict):
    """Dictionary of details for a backoff or giveup."""

    # TODO: implement better typing
    target: Any
    args: tuple[Any]
    kwargs: dict[str, Any]
    tries: int
    elapsed: float
    wait: float
    value: Any


def on_backoff(details: HandlerDict) -> None:
    """Generic callback function that can be fired whenever a backoff is triggered."""
    _log(
        (
            "Backoff triggered after {tries} tries calling function {target}"
            "with args {args} and kwargs {kwargs}"
        ),
        details,
    )


def on_giveup(details: HandlerDict) -> None:
    """Generic callback function that can be fired whenever a giveup is triggered."""
    _log(
        (
            "Gave up after {tries} tries calling function {target}"
            "with args {args} and kwargs {kwargs}"
        ),
        details,
    )


def _log(
    msg: str,
    details: HandlerDict,
) -> None:
    """Log the message with the given details."""
    args = _fmt_args(details)
    kwargs = _fmt_kwargs(details)
    logger.error(
        (msg).format(
            tries=details["tries"], target=details["target"], args=args, kwargs=kwargs
        )
    )


def _fmt_args(details: HandlerDict) -> str:
    """Format the args for logging."""
    args = str(details["args"])
    if len(args) > MAX_LEN_ARGS:
        args = args[:MAX_LEN_ARGS] + "..."
    return args


def _fmt_kwargs(details: HandlerDict) -> str:
    """Format the kwargs for logging."""
    kwargs = str(details["kwargs"])
    if len(kwargs) > MAX_LEN_KWARGS:
        kwargs = kwargs[:MAX_LEN_KWARGS] + "..."
    return kwargs
