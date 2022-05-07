# TODO: implement universal backoff decorator for all functions
from typing import Any, Callable, Final
from auspex_core.utils.backoff import on_backoff, on_giveup, HandlerDict
import backoff

MAX_RETRIES = 5  # type: Final[int]
ON_BACKOFF = on_backoff  # type: Final[Callable[[HandlerDict], None]]
ON_GIVEUP = on_giveup  # type: Final[Callable[[HandlerDict], None]]
