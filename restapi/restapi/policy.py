# TODO: implement universal backoff decorator for all functions
from typing import Any, Callable, Final

import backoff
from auspex_core.utils.backoff import HandlerDict, on_backoff, on_giveup

MAX_RETRIES = 5  # type: Final[int]
ON_BACKOFF = on_backoff  # type: Final[Callable[[HandlerDict], None]]
ON_GIVEUP = on_giveup  # type: Final[Callable[[HandlerDict], None]]
