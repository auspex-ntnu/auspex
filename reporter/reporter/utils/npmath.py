import numpy as np
from loguru import logger
from typing import Any, Callable, Iterable

from ..types.nptypes import NumberType


def mean(a: Iterable[NumberType]) -> float:
    return _do_stats_math(np.mean, a)


def median(a: Iterable[NumberType]) -> float:
    return _do_stats_math(np.median, a)


def stdev(a: Iterable[NumberType]) -> float:
    return _do_stats_math(np.std, a)


def _do_stats_math(
    func: Callable[[Any], np.number[Any]],
    a: Iterable[NumberType],
    default: float = 0.0,
) -> float:
    """Wrapper function around numpy stats functions that handles exceptions and NaN."""
    try:
        res = func(a)
        if np.isnan(res):
            logger.warning(
                f"{func.__name__}({repr(a)}) returned nan. Defaulting to {default}"
            )
            return default
    except Exception as e:
        logger.error(f"{func.__name__}({repr(a)}) failed. Defaulting to {default}", e)
        return default
    return float(res)
