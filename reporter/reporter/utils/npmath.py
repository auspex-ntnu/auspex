import numpy as np
from loguru import logger
from typing import Any, Callable, Iterable, Protocol, Union, overload
from numbers import Number
from numpy.typing import ArrayLike


from .._types import NumberType


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
    res = func(a)
    if np.isnan(res):
        logger.warning(
            f"{func.__name__}({repr(a)}) returned nan. Defaulting to {default}"
        )
        return default
    return float(res)
