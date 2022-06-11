"""Module for reusable Pydantic validators."""

from typing import TypeVar

IntFloatT = TypeVar("IntFloatT", int, float)


def ensure_nonnegative(v: IntFloatT) -> IntFloatT:
    return abs(v)
