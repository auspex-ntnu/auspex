import math
from reporter.utils import npmath


def test_mean() -> None:
    # TODO: add less trivial test inputs
    assert math.isclose(npmath.mean([1, 2, 3, 4, 5]), 3.0)
    assert math.isclose(npmath.mean([]), 0.0)
    assert math.isclose(npmath.mean([1, "2", 3]), 0.0)


def test_median() -> None:
    # TODO: add less trivial test inputs
    assert math.isclose(npmath.median([1, 2, 3, 4, 5]), 3.0)
    assert math.isclose(npmath.median([]), 0.0)
    assert math.isclose(npmath.median([1, "2", 3]), 0.0)


def test_stdev() -> None:
    # TODO: add less trivial test inputs
    assert math.isclose(npmath.stdev([1, 2, 3, 4, 5]), 1.4142135623730951)
    assert math.isclose(npmath.stdev([]), 0.0)
    assert math.isclose(npmath.stdev([1, "2", 3]), 0.0)
