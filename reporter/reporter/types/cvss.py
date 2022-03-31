from typing import NamedTuple


class CVSS(NamedTuple):
    mean: float
    median: float
    stdev: float
    min: float
    max: float
