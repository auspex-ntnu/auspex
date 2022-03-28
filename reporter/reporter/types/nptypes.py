from numbers import Number, Real
from typing import Any, Union

import numpy as np
from numpy.typing import NDArray

# Represents a single RGBA color used by Matplotlib
MplRGBAColor = NDArray[np.float64]  # shape: (4,)

# Any number type we can pass to numpy
# NOTE: why does list[float] and list[int] not pass as list[Union[Number, Real]]
NumberType = Union[Number, Real, np.number[Any], float, int]
