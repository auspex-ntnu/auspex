from datetime import timedelta
from enum import Enum
from typing import Any, Callable, NamedTuple
import operator
from pydantic import BaseModel
from auspex_core.models.cve import CVETimeType


class DateDescription(NamedTuple):
    # Type checks for comparison methods are done inline for performance and readability
    # Methods bodies can be replaced with operator metaprogramming (but let's not)
    # Example of how it could be done:
    # def __gt__(self, other: object) -> bool:
    #     return self._cmp(other, operator.gt)
    # def _cmp(self, other: object, op: Callable[[Any, Any], bool]) -> bool:
    #     if not isinstance(other, DateDescription):
    #         raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
    #     return op(self.date, other.date)

    date: timedelta
    description: str

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date > other.date

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date >= other.date

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date < other.date

    def __le__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date <= other.date

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date == other.date


# # NOTE: subclass counter instead?
class UpgradabilityCounter(BaseModel):
    is_upgradable: int = 0
    not_upgradable: int = 0


DEFAULT_CVSS_TIMETYPE = CVETimeType.PUBLICATION_TIME

# NOTE: _Must_ be in descending order (high->low)
CVSS_DATE_BRACKETS = [
    DateDescription(timedelta(days=365), ">1 Year"),
    DateDescription(timedelta(days=180), ">180 days"),
    DateDescription(timedelta(days=90), ">90 days"),
    DateDescription(timedelta(days=30), ">30 days"),
    DateDescription(timedelta(days=0), "Last month"),
]
