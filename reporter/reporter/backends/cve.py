from datetime import timedelta
from enum import Enum
from typing import NamedTuple

from pydantic import BaseModel


class DateDescription(NamedTuple):
    date: timedelta
    description: str

    # inline duplicate type checks for performance and readability
    # Methods can be replaced with operator metaprogramming (but let's not)
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


class CVSSTimeType(Enum):
    CREATION_TIME = "creationTime"
    MODIFICATION_TIME = "modificationTime"
    PUBLICATION_TIME = "publicationTime"
    DISCLOSURE_TIME = "disclosureTime"


DEFAULT_CVSS_TIMETYPE = CVSSTimeType.CREATION_TIME

# NOTE: _Must_ be in descending order (high->low)
CVSS_DATE_BRACKETS = [
    DateDescription(timedelta(days=365), ">1 Year"),
    DateDescription(timedelta(days=180), ">180 days"),
    DateDescription(timedelta(days=90), ">90 days"),
    DateDescription(timedelta(days=30), ">30 days"),
    DateDescription(timedelta(days=0), "Last month"),
]


class CVESeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    UNDEFINED = 0

    @classmethod
    def get(cls, severity: str) -> int:
        # Can omit this type checking for performance reasons.
        # Pydantic should guarantee severity is always a string.
        if not isinstance(severity, str):
            return cls.UNDEFINED.value
        return cls.__members__.get(severity.upper(), cls.UNDEFINED).value


SEVERITIES = {
    "critical": 1,
    # skip 0 to avoid bugs due to falsey value in comparison
    "high": -1,
    "medium": -2,
    "low": -3,
}
