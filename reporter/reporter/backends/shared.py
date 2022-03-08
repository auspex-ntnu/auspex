from datetime import timedelta
from enum import Enum
from typing import NamedTuple

from pydantic import BaseModel


class DateDescription(NamedTuple):
    date: timedelta
    description: str

    # inline duplicate type checks for performance reasons
    def __gt__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date > other.date

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DateDescription):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        return self.date < other.date

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
