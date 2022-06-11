from enum import Enum

from pydantic import BaseModel


class CVSS(BaseModel):
    """Key CVSS metrics for a scanned container."""

    mean: float
    median: float
    stdev: float
    min: float
    max: float


class CVETimeType(Enum):
    CREATION_TIME = "creationTime"
    MODIFICATION_TIME = "modificationTime"
    PUBLICATION_TIME = "publicationTime"
    DISCLOSURE_TIME = "disclosureTime"


class CVESeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    UNDEFINED = 0

    @classmethod
    def get(cls, severity: str) -> int:
        """Returns the numeric value of a given severity.
        Defaults to UNDEFINED."""
        # Can omit this type checking for performance reasons.
        # Pydantic should guarantee severity is always a string.
        if not isinstance(severity, str):
            return cls.UNDEFINED.value
        return cls.__members__.get(severity.upper(), cls.UNDEFINED).value


# TODO: accomodate for future versions of CVSS where score range or severity levels change
CVSS_MIN_SCORE = 0.0
CVSS_MAX_SCORE = 10.0
SEVERITIES = ("low", "medium", "high", "critical")
