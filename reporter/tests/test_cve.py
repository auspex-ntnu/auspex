import datetime
from reporter.backends.cve import CVESeverity, DateDescription
import pytest

date_year = DateDescription(
    datetime.timedelta(days=365),
    "More than a year old.",
)

date_halfyear = DateDescription(
    datetime.timedelta(days=180),
    "More than half a year old.",
)


def test_DateDescription_gt() -> None:
    assert date_year > date_halfyear
    with pytest.raises(TypeError):
        assert date_year > 364


def test_DateDescription_ge() -> None:
    assert date_year >= date_halfyear
    with pytest.raises(TypeError):
        assert date_year >= 365


def test_DateDescription_lt() -> None:
    assert date_halfyear < date_year
    with pytest.raises(TypeError):
        assert date_year < 366


def test_DateDescription_le() -> None:
    assert date_halfyear <= date_year
    with pytest.raises(TypeError):
        assert date_year <= 365


def test_DateDescription_eq() -> None:
    assert date_year != date_halfyear
    assert date_year == date_year
    with pytest.raises(TypeError):
        assert date_year == 365


def test_CVESeverity(cve_levels: list[str]) -> None:
    # Test valid values (upper and lower-case + key access)
    for level in cve_levels:
        assert CVESeverity.get(level.lower()) != CVESeverity.UNDEFINED.value
        assert CVESeverity.get(level.upper()) != CVESeverity.UNDEFINED.value
        assert CVESeverity.get(level) == CVESeverity[level.upper()].value

    # Test invalid value
    assert CVESeverity.get("unknown_severity") == CVESeverity.UNDEFINED.value

    # Test invalid type
    assert CVESeverity.get(object()) == CVESeverity.UNDEFINED.value  # type: ignore
