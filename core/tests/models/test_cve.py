from auspex_core.models.cve import CVESeverity


def test_CVESeverity(cve_levels: list[str]) -> None:
    # Test valid values (upper and lower-case + key access)
    for level in cve_levels:
        assert CVESeverity.get(level.lower()) != CVESeverity.UNDEFINED.value
        assert CVESeverity.get(level.upper()) != CVESeverity.UNDEFINED.value
        assert CVESeverity.get(level) == CVESeverity[level.upper()].value

    # Test invalid value
    assert CVESeverity.get("unknown_severity") == CVESeverity.UNDEFINED.value

    # Test invalid type
    assert CVESeverity.get(object()) == CVESeverity.UNDEFINED.value
