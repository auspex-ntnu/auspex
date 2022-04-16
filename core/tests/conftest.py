import pytest


@pytest.fixture(scope="session")
def cve_levels() -> list[str]:
    return ["low", "medium", "high", "critical"]
