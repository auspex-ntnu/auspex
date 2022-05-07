from subprocess import CompletedProcess
from unittest.mock import Mock
from scanner.backends.snyk import SnykScanResults


def test_snykscanresults_ok() -> None:
    mockprocess = Mock(spec=CompletedProcess)
    mockprocess.returncode = 0
    scan = SnykScanResults(scan="{'status': 'ok'}", error="", process=mockprocess)
    assert scan.process.returncode == 0
    assert scan.ok


def test_snykscanresults_error() -> None:
    mockprocess = Mock(spec=CompletedProcess)
    mockprocess.returncode = 2
    scan = SnykScanResults(scan="", error="Fail!", process=mockprocess)
    assert scan.process.returncode != 0
    assert not scan.ok


def test_snykscanresults_1() -> None:
    """`Snyk container test` can have an exit code of 1, which is not an error.
    This test verifies that 1 is not treated as an error.

    See: SnykScanResults.ok
    """
    mockprocess = Mock(spec=CompletedProcess)
    mockprocess.returncode = 1
    scan = SnykScanResults(scan="", error="Fail!", process=mockprocess)
    assert scan.ok
