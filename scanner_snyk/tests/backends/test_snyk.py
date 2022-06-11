from subprocess import CompletedProcess
from unittest.mock import Mock
from scanner.backends.snyk import SnykScanResults

command = "/usr/bin/snyk container test --json my-image"


def test_snykscanresults_ok() -> None:
    mockprocess = Mock(spec=CompletedProcess)
    mockprocess.returncode = 0
    scan = SnykScanResults(stdout="{'status': 'ok'}", stderr="", process=mockprocess)
    assert scan.process.returncode == 0
    assert scan.ok


def test_snykscanresults_error() -> None:
    mockprocess = Mock(spec=CompletedProcess)
    mockprocess.returncode = 2
    scan = SnykScanResults(stdout="", stderr="Fail!", process=mockprocess)
    assert scan.process.returncode != 0
    assert not scan.ok


def test_snykscanresults_1() -> None:
    """`Snyk container test` can have an exit code of 1, which is not an error.
    This test verifies that 1 is not treated as an error.

    See: SnykScanResults.ok
    """
    mockprocess = Mock(spec=CompletedProcess)
    mockprocess.returncode = 1
    scan = SnykScanResults(stdout="", stderr="Fail!", process=mockprocess)
    assert scan.ok
