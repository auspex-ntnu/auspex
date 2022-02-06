from scanner.backends.snyk import SnykScanResults


def _get_scan() -> SnykScanResults:
    return SnykScanResults(stderr="", stdout="Ok!", returncode=0)


def _get_scan_error() -> SnykScanResults:
    return SnykScanResults(stderr="", stdout="Fail!", returncode=1)


def test_model_snykscanresults() -> None:
    # verify that we can instantiate the model
    assert _get_scan()


def test_snyk_model_error() -> None:
    s = _get_scan_error()
    assert not s.ok()
    assert s.returncode != 0
