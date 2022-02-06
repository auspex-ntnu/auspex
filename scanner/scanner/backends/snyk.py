import shutil
import subprocess
from subprocess import CalledProcessError, CompletedProcess
from functools import cache
from typing import Any

from ..types import ScanResults


class SnykScanResults(ScanResults):
    stdout: str
    stderr: str
    returncode: int
    _process: CompletedProcess

    @classmethod
    def from_subprocess(
        cls, process: CompletedProcess
    ) -> "SnykScanResults":  # TODO: FIX ANNOTATION
        return cls(
            stdout=process.stdout,
            stderr=process.stderr,
            returncode=process.returncode,
            _process=process,
        )

    def ok(self) -> bool:
        try:
            self._process.check_returncode()
        except CalledProcessError:
            return False
        return True

    def get_results(self) -> str:
        return self.stdout

    def get_error(self) -> str:
        return self.stderr


def run_snyk_scan(image_name: str) -> SnykScanResults:
    snyk_exe = shutil.which("snyk") or "snyk"
    # We don't use --json-file-output here because a successful scan
    # that finds vulnerabilities will return a non-zero exit code.
    # That makes checking for scan errors non-deterministic.
    # Instead we use the --json option to pipe the results to stdout.
    p = subprocess.run(
        [snyk_exe, "container", "test", "--json", image_name],
        capture_output=True,
    )
    return SnykScanResults.from_subprocess(p)
