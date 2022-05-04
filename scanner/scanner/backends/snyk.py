import shutil
import subprocess
from subprocess import CalledProcessError, CompletedProcess
from functools import cache
from typing import Any
from loguru import logger

from pydantic import BaseModel, Field

from ..config import AppConfig


DEFAULT_CMD = "snyk"


class SnykScanResults(BaseModel):
    scan: str
    error: str
    backend: str = Field("snyk", const=True)
    process: CompletedProcess[str] = Field(..., exclude=True)

    class Config:
        arbitrary_types_allowed = True  # for CompletedProcess

    @classmethod
    def from_subprocess(cls, process: CompletedProcess[str]) -> "SnykScanResults":
        return cls(
            scan=process.stdout,
            error=process.stderr,
            process=process,
        )

    @property
    def ok(self) -> bool:
        # Source: snyk container test --help
        # Exit codes
        # Possible exit codes and their meaning:
        # 0: success, no vulnerabilities found
        # 1: action_needed, vulnerabilities found
        # 2: failure, try to re-run command
        # 3: failure, no supported projects detected

        # TODO: replace with something more robust:

        # class SnykExitCode(Enum):
        #     SUCCESS = 0
        #     FAILURE = 1
        #     FAILURE_RERUN = 2
        #     FAILURE_NOT_SUPPORTED = 3

        if self.process.returncode in [0, 1]:
            return True
        return False


def run_snyk_scan(image: str) -> SnykScanResults:
    # TODO: support other container registries.
    # Currently only supports GCR
    snyk_exe = shutil.which("snyk")
    if not snyk_exe:
        logger.warning(
            "Unable to locate snyk executable. "
            "Program is either not in PATH or is not installed. "
            f"Attempting to use '{DEFAULT_CMD}'."
        )
        snyk_exe = DEFAULT_CMD

    # We use the --json option to pipe the results to stdout
    # and then read it directly into memory.
    snyk_cmd = f'{snyk_exe} container test --json --username=_json_key --password="$(cat {AppConfig().google_credentials})" {image}'
    logger.debug(f"Running snyk command: {snyk_cmd}")
    p = subprocess.run(
        # FIXME: is there a better way to use "$(cat <file>)" in a subprocess?
        # Ideally we would just want to run the Snyk binary directly
        ["/bin/bash", "-c", snyk_cmd],
        capture_output=True,
        text=True,
    )
    return SnykScanResults.from_subprocess(p)
