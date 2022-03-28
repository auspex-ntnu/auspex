import shutil
import subprocess
from subprocess import CalledProcessError, CompletedProcess
from functools import cache
from typing import Any
from loguru import logger

from pydantic import BaseModel, Field


DEFAULT_CMD = "snyk"


class SnykScanResults(BaseModel):
    image: str
    scan: str
    error: str
    backend: str = Field("snyk", const=True)
    process: CompletedProcess[str] = Field(..., exclude=True)

    class Config:
        arbitrary_types_allowed = True  # for CompletedProcess

    @classmethod
    def from_subprocess(
        cls, process: CompletedProcess[str], image: str
    ) -> "SnykScanResults":  # TODO: FIX ANNOTATION
        return cls(
            image=image,
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

        if self.process.returncode in [0, 1]:
            return True
        return False


def run_snyk_scan(image: str) -> SnykScanResults:
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
    p = subprocess.run(
        [snyk_exe, "container", "test", "--json", image],
        capture_output=True,
        text=True,
    )
    return SnykScanResults.from_subprocess(p, image)
