import json
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
    stdout: str
    stderr: str
    backend: str = Field("snyk", const=True)
    # WARNING: the command might include sensitive information such as credentials
    # DO NOT DISPLAY THIS TO USERS
    # It isn't part of the ScanResultsType interface for this reason
    command: str
    process: CompletedProcess[str] = Field(..., exclude=True)

    class Config:
        arbitrary_types_allowed = True  # for CompletedProcess

    @classmethod
    def from_subprocess(
        cls, process: CompletedProcess[str], command: str
    ) -> "SnykScanResults":
        return cls(
            stdout=process.stdout,
            stderr=process.stderr,
            process=process,
            command=command,
        )

    @property
    def scan(self) -> str:
        return self.stdout

    @property
    def error(self) -> dict[str, Any]:
        """Returns error message for scan (if any)."""

        def update_d(s: str, d: dict[str, Any]) -> dict[str, Any]:
            try:
                d.update(json.loads(s))
            except json.JSONDecodeError:
                pass
            return d

        d = {"error": self.stderr, "out": self.stdout, "message": ""}
        d = update_d(self.stderr, d)
        d = update_d(self.stdout, d)
        if self.process.returncode == 2 and "incorrect username" in self.stdout:
            d["message"] = (
                "NOTE: This error might be due to an invalid image name. "
                "Snyk does not report errors correctly when using custom username and password authentication. "
                "Please check your image name and try again."
            )
        return d

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
    return SnykScanResults.from_subprocess(p, command=snyk_cmd)
