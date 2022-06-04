import json
import shutil
import subprocess
from subprocess import CompletedProcess
from typing import Any
from auspex_core.docker.models import ImageInfo
from auspex_core.models.api.scan import ScanRequest

import backoff
from auspex_core.utils.backoff import on_backoff, on_giveup
from loguru import logger
from pydantic import BaseModel, Field

from ..config import AppConfig

DEFAULT_CMD = "snyk"


class ECONNRESET_Exception(Exception):
    """Exception raised when Snyk CLI returns an ECONNRESET error."""


class SnykScanResults(BaseModel):
    stdout: str
    stderr: str
    backend: str = Field("snyk", const=True)
    # WARNING: the command (CompletedProcess.args) might include sensitive information such as credentials
    # DO NOT DISPLAY THIS TO USERS
    process: CompletedProcess[str] = Field(..., exclude=True)

    class Config:
        arbitrary_types_allowed = True  # for CompletedProcess

    @classmethod
    def from_subprocess(cls, process: CompletedProcess[str]) -> "SnykScanResults":
        return cls(
            stdout=process.stdout,
            stderr=process.stderr,
            process=process,
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


def get_snyk_exe() -> str:
    """Attempts to find the Snyk executable.

    Returns
    -------
    str
        Path to the Snyk executable.
    """
    snyk_exe = shutil.which("snyk")
    if snyk_exe:
        return snyk_exe
    logger.warning(
        "Unable to locate Snyk CLI executable. "
        "Program is either not in PATH or is not installed. "
        f"Attempting to use '{DEFAULT_CMD}'."
    )
    return DEFAULT_CMD


def get_snyk_cmd(image: ImageInfo, options: ScanRequest) -> str:
    """Returns the Snyk CLI command to run based on image and options.

    Parameters
    ----------
    image : `ImageInfo`
        The image to scan.
    options : `ScanRequest`
        The options for the scan.

    Returns
    -------
    `str`
        The Snyk CLI command to run.
    """
    snyk_exe = get_snyk_exe()

    # We use the --json option to pipe the results to stdout
    # and then read it directly into memory.
    cmd = f"{snyk_exe} container test --json "
    # TODO: decide authentication scheme based on image info + configured repos
    # TODO: replace with something more robust:
    if "gcr.io" in image.image:
        cmd += f'--username=_json_key --password="$(cat {AppConfig().google_credentials})" '
    if not options.base_vulns:
        cmd += "--exclude-base-image-vulns "
    # if options.app_vulns:
    #     cmd += "--app-vulns "
    cmd += image.image

    return cmd


@backoff.on_exception(
    backoff.expo,
    ECONNRESET_Exception,
    max_tries=5,
    on_backoff=on_backoff,
    on_giveup=on_giveup,
)
def run_snyk_scan(image: ImageInfo, options: ScanRequest) -> SnykScanResults:
    """Runs the Snyk CLI container scan.

    Parameters
    ----------
    image : `str`
        Image name to scan.

    Returns
    -------
    `SnykScanResults`
        Results of the scan.
    """
    snyk_cmd = get_snyk_cmd(image, options)

    # SECURITY RISK
    # This will leak the location of the credentials file but NOT its contents
    logger.debug(f"Running snyk command: {snyk_cmd}")

    p = subprocess.run(
        # FIXME: is there a better way to use "$(cat <file>)" in a subprocess?
        # Ideally we would just want to run the Snyk binary directly
        ["/bin/bash", "-c", snyk_cmd],
        capture_output=True,
        text=True,
    )
    snykscan = SnykScanResults.from_subprocess(p)
    if "ECONNRESET" in snykscan.stderr:
        logger.debug(
            f"Snyk CLI returned an ECONNRESET error. Rerunning scan of {image}."
        )
        raise ECONNRESET_Exception(snykscan.stderr)
    return snykscan
