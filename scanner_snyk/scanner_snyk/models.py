from typing import Any

from auspex_core.docker.models import ImageInfo
from pydantic import BaseModel


class ScanOptions(BaseModel):
    image: str
    base_vulns: bool = False  # remove default?
