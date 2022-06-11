from typing import Any

from auspex_core.docker.models import ImageInfo
from pydantic import BaseModel


class ScanIn(BaseModel):
    image: str
    backend: str = "snyk"
