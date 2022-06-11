from typing import Any
from auspex_core.docker.models import ImageInfo
from pydantic import BaseModel


class ScanOptions(BaseModel):
    image: str
    base_vulns: bool = False  # remove default?


class CompletedScan(BaseModel):
    image: ImageInfo
    backend: str
    scan: str

    def dict(self, *args, **kwargs) -> dict[str, Any]:
        # Instead of defining a custom JSON encoder, we just convert the
        # datetime objects to UNIX timestamps here.
        img = self.image.dict()
        img["uploaded"] = self.image.uploaded.timestamp()
        img["created"] = self.image.created.timestamp()
        return {
            "image": img,
            "backend": self.backend,
            "scan": self.scan,
        }
