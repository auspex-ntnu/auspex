from typing import Any
import httpx


def get_metadata() -> dict[str, Any]:
    r = httpx.get(
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/metadata",
        headers={"Metadata-Flavor": "Google"},
    )
    return r.json()


def get_project_id() -> str:
    r = httpx.get(
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        headers={"Metadata-Flavor": "Google"},
    )
    return str(r.text)  # don't handle errors
