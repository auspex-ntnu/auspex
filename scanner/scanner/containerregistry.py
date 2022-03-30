# https://stackoverflow.com/questions/61465794/docker-sdk-with-google-container-registry

import asyncio
from enum import Enum, auto
import os
from datetime import datetime
from typing import Any, NamedTuple, Optional

import google.auth
import google.auth.transport.requests
import httpx
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials
from loguru import logger
from pydantic import BaseModel, Field, ValidationError, root_validator, validator

from .exceptions import APIError, UserAPIError


class CatalogResponse(BaseModel):
    repositories: list[str]

    def get_repository(self, image: str) -> str:
        """Get the repository name for an image"""
        for repo in self.repositories:
            if repo in image:
                return repo
        raise UserAPIError(f"Image '{image}' not found in registry")


def timestamp_ms_to_datetime(timestamp_ms: str) -> datetime:
    """Convert a timestamp in milliseconds to a datetime object"""
    ts = int(timestamp_ms) / 1000
    return datetime.fromtimestamp(ts)


class ImageInfo(BaseModel):
    image_size_bytes: str = Field(..., alias="imageSizeBytes")
    layer_id: str = Field(..., alias="layerId")
    mediaType: str = Field(..., alias="mediaType")
    tag: list[str]
    created: datetime = Field(..., alias="timeCreatedMs")
    uploaded: datetime = Field(..., alias="timeUploadedMs")
    digest: Optional[str]  # injected by us

    # Parse the timestamps in milliseconds to datetime objects
    _validate_created = validator("created", pre=True, allow_reuse=True)(
        timestamp_ms_to_datetime
    )
    _validate_uploaded = validator("uploaded", pre=True, allow_reuse=True)(
        timestamp_ms_to_datetime
    )


class ImageTimeMode(Enum):
    """Time mode for image"""

    CREATED = "created"
    UPLOADED = "uploaded"


class ImageNameMode(Enum):
    """Name mode for image"""

    DIGEST = auto()
    TAG = auto()
    NONE = auto()


class ImageVersionInfo(NamedTuple):
    image: str
    mode: ImageNameMode
    tag_or_digest: Optional[str] = None
    delimiter: Optional[str] = None


class ImageManifest(BaseModel):
    __root__: dict[str, ImageInfo]

    @root_validator
    def inject_digest(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Inject the digest into the image info"""
        for k, v in values["__root__"].items():
            v.digest = k
        return values

    def get_image_metadata(self, image_info: "ImageVersionInfo") -> ImageInfo:
        """Get the metadata for an image"""
        # Try to find image by digest
        if image_info.mode == ImageNameMode.DIGEST and image_info.tag_or_digest:
            img = self.__root__.get(image_info.tag_or_digest)
            if img is not None:
                return img

        # Try to find most recent image with the given tag
        if image_info.mode == ImageNameMode.TAG:
            # create sorted list of images from most to least recent
            images = sorted(
                self.__root__.values(), key=lambda i: i.created, reverse=True
            )
            for img in images:
                if image_info.tag_or_digest in img.tag:
                    return img

        # Use latest image if no tag or digest
        if image_info.mode == ImageNameMode.NONE:
            for img in self.__root__.values():
                if img.tag == "latest":
                    return img

        raise UserAPIError(f"Image '{image_info.image}' not found in registry")

    def get_newest_image(
        self, mode: ImageTimeMode = ImageTimeMode.UPLOADED
    ) -> ImageInfo:
        # TODO: delete method
        """Get the newest image in the manifest"""
        images = list(self.__root__.values())
        if mode == mode.CREATED:
            images.sort(key=lambda image: image.created)
        elif mode == mode.UPLOADED:
            images.sort(key=lambda image: image.uploaded)
        return images[-1]


class TagsResponse(BaseModel):
    name: str
    tags: list[str]
    child: list[Any]
    manifest: ImageManifest


async def get_image_info(image: str) -> ImageInfo:
    """Get information about a Container image from Google Container Registry"""
    resp = await get_repositories("ntnu-student-project")
    versioninfo = split_image_version(image)
    repo = resp.get_repository(image)

    # TODO: determine repository to search through

    credentials = await credentials_from_file()
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://eu.gcr.io/v2/ntnu-student-project/auspex/scanner/tags/list",
            auth=("_token", credentials.token),
        )

    try:
        tagsresp = TagsResponse.parse_obj(r.json())
    except ValidationError:
        logger.error(f"Failed to parse response from registry: {r.text}")
        raise APIError(f"Image '{image}' not found in registry")  # or?
    image_info = tagsresp.manifest.get_image_metadata(versioninfo)
    return image_info


# list repositories
async def get_repositories(project_id: str = None) -> CatalogResponse:
    """Get a list of repositories in a project."""
    credentials = await credentials_from_file()
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://eu.gcr.io/v2/_catalog", auth=("_token", credentials.token)
        )
        resp = CatalogResponse.parse_obj(r.json())
        return resp


async def credentials_from_file() -> Credentials:
    """Get credentials from a service account file and prime it with a token."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _do_credentials_from_file)


def _do_credentials_from_file() -> Credentials:
    """Get credentials from a service account file and prime it with a token."""
    # https://stackoverflow.com/a/67069710
    credentials = service_account.Credentials.from_service_account_file(
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)
    return credentials


def split_image_version(image: str) -> ImageVersionInfo:
    """Split image name and tag/digest from image name"""
    for c in ["@", ":"]:
        if c in image:
            image, tag_or_digest = image.split(c, maxsplit=1)
            mode = ImageNameMode.DIGEST if c == "@" else ImageNameMode.TAG
            return ImageVersionInfo(
                image=image,
                tag_or_digest=tag_or_digest,
                mode=mode,
                delimiter=c,
            )
    return ImageVersionInfo(image=image, mode=ImageNameMode.NONE)
