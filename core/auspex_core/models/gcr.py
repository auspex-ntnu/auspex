from datetime import datetime
from enum import Enum, auto
from typing import Any, NamedTuple, Optional, Union

from pydantic import BaseModel, Field, root_validator, validator

from ..utils.time import timestamp_ms_to_datetime


class CatalogResponse(BaseModel):
    """Represents the response to a docker repository catalog request.

    In our case: https://eu.gcr.io/v2/_catalog

    See: https://docs.docker.com/registry/spec/api/#listing-repositories
    """

    repositories: list[str]

    def get_repository(self, image: str) -> str:
        """Get the repository name for an image"""
        for repo in self.repositories:
            if repo in image:
                return repo
        raise ValueError(f"Image '{image}' not found in registry")


def _validate_imageinfo_ts(timestamp_ms: Union[str, int, datetime]) -> datetime:
    """Convert a timestamp (in milliseconds) to a datetime object"""
    # Hacks to make serializing to/from JSON str timestamps work

    # We already have a datetime object, so we don't need to convert
    if isinstance(timestamp_ms, datetime):
        return timestamp_ms
    # Treat string as ISO timestamp if string is not all digits
    elif isinstance(timestamp_ms, str) and not timestamp_ms.isdigit():
        return datetime.fromisoformat(timestamp_ms)
    # Fall back on treating as timestamp in milliseconds
    return timestamp_ms_to_datetime(timestamp_ms)


class ImageTimeMode(Enum):
    """Time mode for a Docker image"""

    CREATED = "created"
    UPLOADED = "uploaded"


class ImageInfo(BaseModel):
    """Represents information about a single Docker image."""

    image_size_bytes: str = Field(..., alias="imageSizeBytes")
    layer_id: str = Field(..., alias="layerId")
    media_type: str = Field(..., alias="mediaType")
    tag: list[str]
    created: datetime = Field(..., alias="timeCreatedMs")
    uploaded: datetime = Field(..., alias="timeUploadedMs")
    digest: Optional[str]  # injected by ImageManifest (see its root_validator)
    image: Optional[str]  # injected by get_image_info()
    # TODO: add name:tag used to reference this image

    # Parse the timestamps in milliseconds to datetime objects
    _validate_created = validator("created", pre=True, allow_reuse=True)(
        _validate_imageinfo_ts
    )
    _validate_uploaded = validator("uploaded", pre=True, allow_reuse=True)(
        _validate_imageinfo_ts
    )

    def get_timestamp(self, mode: ImageTimeMode = ImageTimeMode.CREATED) -> datetime:
        """Get the timestamp for the image in the given mode"""
        if mode == ImageTimeMode.CREATED:
            return self.created
        elif mode == ImageTimeMode.UPLOADED:
            return self.uploaded
        else:
            raise ValueError(f"Invalid mode '{mode}'")

    @classmethod
    def init_empty(cls) -> "ImageInfo":
        """Initialize an empty ImageInfo object"""
        return cls(
            image_size_bytes="",
            layer_id="",
            media_type="",
            tag=[],
            created=datetime.utcnow(),
            uploaded=datetime.utcnow(),
            digest=None,
            image=None,
        )

    class Config:
        # Allow population using both camelCase and snake_case
        allow_population_by_field_name = True


class ImageNameMode(Enum):
    """Name mode for a Docker image"""

    DIGEST = auto()
    TAG = auto()
    NONE = auto()


class ImageVersionInfo(NamedTuple):
    """Parameters for getting information about a Docker image version."""

    image: str
    mode: ImageNameMode
    tag_or_digest: Optional[str] = None
    delimiter: Optional[str] = None


class ImageManifest(BaseModel):
    """Represents the manifest for a Docker image."""

    __root__: dict[str, ImageInfo]

    @root_validator
    def inject_digest(
        cls, values: dict[str, dict[str, ImageInfo]]
    ) -> dict[str, dict[str, ImageInfo]]:
        """Inject the sha256 digest into the ImageInfo object"""
        # Each key is in the dictionary is the image's sha256 digest
        # We assign this value to the ImageInfo object's digest attribute
        for k, v in values["__root__"].items():
            v.digest = k
        return values

    def get_image_metadata(self, image_info: ImageVersionInfo) -> ImageInfo:
        """Get the metadata for an image"""
        # Try to find image by digest
        # Example: "repo/image@sha256:digest"
        if image_info.mode == ImageNameMode.DIGEST and image_info.tag_or_digest:
            img = self.__root__.get(image_info.tag_or_digest)
            if img is not None:
                return img

        # Try to find most recent image with the given tag
        # Example: "repo/image:tag"
        if image_info.mode == ImageNameMode.TAG:
            # create sorted list of images from most to least recent
            images = sorted(
                self.__root__.values(), key=lambda i: i.created, reverse=True
            )
            for img in images:
                if image_info.tag_or_digest in img.tag:
                    return img

        # Use latest image if no tag or digest
        # Example: "repo/image"
        if image_info.mode == ImageNameMode.NONE:
            for img in self.__root__.values():
                # TODO: verify that only one image can have the tag 'latest' at any given time
                if "latest" in img.tag:
                    return img

        raise ValueError(f"Image '{image_info.image}' not found in registry")

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
    """Represents the response to a docker repository tags request.

    In our case: "https://eu.gcr.io/v2/<project>/<image>/tags/list"

    See: https://docs.docker.com/registry/spec/api/#listing-image-tags
    """

    name: str
    tags: list[str]
    child: list[Any]
    manifest: ImageManifest
