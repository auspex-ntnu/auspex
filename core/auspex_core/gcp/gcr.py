"""Module defining Google Container Registry API functions."""

# https://stackoverflow.com/questions/61465794/docker-sdk-with-google-container-registry

import asyncio
import os

import google.auth
import google.auth.transport.requests
import httpx
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials
from loguru import logger
from pydantic import ValidationError

from ..models.gcr import (
    CatalogResponse,
    ImageInfo,
    ImageNameMode,
    TagsResponse,
    ImageVersionInfo,
)


def split_image_version(image: str) -> ImageVersionInfo:
    """Split name and tag/digest from an image name.

    Example:
        >>> split_image_version("gcr.io/ntnu-student-project/auspex:latest")
        ImageVersionInfo(
            image='gcr.io/ntnu-student-project/auspex',
            tag_or_digest='latest',
            mode=ImageNameMode.TAG,
            delimiter=":"
        )
    """
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


def get_registry(image_info: ImageVersionInfo) -> str:
    """Get the registry from an image name."""
    base_url = image_info.image.split("/")[0]
    supported = ["eu.gcr.io", "us.gcr.io", "docker.io"]
    if base_url in supported:
        return base_url
    # NOTE: what about gcr.io?
    return "docker.io"  # fall back on DockerHub URL (or?)



    Example:
        >>> get_image_info("gcr.io/ntnu-student-project/auspex:latest")
        ImageInfo(
            image_size_bytes='0',
            layer_id='',
            mediaType='application/vnd.docker.distribution.manifest.v2+json',
            tag=['latest'],
            created=datetime.datetime(2020, 4, 23, 14, 0, 0, tzinfo=tzutc()),
            uploaded=datetime.datetime(2020, 4, 23, 14, 0, 0, tzinfo=tzutc()),
            image_id='sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            image='gcr.io/ntnu-student-project/auspex'
        )
    """
    # resp = await get_repositories("ntnu-student-project")
    versioninfo = split_image_version(image)
    # repo = resp.get_repository(image)

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
        raise ValueError(f"Image '{image}' not found in registry")  # or?
    image_info = tagsresp.manifest.get_image_metadata(versioninfo)
    # inject the image name (without tag) into the image info
    image_info.image = versioninfo.image
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
    # TODO determine which project to use


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
