"""Module defining Google Container Registry API functions."""

# https://stackoverflow.com/questions/61465794/docker-sdk-with-google-container-registry

import asyncio
import os
import time
from typing import Any, Optional, Union

import google.auth
import google.auth.transport.requests
import httpx
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials
from loguru import logger
from pydantic import ValidationError

from .exceptions import RegistryError, TagsError
from .models import (
    CatalogResponse,
    ImageInfo,
    ImageNameMode,
    ImageVersionInfo,
    TagsResponse,
)

GCR_REGISTRIES = ["gcr.io", "eu.gcr.io", "us.gcr.io", "asia.gcr.io"]
DOCKER_REGISTRIES = ["docker.io", "registry.hub.docker.com"]
SUPPORTED_REGISTRIES = GCR_REGISTRIES + DOCKER_REGISTRIES
DEFAULT_REGISTRY = "docker.io"


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


def get_registry_name(image_info: ImageVersionInfo) -> str:
    """Get the registry name from an image name."""
    base_url = image_info.image.split("/")[0]
    if base_url in SUPPORTED_REGISTRIES:
        return base_url
    # NOTE: what about gcr.io?
    return DEFAULT_REGISTRY  # fall back on DockerHub URL (or?)


async def get_image_info(image: str, project: str) -> ImageInfo:
    """Get information about a container image.

    Example:
        >>> get_image_info("gcr.io/ntnu-student-project/auspex:latest")
        ImageInfo(
            image_size_bytes='0',
            layer_id='',
            media_type='application/vnd.docker.distribution.manifest.v2+json',
            tag=['latest'],
            created=datetime.datetime(2020, 4, 23, 14, 0, 0, tzinfo=tzutc()),
            uploaded=datetime.datetime(2020, 4, 23, 14, 0, 0, tzinfo=tzutc()),
            image_id='sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            image='gcr.io/ntnu-student-project/auspex'
        )
    """
    # Determine image version (tag or digest) from its name
    versioninfo = split_image_version(image)

    # Given the image's name, we can find its registry
    registry = get_registry_name(versioninfo)

    # TODO: add support for other registries
    # Right now we just mock docker.io and return early
    if registry in DOCKER_REGISTRIES:
        return mock_dockerhub_imageinfo(versioninfo)
    return await _get_gcr_image_info(image, project, registry, versioninfo)


async def _get_gcr_image_info(
    image: str, project: str, registry: str, versioninfo: ImageVersionInfo
) -> ImageInfo:
    imgpath = get_image_path(versioninfo.image, project, registry)

    if registry in GCR_REGISTRIES:
        credentials = await get_gcr_token()
    else:
        credentials = None

    url = f"https://{registry}/v2/{project}/{imgpath}/tags/list"
    logger.debug("Fetching image info from {}", url)
    async with httpx.AsyncClient() as client:
        r = await client.get(url, auth=credentials)

    if not r.is_success:
        logger.error(
            f"Failed to get image info for {image}. "
            f"Status code: {r.status_code} "
            f"Response: {r.text}"
        )
        raise RegistryError(f"Failed to get image info for {image}")

    try:
        tagsresp = TagsResponse.parse_obj(r.json())
    except ValidationError:
        logger.error(f"Failed to parse response from registry: {r.text}")
        raise TagsError(f"Failed to parse response from image registry for '{image}'")

    # Parse tags response and retrieve image info
    image_info = tagsresp.manifest.get_image_metadata(versioninfo)

    # inject the image name (without tag) into the image info
    # TODO: this needs a lot of testing. This whole function should be refactored.
    if registry not in versioninfo.image or project not in versioninfo.image:
        image_info.image = (
            f"{registry.strip('/')}/{project.strip('/')}/{imgpath.strip('/')}"
        )
    else:
        image_info.image = versioninfo.image
    return image_info


def get_image_path(image: str, project: str, registry: str) -> str:
    """Get the image part of a path to an image in a container registry.

    Example:
        >>> _get_image_path("gcr.io/ntnu-student-project/auspex/scanner", "ntnu-student-project", "gcr.io")
        'auspex/scanner'


    Parameters
    ----------
    image : `str`
        Full name of the image (possibly including its registry and/or project)
    project : `str`
        Name of the project the image belongs to.
    registry : `str`
        Name of the registry the image belongs to.

    Returns
    -------
    `str`
        URL path segment for the image.
    """
    if registry in image:
        imgpath = image.split(registry, maxsplit=1)[1]
    if project in imgpath:
        image = image.split(project, maxsplit=1)[1]
    return image.strip("/")  # remove leading and trailing slashes


def mock_dockerhub_imageinfo(versioninfo: ImageVersionInfo) -> ImageInfo:
    """Mock image info for dockerhub. This is a hack to 'support' Dockerhub images."""

    # TODO: find a way to pull this information from DockerHub

    if versioninfo.mode == ImageNameMode.TAG and versioninfo.tag_or_digest is not None:
        tag = versioninfo.tag_or_digest
    else:
        tag = ""

    if "docker.io" not in versioninfo.image:
        image = f"docker.io/{versioninfo.image}"
    else:
        image = versioninfo.image

    return ImageInfo(
        image_size_bytes="0",
        layer_id="",
        media_type="application/vnd.docker.distribution.manifest.v2+json",
        tag=[tag],
        created=time.time() * 1000,  # type: ignore
        uploaded=time.time() * 1000,  # type: ignore
        image=image,
    )


# list repositories
async def get_repos_in_registry(
    registry: str, exclude: Optional[list[str]] = None
) -> list[str]:
    """Get a list of image repositories in a registry."""
    if exclude is None:
        exclude = []
    # TODO: support other container registries apart from gcr.io
    if any(x in registry for x in GCR_REGISTRIES):
        return await _get_repositories_gcr(registry, exclude)
        # TODO: filter by tags as well
        #       We can only assume :latest is safe to use as a tag
        #       for all images in the registry if we don't invidually check
    raise NotImplementedError(f"Listing repositories for {registry} is not supported.")


async def _get_repositories_gcr(registry: str, exclude: list[str]) -> list[str]:
    credentials = await get_gcr_token()
    reg = registry.split("/")[0]
    assert reg in GCR_REGISTRIES, f"Unknown registry: {reg}"
    async with httpx.AsyncClient() as client:
        # TODO: use appropriate endpoint for gcr.io
        r = await client.get(f"https://{reg}/v2/_catalog", auth=credentials)
        resp = CatalogResponse.parse_obj(r.json())
        # exclude = ["/gcf/", "cache"] will match all repos containing "/gcf/" or "cache"
        repos = [
            # The catalog response strips the top-level registry name (gcr.io)
            # so we have to add it back in here
            f"{reg}/{repo}"
            for repo in resp.repositories
            if not any(x in repo for x in exclude)
        ]
        # BACKLOG: add RepositoryInfo type instead of returning strings
        return repos


async def get_gcr_token() -> tuple[str, Union[bytes, Any]]:
    """Get credentials from a service account file and prime it with a token."""
    # TODO: REWRITE TO SUPPORT MULTIPLE SERVICE ACCOUNTS
    loop = asyncio.get_event_loop()
    credentials_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    credentials = await loop.run_in_executor(
        None, _get_gcr_credentials, credentials_file
    )
    return ("_token", credentials.token)  # only return the token from the credentials


def _get_gcr_credentials(credentials_file: Optional[str]) -> Credentials:
    """Get credentials (optionally from a service account file) and prime it with a token."""
    # https://stackoverflow.com/a/67069710
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    if credentials_file:
        credentials = service_account.Credentials.from_service_account_file(
            credentials_file, scopes=scopes
        )
    else:
        credentials, _ = google.auth.default(scopes=scopes)

    # Create the request object and generate a token
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)
    return credentials
