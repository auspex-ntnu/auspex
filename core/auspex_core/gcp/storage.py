import asyncio
import json
import os
from pathlib import Path
from typing import Any, NamedTuple, Optional
import aiohttp
import backoff


from google.cloud import storage
from google.cloud.storage import Bucket
from gcloud.aio.storage import Blob, Storage
from loguru import logger
from pydantic import BaseModel
from sanitize_filename import sanitize


class StorageObject(NamedTuple):
    blob: Blob
    content: Any


class StorageWithBackoff(Storage):
    """Inspired by https://github.com/talkiq/gcloud-aio/blob/master/storage/README.rst#customization

    Async Google Cloud Storage client with backoff implemented for retrying failed requests.
    """

    @backoff.on_exception(
        backoff.expo,
        aiohttp.ClientResponseError,
        max_tries=5,  # FIXME: make this configurable (retry policy)
        jitter=backoff.full_jitter,
    )
    async def copy(self, *args: Any, **kwargs: Any):
        return await super().copy(*args, **kwargs)

    @backoff.on_exception(
        backoff.expo,
        aiohttp.ClientResponseError,
        max_tries=5,
        jitter=backoff.full_jitter,
    )
    async def upload(self, *args: Any, **kwargs: Any):
        return await super().upload(*args, **kwargs)

    @backoff.on_exception(
        backoff.expo,
        aiohttp.ClientResponseError,
        max_tries=10,
        jitter=backoff.full_jitter,
    )
    async def download(self, *args: Any, **kwargs: Any):
        return await super().download(*args, **kwargs)

    @backoff.on_exception(
        backoff.expo,
        aiohttp.ClientResponseError,
        max_tries=10,
        jitter=backoff.full_jitter,
    )
    async def delete(self, *args: Any, **kwargs: Any):
        return await super().delete(*args, **kwargs)


def get_storage_client(service_file: Optional[str]) -> StorageWithBackoff:
    """Returns a Google Cloud Storage client."""
    return StorageWithBackoff(service_file=service_file)


async def fetch_json_blob(
    bucket_name: str, blob_name: str, service_file: Optional[str] = None
) -> StorageObject:
    """Fetches a JSON blob from the given bucket.

    Returns a StorageObject with the blob and the parsed JSON content.
    """
    if not service_file:
        service_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    async with get_storage_client(service_file) as client:
        # TODO: handle missing bucket
        bucket = client.get_bucket(bucket_name)
        blob = await bucket.get_blob(blob_name)
        content = await blob.download()

    # Decode content as UTF-8
    b = content.decode("utf-8")  # NOTE: This blocks. Run in executor?

    loop = asyncio.get_event_loop()
    try:
        json_content = await loop.run_in_executor(None, json.loads, b)
    except Exception as e:
        id = getattr(
            blob, "id", None
        )  # gcloud-aio doesn't guarantee that the id attribute is available (?)
        logger.exception(
            f"Unable to deserialize JSON content of blob with name '{blob.name}' and ID '{id}'",
            e,
        )
        raise
    return StorageObject(blob=blob, content=json_content)


# TODO: add backoff?
async def upload_file_to_bucket(
    path: Path, bucket_name: str, service_file: Optional[str] = None
) -> "ObjectStatus":
    """Uploads a file to the given bucket.

    Returns the metadata of the uploaded blob.
    """
    if not service_file:
        service_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    # TODO: don't nest try/excepts
    # TODO: refactor. Handle exceptions with backoff.
    # TODO: Don't create bucket here. Create bucket in startup script.

    try:
        async with get_storage_client(service_file) as client:

            try:
                # Check if bucket exists
                bucket = client.get_bucket(bucket_name)
                await bucket.get_metadata()
            except aiohttp.ClientResponseError as e:
                if e.code != 404:
                    raise
                # Create bucket if it doesn't exist
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, create_bucket, bucket_name)

            status = await client.upload_from_filename(
                bucket_name, path.name, str(path)
            )
            logger.debug(status)
            logger.debug(f"Uploaded file {path} to bucket {bucket_name}")
    # catch errors
    except Exception as e:
        logger.exception(f"Unable to upload file {path} to bucket {bucket_name}", e)
        raise

    # TODO: investigate if it's safe to use .construct() here
    return ObjectStatus.construct(**status)


async def upload_json_blob_from_memory(
    scan_contents: str,
    filename: str,
    bucket: str,
    credentials_file: Optional[str] = None,
    content_type: str = "application/json; charset=UTF-8",
) -> "ObjectStatus":
    """Uploads a file to the bucket."""
    async with get_storage_client(credentials_file) as client:
        # Upload file with .json suffix
        if not filename.endswith(".json"):
            filename = f"{filename}.json"
        filename = sanitize(filename)

        st = await client.upload(
            bucket,
            filename,
            scan_contents,
            content_type=content_type,
        )

        status = ObjectStatus.construct(**st)
        logger.debug(f"{status.mediaLink} uploaded to {bucket}.")
        return status


def create_bucket(bucket_name: str) -> Bucket:
    """Blocking function that creates a bucket with the given name.

    Uses the default project ID.
    """

    logger.info(f"Creating bucket {bucket_name}")
    # gcloud.aio.storage.Storage doesn't support creating buckets (it seems)
    client = storage.Client()
    bucket = client.create_bucket(bucket_name)
    logger.info(f"Created bucket {bucket_name}")
    return bucket


class ObjectStatus(BaseModel):
    # BACKLOG: investigate which fields can be cast to int/float/datetime
    kind: str
    id: str
    selfLink: str
    mediaLink: str
    name: str
    bucket: str
    generation: str
    metageneration: str
    contentType: str
    storageClass: str
    size: str
    md5Hash: str
    crc32c: str
    etag: str
    timeCreated: str
    updated: str
    timeStorageClassUpdated: str
