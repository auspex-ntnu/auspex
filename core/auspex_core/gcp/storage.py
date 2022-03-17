import asyncio
import json
from typing import Any, NamedTuple

from gcloud.aio.storage import Blob, Storage
from loguru import logger

from .env import SERVICE_ACCOUNT_KEYFILE


class StorageObject(NamedTuple):
    blob: Blob
    content: Any


def get_storage_client() -> Storage:
    return Storage(service_file=SERVICE_ACCOUNT_KEYFILE)


async def fetch_json_blob(bucket_name: str, blob_name: str) -> StorageObject:
    async with get_storage_client() as client:
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
