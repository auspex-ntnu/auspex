import json
import asyncio
from .env import SERVICE_ACCOUNT_KEYFILE
from gcloud.aio.storage import Storage


def get_storage_client() -> Storage:
    return Storage(service_file=SERVICE_ACCOUNT_KEYFILE)


async def fetch_json_blob(bucket_name: str, blob_name: str) -> dict:    
    async with get_storage_client() as client:
        bucket = client.get_bucket(bucket_name)
        blob = await bucket.get_blob(blob_name)
        content = await blob.download()
    b = content.decode("utf-8") # NOTE: This blocks. Run in executor?
    # TODO: assert result of json.loads is a dict
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, json.loads, b)

