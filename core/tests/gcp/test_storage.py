import json
from typing import Any
from unittest.mock import Mock, patch

import pytest
from auspex_core.gcp.storage import ObjectStatus, upload_json_blob_from_memory
from auspex_core.models.scan import ScanLog
from gcloud.aio.storage import Storage
from google.cloud import storage
from hypothesis import given
from hypothesis import strategies as st


class MockStorageClient(Storage):
    async def upload(  # type: ignore
        self, bucket: str, filename: str, contents: Any, **kwargs
    ) -> dict[str, Any]:
        return ObjectStatus(
            kind="storage#object",
            id="12345",
            selfLink="http://example.com/file.json",
            mediaLink="http://example.com/file.json",
            name=filename,
            bucket=bucket,
            generation="12345",
            metageneration="12345",
            contentType=kwargs.get("content_type", "application/json; charset=UTF-8"),
            storageClass="STANDARD",
            size="12345",
            md5Hash="12345",
            crc32c="12345",
            etag="12345",
            timeCreated="12345",
            updated="12345",
            timeStorageClassUpdated="12345",
        ).dict()


@patch("auspex_core.gcp.storage.StorageWithBackoff", MockStorageClient)
@pytest.mark.asyncio
async def test_upload_json_blob_from_memory() -> None:
    scan_contents = "{'foo': 'bar'}"
    filename = "test.json"
    bucket = "test-bucket"
    obj = await upload_json_blob_from_memory(scan_contents, filename, bucket)
    assert obj is not None
    assert obj.name == filename
    assert obj.bucket == bucket
