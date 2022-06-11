"""Unit tests that require mocking."""
import json
import os
from unittest.mock import Mock, patch

import pytest
from auspex_core.gcp.firestore import add_document
from auspex_core.models.scan import ScanLog
from google.cloud.firestore import DocumentSnapshot
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.async_document import AsyncDocumentReference
from hypothesis import given
from hypothesis import strategies as st

# Just mocking GCP services for now.
# Will be replaced with actual GCP services in the future.
# Source: https://stackoverflow.com/questions/57808461/how-to-mock-a-google-api-library-with-python-3-7-for-unit-testing

# FIXME: I don't know how to mock a GCP service.
# I used GitHub Copilot to generate a lot of the mocked services.
class MockDocumentReference(AsyncDocumentReference):
    def __init__(self, *path, **kwargs):
        # super().__init__(*path, **kwargs)
        # TODO: fix super() call
        self._path = path

    async def get(
        self, field=None, transaction=None, retry=None, timeout=None, **kwargs
    ):
        r = {
            "image_size_bytes": "12345",
            "layer_id": "12345",
            "media_type": "12345",
            "tag": ["12345"],
            "created": "12345",
            "uploaded": "12345",
            "digest": "12345",
            "image": "12345",
        }
        if field is None:
            return r
        else:
            return r[field]

    async def set(
        self, data, merge=False, transaction=None, retry=None, timeout=None, **kwargs
    ):
        pass


class MockCollectionReference(object):
    def __init__(self, *path: str, **kwargs):
        self.path = path
        self.documents = []  # type: list[MockDocumentReference]

    def add(self, *args, **kwargs):
        self.documents.append(args[0])

    def document(self, *args, **kwargs):
        return MockDocumentReference(self.path)


class MockFirestoreClient(AsyncClient):
    def collection(self, *collection_path: str):
        return MockCollectionReference(*collection_path)


# TODO: fix this patching. Not sure why it doesn't work.


@patch("google.cloud.firestore_v1.async_client.AsyncClient", MockFirestoreClient)
@given(st.builds(ScanLog))
@pytest.mark.asyncio
async def test_add_firestore_document(scan: ScanLog):
    """
    Test that the add_firestore_document function adds a document to the Firestore collection.
    """
    # FIXME: it is dubious how much of the code is actually tested here.
    os.putenv("GOOGLE_APPLICATION_CREDENTIALS", "test/test_credentials.json")
    doc = await add_document("auspex-scans", scan.dict())
    assert doc is not None
    assert isinstance(doc, AsyncDocumentReference)
    assert doc.id is not None
    d = await doc.get()  # type: DocumentSnapshot
    # TODO: this isn't mocking the interface accurately.
    # We need to do DocumentReference -> DocumentSnapshot -> dict
    # Right now, we're just doing DocumentReference -> dict
    assert d is not None
    for field in [
        "image",
        "image_size_bytes",
        "layer_id",
        "media_type",
        "tag",
        "created",
        "uploaded",
    ]:
        assert field in d
        assert await doc.get(field) is not None
