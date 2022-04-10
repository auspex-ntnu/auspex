"""Unit tests that require mocking."""
import json
from unittest.mock import Mock, patch

from google.cloud import storage
from google.cloud.firestore import Client as FirestoreClient
from google.cloud.firestore import DocumentReference
from hypothesis import given
from hypothesis import strategies as st

import main

# Just mocking GCP services for now.
# Will be replaced with actual GCP services in the future.
# Source: https://stackoverflow.com/questions/57808461/how-to-mock-a-google-api-library-with-python-3-7-for-unit-testing

# FIXME: I don't know how to mock a GCP service.
# I used GitHub Copilot to generate a lot of the mocked services.
class MockDocumentReference(DocumentReference):
    def __init__(self, *path, **kwargs):
        # super().__init__(*path, **kwargs)
        # TODO: fix super() call
        self._path = path

    def get(self, field=None, transaction=None, retry=None, timeout=None, **kwargs):
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

    def set(
        self, data, merge=False, transaction=None, retry=None, timeout=None, **kwargs
    ):
        pass


class MockCollectionReference(object):
    def __init__(self, collection_path: str, *args, **kwargs):
        self.collection_path = collection_path
        self.documents = []

    def add(self, *args, **kwargs):
        self.documents.append(args[0])

    def document(self, *args, **kwargs):
        return MockDocumentReference(self.collection_path)


class MockFirestoreClient(FirestoreClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def collection(self, collection_path: str):
        return MockCollectionReference(collection_path)


@patch("google.cloud.firestore.Client", MockFirestoreClient)
@given(st.builds(main.Scan))
def test_add_firestore_document(scan: main.Scan):
    """
    Test that the add_firestore_document function adds a document to the Firestore collection.
    """
    # FIXME: it is dubious how much of the code is actually tested here.
    doc = main.add_firestore_document(scan)
    assert doc is not None
    assert isinstance(doc, DocumentReference)
    assert doc.id is not None
    assert doc.get() is not None
    for field in [
        "image",
        "image_size_bytes",
        "layer_id",
        "media_type",
        "tag",
        "created",
        "uploaded",
    ]:
        assert field in doc.get()
        assert doc.get(field) is not None


class MockStorageClient(storage.Client):
    def bucket(self, bucket_name: str):
        return MockBucket(self, bucket_name)


class MockBucket(storage.Bucket):
    def exists(self):
        return True

    def blob(self, blob_name: str):
        return MockBlob(blob_name, self)


class MockBlob(storage.Blob):
    @property
    def public_url(self):
        return "http://example.com/file.json"

    def upload_from_string(self, *args, **kwargs) -> None:
        pass


@patch("google.cloud.storage.Client", MockStorageClient)
def test_upload_json_blob_from_memory() -> None:
    scan_contents = "{'foo': 'bar'}"
    filename = "test.json"
    blob = main.upload_json_blob_from_memory(scan_contents, filename)
    assert blob is not None
    assert blob.name == filename
    # TODO: test for bucket.exists==False


@patch("google.cloud.storage.Client", MockStorageClient)
@patch("google.cloud.firestore.Client", MockFirestoreClient)
@given(st.builds(main.Scan))
def test_handle_request(scan: main.Scan) -> None:
    """
    Test that the handle_request function adds a document to the Firestore collection.
    """
    d = scan.dict()
    d["scan"] = "{'foo': 'bar'}"  # add JSON-encoded scan to dict
    req = Mock(json=d, method="POST")
    j, code = main.handle_request(req)
    assert j is not None
    assert json.loads(j)  # just check if it is valid json
    assert code == 201
