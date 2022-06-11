import httpx
from auspex_core.gcp.storage import ObjectStatus
from auspex_core.models.api.scan import ScanRequest
from auspex_core.models.scan import ScanLog
from fastapi.testclient import TestClient
from google.cloud.firestore_v1.async_document import AsyncDocumentReference
from pytest_mock import MockerFixture

from scanner.main import app

client = TestClient(app)


def test_backend_invalid():
    """Tests that POST /scans with an invalid backend returns a 400 error
    with the appropriate error message."""
    req = ScanRequest(
        images=["image1", "image2"],
        backend="some_invalid_backend",
    )
    response = client.post("/scans", json=req.dict())
    assert response.status_code == 400
    assert response.json() == {"detail": "Unknown backend: some_invalid_backend"}


def test_post_scans(mocker: MockerFixture):
    """Tests the POST /scans endpoint.

    The test mocks Snyk scanner, Cloud Storage and Firestore.
    """
    # Make the request body
    req_body = ScanRequest(
        images=["image1", "image2"],
        backend="snyk",
    )

    # Create the mock response from the backend scanning service
    mock_response = httpx.Response(
        status_code=200,
        json=dict(
            scan='{"id": "123", "backend": "snyk", "vulnerabilities": 0}',
            image=dict(
                image="image1",  # not dynamic
                image_size_bytes="123",
                layer_id="",
                media_type="some_type",
                tag=["latest", "test"],
                created="16548615552012",
                uploaded="16548615552012",
                digest="sha256:123",
            ),
            backend="snyk",
            error="",
            ok=True,
        ),
        request=httpx.Request(
            url="http://localhost:8080/scans",
            method="POST",
            headers={"Content-Type": "application/json"},
            json=req_body.dict(),
        ),
    )

    # Mock the backend scanning service
    mocker.patch("scanner.main.httpx.AsyncClient.post", return_value=mock_response)

    # Mock the Cloud Storage JSON blob upload
    mock_obj = mocker.Mock(
        spec=ObjectStatus, selfLink="http://blob.url", name="blob", bucket="bucket"
    )
    setattr(mock_obj, "name", "name")  # NOTE: why doesn't constructor work?
    mocker.patch(
        "scanner.db.upload_json_blob_from_memory",
        return_value=mock_obj,
    )

    # Mock Firestore document creation
    mocker.patch(
        "scanner.db.add_document",
        return_value=mocker.Mock(spec=AsyncDocumentReference, id="123"),
    )

    # Send the request
    response = client.post("/scans", json=req_body.dict())
    assert response.status_code == 200
    j = response.json()
    assert isinstance(j, list)
    assert len(j) == 2
    scans = [ScanLog.parse_obj(s) for s in j]
    for scan in scans:
        assert scan.backend == "snyk"
        assert scan.base_vulns == True
        assert scan.id == "123"
        # TODO: more assertions...
