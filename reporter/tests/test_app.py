from fastapi.testclient import TestClient
import pytest

from reporter.main import app
from httpx import AsyncClient

# TODO: patch firestore client to return a mock


@pytest.mark.anyio
@pytest.mark.skip
async def test_generate_report() -> None:
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.post(
            "/report",
            json={
                "format": "latex",
                "document_id": "cCvih5GoS5ZTQV2GZN5G",
                # "collection": "auspex-scans-test",
            },
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"


@pytest.mark.anyio
@pytest.mark.skip
async def test_generate_report_invalid_id() -> None:
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.post(
            "/report",
            json={
                "format": "latex",
                "document_id": "some_invalid_firestore_id",
            },
        )
        assert resp.status_code == 404
        assert "not found" in resp.text
