from fastapi.testclient import TestClient
import pytest

from reporter.main import app
from httpx import AsyncClient

# TODO: implement patching before running integraton tests


@pytest.mark.anyio
@pytest.mark.skip
async def test_generate_report() -> None:
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.post(
            "/reports",
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
            "/reports",
            json={
                "format": "latex",
                "document_id": "some_invalid_firestore_id",
            },
        )
        assert resp.status_code == 404
        assert "not found" in resp.text


@pytest.mark.anyio
@pytest.mark.skip
async def test_get_report() -> None:
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/reports/cCvih5GoS5ZTQV2GZN5G")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
