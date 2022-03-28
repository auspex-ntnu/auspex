from fastapi.testclient import TestClient
import pytest

from reporter.main import app

test_client = TestClient(app)


def test_generate_report() -> None:
    resp = test_client.post(
        "/report",
        json={
            "format": "latex",
            "document_id": "cCvih5GoS5ZTQV2GZN5G",
            "collection": "auspex-logs-test",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"


def test_generate_report_invalid_id() -> None:
    resp = test_client.post(
        "/report",
        json={
            "format": "latex",
            "document_id": "some_invalid_firestore_id",
            "collection": "auspex-logs-test",
        },
    )
    assert resp.status_code == 404
    assert "not found" in resp.text
