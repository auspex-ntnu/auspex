from fastapi.testclient import TestClient

from reporter.main import app

client = TestClient(app)


def test_generate_report() -> None:
    resp = client.post(
        "/report",
        json={
            "format": "latex",
            "document_id": "6yh6rPCX7hFgAgUIB2Wo",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
