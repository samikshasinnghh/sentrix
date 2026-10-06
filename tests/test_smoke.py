from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_root_is_running():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"status": "Sentrix API is running"}


def test_unknown_route_returns_404():
    assert client.get("/does-not-exist").status_code == 404


def test_metrics_records_requests_by_route():
    client.get("/")
    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.json()
    assert body["requests_total"] >= 1
    assert "GET / 200" in body["requests_by_route_status"]


def test_unknown_urls_are_grouped_as_unmatched():
    client.get("/random-1")
    client.get("/random-2")
    body = client.get("/metrics").json()
    assert body["requests_by_route_status"]["GET unmatched 404"] >= 2


def test_metrics_does_not_count_itself():
    client.get("/metrics")
    body = client.get("/metrics").json()
    assert not any("/metrics" in key for key in body["requests_by_route_status"])