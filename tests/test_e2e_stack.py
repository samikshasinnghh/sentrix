"""
End-to-end checks against the REAL running Docker stack.

Skipped unless E2E_BASE_URL is set, so a normal `pytest` run never touches it.
Read-only: logs in with an existing account and only calls GET endpoints.

    $env:E2E_BASE_URL = "http://localhost:8000"
    $env:E2E_USERNAME = "<existing username>"
    $env:E2E_PASSWORD = Read-Host "Password"
    pytest tests/test_e2e_stack.py -v
"""
import os
import subprocess

import httpx
import pytest

BASE_URL = os.getenv("E2E_BASE_URL")

pytestmark = pytest.mark.skipif(
    not BASE_URL,
    reason="set E2E_BASE_URL to run end-to-end tests against the Docker stack",
)

API_CONTAINER = "sentrix-api-1"


def _get(path, **kwargs):
    return httpx.get(f"{BASE_URL}{path}", timeout=10, **kwargs)


@pytest.fixture(scope="module")
def token():
    username = os.getenv("E2E_USERNAME")
    password = os.getenv("E2E_PASSWORD")
    if not username or not password:
        pytest.skip("set E2E_USERNAME and E2E_PASSWORD to run login-dependent checks")
    r = httpx.post(
        f"{BASE_URL}/auth/login",
        data={"username": username, "password": password},
        timeout=10,
    )
    assert r.status_code == 200, f"login failed with status {r.status_code}"
    return r.json()["access_token"]


def test_health_reports_database_up():
    r = _get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["database"] == "up"


def test_api_container_is_docker_healthy():
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", API_CONTAINER],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        pytest.skip("docker CLI not available")
    if result.returncode != 0:
        pytest.skip(f"container {API_CONTAINER} not found")
    assert result.stdout.strip() == "healthy"


def test_login_with_real_account_returns_token(token):
    assert token


def test_dashboard_stats_shows_loaded_data():
    r = _get("/dashboard/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] > 0
    assert "risk_distribution" in body


def test_alerts_returns_real_high_and_critical_alerts(token):
    r = _get("/alerts?limit=5", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    alerts = r.json()
    assert len(alerts) >= 1
    assert all(a["severity"] in {"HIGH", "CRITICAL"} for a in alerts)
    assert all(0 <= a["risk_score"] <= 100 for a in alerts)


def test_bad_token_is_rejected():
    r = _get("/alerts", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_metrics_reflect_real_traffic():
    _get("/health")
    body = _get("/metrics").json()
    assert body["requests_total"] > 0
    assert "GET /health 200" in body["requests_by_route_status"]