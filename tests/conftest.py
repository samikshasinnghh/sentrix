import os
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import psycopg2
import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

ADMIN_URL = os.getenv("DATABASE_URL")
if not ADMIN_URL:
    raise RuntimeError("DATABASE_URL is not set; check your .env file")

TEST_DB_NAME = "sentrix_test"
TEST_DATABASE_URL = urlunparse(urlparse(ADMIN_URL)._replace(path=f"/{TEST_DB_NAME}"))

# Safety: the app must only ever see the test database.
assert TEST_DATABASE_URL.split("?")[0].endswith("_test")
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret")


@pytest.fixture(scope="session")
def test_db():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB_NAME};")
        cur.execute(f"CREATE DATABASE {TEST_DB_NAME};")
    admin.close()

    schema = (BASE_DIR / "database" / "schema.sql").read_text(
        encoding="utf-8", errors="replace"
    )
    conn = psycopg2.connect(TEST_DATABASE_URL)
    with conn.cursor() as cur:
        cur.execute(schema)
    conn.commit()
    conn.close()
    yield


@pytest.fixture
def clean_db(test_db):
    conn = psycopg2.connect(TEST_DATABASE_URL)
    with conn.cursor() as cur:
        cur.execute(
            "TRUNCATE alerts, anomalies, risk_scores, security_events, "
            "users, app_users RESTART IDENTITY CASCADE;"
        )
    conn.commit()
    conn.close()
    yield


@pytest.fixture
def client(clean_db):
    from backend.main import app
    return TestClient(app)


@pytest.fixture
def make_headers(client):
    def _make(role, username=None):
        username = username or f"{role}_test"
        client.post("/auth/register", json={
            "username": username, "password": "Passw0rd!test", "role": role,
        })
        r = client.post("/auth/login", data={
            "username": username, "password": "Passw0rd!test",
        })
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _make


@pytest.fixture
def seed_event(clean_db):
    """Insert one event + risk score + anomaly row; returns the event_id."""
    conn = psycopg2.connect(TEST_DATABASE_URL)

    def _seed(user_id="u1", severity="HIGH", risk_score=80.0,
              timestamp="2026-01-01 10:00:00", is_attack=True,
              attack_type="recon"):
        event_id = str(uuid.uuid4())
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (user_id, role) VALUES (%s, %s) "
                "ON CONFLICT (user_id) DO NOTHING;",
                [user_id, "engineer"],
            )
            cur.execute(
                "INSERT INTO security_events (event_id, user_id, timestamp, "
                "source_ip, country, action, status, is_privileged_action) "
                "VALUES (%s, %s, %s, '10.0.0.1', 'IN', 'login', 'success', false);",
                [event_id, user_id, timestamp],
            )
            cur.execute(
                "INSERT INTO risk_scores (event_id, anomaly_score, "
                "anomaly_score_normalized, risk_score, severity, rules_triggered) "
                "VALUES (%s, 0.5, 0.5, %s, %s, 0);",
                [event_id, risk_score, severity],
            )
            cur.execute(
                "INSERT INTO anomalies (event_id, is_attack, attack_type) "
                "VALUES (%s, %s, %s);",
                [event_id, is_attack, attack_type],
            )
        conn.commit()
        return event_id

    yield _seed
    conn.close()


@pytest.fixture
def db_query(clean_db):
    """Run a SELECT against the test database and return all rows."""
    def _query(sql, params=None):
        conn = psycopg2.connect(TEST_DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        finally:
            conn.close()
    return _query