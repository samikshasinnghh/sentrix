EVENT = {
    "user_id": "u_does_not_exist",
    "timestamp": "2026-01-01T00:00:00",
    "source_ip": "10.0.0.1",
    "country": "IN",
    "action": "login",
    "status": "success",
    "is_privileged_action": False,
}


def _register(client, username="alice", password="Passw0rd!test", role="viewer"):
    return client.post("/auth/register", json={
        "username": username, "password": password, "role": role,
    })


def test_register_and_login_returns_token(client):
    assert _register(client).status_code == 201
    r = client.post("/auth/login", data={"username": "alice", "password": "Passw0rd!test"})
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"
    assert r.json()["access_token"]


def test_register_rejects_invalid_role(client):
    assert _register(client, role="superuser").status_code == 400


def test_register_rejects_duplicate_username(client):
    assert _register(client, role="admin").status_code == 201
    token = client.post(
        "/auth/login", data={"username": "alice", "password": "Passw0rd!test"}
    ).json()["access_token"]
    r = client.post("/auth/register", json={
        "username": "alice", "password": "Passw0rd!test", "role": "viewer",
    }, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400


def test_login_wrong_password_returns_401(client):
    _register(client)
    r = client.post("/auth/login", data={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user_returns_401(client):
    r = client.post("/auth/login", data={"username": "nobody", "password": "x"})
    assert r.status_code == 401


def test_protected_route_without_token_returns_401(client):
    assert client.get("/alerts").status_code == 401


def test_protected_route_with_garbage_token_returns_401(client):
    r = client.get("/alerts", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_valid_token_can_read_alerts(client, make_headers):
    r = client.get("/alerts", headers=make_headers("viewer"))
    assert r.status_code == 200
    assert r.json() == []


def test_viewer_cannot_create_event(client, make_headers):
    r = client.post("/events", json=EVENT, headers=make_headers("viewer"))
    assert r.status_code == 403


def test_analyst_passes_role_check_on_events(client, make_headers):
    r = client.post("/events", json=EVENT, headers=make_headers("analyst"))
    assert r.status_code == 400  # past the role check, rejected for unknown user


def _auth_headers(client, username):
    r = client.post("/auth/login", data={"username": username, "password": "Passw0rd!test"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_register_requires_login_after_first_user(client):
    assert _register(client, username="first", role="admin").status_code == 201
    assert _register(client, username="second").status_code == 401


def test_register_forbidden_for_non_admin(client):
    assert _register(client, username="boss", role="admin").status_code == 201
    admin = _auth_headers(client, "boss")
    client.post("/auth/register", json={
        "username": "reader", "password": "Passw0rd!test", "role": "viewer",
    }, headers=admin)
    r = client.post("/auth/register", json={
        "username": "other", "password": "Passw0rd!test", "role": "viewer",
    }, headers=_auth_headers(client, "reader"))
    assert r.status_code == 403


def test_admin_can_register_more_users(client):
    assert _register(client, username="boss", role="admin").status_code == 201
    r = client.post("/auth/register", json={
        "username": "analyst1", "password": "Passw0rd!test", "role": "analyst",
    }, headers=_auth_headers(client, "boss"))
    assert r.status_code == 201