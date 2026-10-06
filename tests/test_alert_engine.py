def _make_alert(client, make_headers, seed_event, db_query):
    """Seed one HIGH event, generate alerts, return (analyst headers, alert_id)."""
    seed_event(severity="HIGH", risk_score=80)
    headers = make_headers("analyst")
    client.post("/alerts/generate", headers=headers)
    alert_id = db_query("SELECT alert_id FROM alerts;")[0][0]
    return headers, alert_id


def test_generate_creates_alerts_only_for_high_and_critical(
    client, make_headers, seed_event
):
    seed_event(severity="CRITICAL", risk_score=95)
    seed_event(severity="HIGH", risk_score=80)
    seed_event(severity="MEDIUM", risk_score=50)
    seed_event(severity="LOW", risk_score=10)

    r = client.post("/alerts/generate", headers=make_headers("analyst"))
    assert r.status_code == 200
    assert r.json() == {"new_alerts_created": 2, "total_alerts": 2}


def test_generate_is_idempotent(client, make_headers, seed_event):
    seed_event(severity="HIGH", risk_score=80)
    headers = make_headers("analyst")

    first = client.post("/alerts/generate", headers=headers).json()
    second = client.post("/alerts/generate", headers=headers).json()

    assert first["new_alerts_created"] == 1
    assert second["new_alerts_created"] == 0
    assert second["total_alerts"] == 1


def test_generate_requires_analyst_or_admin(client, make_headers):
    assert client.post("/alerts/generate", headers=make_headers("viewer")).status_code == 403
    assert client.post("/alerts/generate").status_code == 401


def test_status_update_changes_the_alert(client, make_headers, seed_event, db_query):
    headers, alert_id = _make_alert(client, make_headers, seed_event, db_query)

    r = client.patch(f"/alerts/{alert_id}/status", json={"status": "RESOLVED"}, headers=headers)
    assert r.status_code == 200

    row = db_query("SELECT status FROM alerts WHERE alert_id = %s;", [alert_id])
    assert row[0][0] == "RESOLVED"


def test_status_update_rejects_invalid_status(client, make_headers, seed_event, db_query):
    headers, alert_id = _make_alert(client, make_headers, seed_event, db_query)
    r = client.patch(f"/alerts/{alert_id}/status", json={"status": "BANANA"}, headers=headers)
    assert r.status_code == 400


def test_status_update_unknown_alert_returns_404(client, make_headers):
    r = client.patch("/alerts/999999/status", json={"status": "RESOLVED"},
                     headers=make_headers("analyst"))
    assert r.status_code == 404


def test_viewer_cannot_update_alert_status(client, make_headers, seed_event, db_query):
    _, alert_id = _make_alert(client, make_headers, seed_event, db_query)
    r = client.patch(f"/alerts/{alert_id}/status", json={"status": "RESOLVED"},
                     headers=make_headers("viewer"))
    assert r.status_code == 403