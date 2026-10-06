def _event(user_id):
    return {
        "user_id": user_id,
        "timestamp": "2026-01-01T00:00:00",
        "source_ip": "10.0.0.1",
        "country": "IN",
        "action": "login",
        "status": "success",
        "is_privileged_action": False,
    }


def test_create_event_stores_row_without_scoring_it(
    client, make_headers, seed_event, db_query
):
    seed_event(user_id="u1")  # creates user u1
    r = client.post("/events", json=_event("u1"), headers=make_headers("analyst"))
    assert r.status_code == 201
    new_id = r.json()["event_id"]

    assert db_query("SELECT 1 FROM security_events WHERE event_id = %s;", [new_id])
    # Scoring is a separate batch process, so no risk score exists yet.
    assert db_query("SELECT 1 FROM risk_scores WHERE event_id = %s;", [new_id]) == []


def test_create_event_unknown_user_returns_400(client, make_headers):
    r = client.post("/events", json=_event("ghost"), headers=make_headers("admin"))
    assert r.status_code == 400