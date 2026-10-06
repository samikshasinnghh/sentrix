import uuid


def test_alerts_only_returns_high_and_critical(client, make_headers, seed_event):
    seed_event(severity="CRITICAL", risk_score=95)
    seed_event(severity="HIGH", risk_score=80)
    seed_event(severity="MEDIUM", risk_score=50)
    seed_event(severity="LOW", risk_score=10)

    r = client.get("/alerts", headers=make_headers("viewer"))
    assert r.status_code == 200
    assert len(r.json()) == 2
    assert {a["severity"] for a in r.json()} == {"CRITICAL", "HIGH"}


def test_alerts_severity_filter_is_case_insensitive(client, make_headers, seed_event):
    seed_event(severity="CRITICAL", risk_score=95)
    seed_event(severity="HIGH", risk_score=80)

    r = client.get("/alerts?severity=critical", headers=make_headers("viewer"))
    assert r.status_code == 200
    assert [a["severity"] for a in r.json()] == ["CRITICAL"]


def test_alerts_ordered_by_risk_score_descending(client, make_headers, seed_event):
    seed_event(severity="HIGH", risk_score=70)
    seed_event(severity="CRITICAL", risk_score=95)
    seed_event(severity="HIGH", risk_score=85)

    r = client.get("/alerts", headers=make_headers("viewer"))
    assert [a["risk_score"] for a in r.json()] == [95, 85, 70]


def test_paging_with_tied_scores_has_no_overlap_or_gaps(client, make_headers, seed_event):
    # Same score and timestamp for all five: only the event_id tiebreaker
    # keeps the page order stable.
    seeded = {seed_event(severity="HIGH", risk_score=80) for _ in range(5)}
    headers = make_headers("viewer")

    seen = []
    for offset in (0, 2, 4):
        r = client.get(f"/alerts?limit=2&offset={offset}", headers=headers)
        seen += [a["event_id"] for a in r.json()]

    assert len(seen) == 5
    assert set(seen) == seeded


def test_get_alert_by_id(client, make_headers, seed_event):
    event_id = seed_event(severity="HIGH", risk_score=80)
    r = client.get(f"/alerts/{event_id}", headers=make_headers("viewer"))
    assert r.status_code == 200
    assert r.json()["event_id"] == event_id


def test_get_alert_malformed_uuid_returns_404_not_500(client, make_headers):
    r = client.get("/alerts/not-a-uuid", headers=make_headers("viewer"))
    assert r.status_code == 404


def test_get_alert_unknown_uuid_returns_404(client, make_headers):
    r = client.get(f"/alerts/{uuid.uuid4()}", headers=make_headers("viewer"))
    assert r.status_code == 404