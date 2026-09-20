from typing import Optional
import uuid as uuid_lib
from fastapi import FastAPI, Depends, HTTPException
from backend.database import get_db_connection
from backend.schemas import AlertOut

app = FastAPI(
    title="Sentrix API",
    description="AI-powered cloud security monitoring platform",
    version="0.1.0",
)


@app.get("/")
def root():
    return {"status": "Sentrix API is running"}


@app.get("/health/db")
def health_check_db(conn=Depends(get_db_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) as count FROM users;")
        result = cur.fetchone()
    return {"database": "connected", "user_count": result["count"]}


@app.get("/dashboard/stats")
def dashboard_stats(conn=Depends(get_db_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) as total FROM security_events;")
        total_events = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM anomalies WHERE is_attack = true;")
        total_anomalies = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM risk_scores WHERE severity = 'HIGH';")
        high_risk = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM risk_scores WHERE severity = 'CRITICAL';")
        critical_alerts = cur.fetchone()["total"]

        cur.execute("""
            SELECT severity, COUNT(*) as count
            FROM risk_scores
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END;
        """)
        risk_distribution = cur.fetchall()

    return {
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "high_risk_events": high_risk,
        "critical_alerts": critical_alerts,
        "risk_distribution": risk_distribution,
    }


@app.get("/alerts", response_model=list[AlertOut])
def get_alerts(
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    conn=Depends(get_db_connection),
):
    query = """
        SELECT e.event_id, e.timestamp, e.user_id, e.action,
               r.risk_score, r.severity, a.attack_type
        FROM security_events e
        JOIN risk_scores r ON e.event_id = r.event_id
        JOIN anomalies a ON e.event_id = a.event_id
        WHERE r.severity IN ('HIGH', 'CRITICAL')
    """
    params = []

    if severity:
        query += " AND r.severity = %s"
        params.append(severity.upper())

    query += " ORDER BY r.risk_score DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    with conn.cursor() as cur:
        cur.execute(query, params)
        results = cur.fetchall()

    return results


@app.get("/alerts/{event_id}", response_model=AlertOut)
def get_alert_by_id(event_id: str, conn=Depends(get_db_connection)):
    try:
        uuid_lib.UUID(event_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Alert not found")

    query = """
        SELECT e.event_id, e.timestamp, e.user_id, e.action,
               r.risk_score, r.severity, a.attack_type
        FROM security_events e
        JOIN risk_scores r ON e.event_id = r.event_id
        JOIN anomalies a ON e.event_id = a.event_id
        WHERE e.event_id = %s
    """

    with conn.cursor() as cur:
        cur.execute(query, [event_id])
        result = cur.fetchone()

    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return result