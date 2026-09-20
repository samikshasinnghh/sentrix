from typing import Optional
import uuid as uuid_lib
from fastapi import FastAPI, Depends, HTTPException
from backend.database import get_db_connection
from backend.schemas import (
    AlertOut, UserRiskOut, EventIn,
    UserRegisterIn, UserLoginIn, TokenOut,
)
from backend.auth import hash_password, verify_password, create_access_token

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


@app.get("/users/{user_id}/risk", response_model=UserRiskOut)
def get_user_risk(user_id: str, conn=Depends(get_db_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT user_id, role FROM users WHERE user_id = %s;", [user_id])
        user = cur.fetchone()

        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        cur.execute("""
            SELECT COUNT(*) as total,
                   AVG(r.risk_score) as avg_score,
                   MAX(r.risk_score) as max_score
            FROM security_events e
            JOIN risk_scores r ON e.event_id = r.event_id
            WHERE e.user_id = %s;
        """, [user_id])
        stats = cur.fetchone()

        cur.execute("""
            SELECT COUNT(*) as total
            FROM security_events e
            JOIN anomalies a ON e.event_id = a.event_id
            WHERE e.user_id = %s AND a.is_attack = true;
        """, [user_id])
        attack_count = cur.fetchone()["total"]

        cur.execute("""
            SELECT e.event_id, e.timestamp, e.user_id, e.action,
                   r.risk_score, r.severity, a.attack_type
            FROM security_events e
            JOIN risk_scores r ON e.event_id = r.event_id
            JOIN anomalies a ON e.event_id = a.event_id
            WHERE e.user_id = %s AND r.severity IN ('HIGH', 'CRITICAL')
            ORDER BY e.timestamp DESC
            LIMIT 5;
        """, [user_id])
        recent_events = cur.fetchall()

    return {
        "user_id": user["user_id"],
        "role": user["role"],
        "total_events": stats["total"],
        "total_flagged_attacks": attack_count,
        "avg_risk_score": round(float(stats["avg_score"]), 2) if stats["avg_score"] else 0.0,
        "max_risk_score": float(stats["max_score"]) if stats["max_score"] else 0.0,
        "recent_high_severity_events": recent_events,
    }


@app.post("/events", status_code=201)
def create_event(event: EventIn, conn=Depends(get_db_connection)):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE user_id = %s;", [event.user_id])
        if cur.fetchone() is None:
            raise HTTPException(status_code=400, detail=f"Unknown user_id: {event.user_id}")

        new_event_id = str(uuid_lib.uuid4())

        cur.execute("""
            INSERT INTO security_events
            (event_id, user_id, timestamp, source_ip, country, action, status, is_privileged_action)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """, [
            new_event_id, event.user_id, event.timestamp, event.source_ip,
            event.country, event.action, event.status, event.is_privileged_action,
        ])
        conn.commit()

    return {
        "event_id": new_event_id,
        "status": "created",
        "note": "Event ingested. Risk scoring is a separate batch process (see Phase 6/7 pipeline) and has not yet been computed for this event.",
    }


@app.post("/auth/register", status_code=201)
def register(user: UserRegisterIn, conn=Depends(get_db_connection)):
    if user.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM app_users WHERE username = %s;", [user.username])
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Username already exists")

        hashed = hash_password(user.password)
        cur.execute(
            "INSERT INTO app_users (username, password_hash, role) VALUES (%s, %s, %s);",
            [user.username, hashed, user.role],
        )
        conn.commit()

    return {"status": "registered", "username": user.username, "role": user.role}


@app.post("/auth/login", response_model=TokenOut)
def login(credentials: UserLoginIn, conn=Depends(get_db_connection)):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT username, password_hash, role FROM app_users WHERE username = %s;",
            [credentials.username],
        )
        user = cur.fetchone()

    if user is None or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_access_token(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer"}