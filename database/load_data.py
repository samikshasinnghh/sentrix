import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.utils.config import DATABASE_URL


def get_connection():
    return psycopg2.connect(DATABASE_URL)


def load_users(conn, df):
    users = df[["user_id", "role"]].drop_duplicates(subset=["user_id"])

    with conn.cursor() as cur:
        execute_values(
            cur,
            "INSERT INTO users (user_id, role) VALUES %s ON CONFLICT (user_id) DO NOTHING",
            users.values.tolist(),
        )
    conn.commit()
    print(f"Loaded {len(users)} unique users")


def load_security_events(conn, df):
    events = df[[
        "event_id", "user_id", "timestamp", "source_ip",
        "country", "action", "status", "is_privileged_action",
    ]]

    with conn.cursor() as cur:
        execute_values(
            cur,
            """INSERT INTO security_events
               (event_id, user_id, timestamp, source_ip, country, action, status, is_privileged_action)
               VALUES %s ON CONFLICT (event_id) DO NOTHING""",
            events.values.tolist(),
        )
    conn.commit()
    print(f"Loaded {len(events)} security events")


def load_risk_scores(conn, df):
    scores = df[[
        "event_id", "anomaly_score", "anomaly_score_normalized",
        "risk_score", "severity", "rules_triggered",
    ]]

    with conn.cursor() as cur:
        execute_values(
            cur,
            """INSERT INTO risk_scores
               (event_id, anomaly_score, anomaly_score_normalized, risk_score, severity, rules_triggered)
               VALUES %s ON CONFLICT (event_id) DO NOTHING""",
            scores.values.tolist(),
        )
    conn.commit()
    print(f"Loaded {len(scores)} risk scores")


def load_anomalies(conn, df):
    anomalies = df[["event_id", "is_attack", "attack_type"]]

    with conn.cursor() as cur:
        execute_values(
            cur,
            """INSERT INTO anomalies (event_id, is_attack, attack_type)
               VALUES %s ON CONFLICT (event_id) DO NOTHING""",
            anomalies.values.tolist(),
        )
    conn.commit()
    print(f"Loaded {len(anomalies)} anomaly records")


if __name__ == "__main__":
    df = pd.read_csv("data/processed/activity_scored.csv")
    df = df.where(pd.notnull(df), None)  # convert NaN to Python None for SQL NULL

    conn = get_connection()

    load_users(conn, df)
    load_security_events(conn, df)
    load_risk_scores(conn, df)
    load_anomalies(conn, df)

    conn.close()
    print("\nAll data loaded successfully.")