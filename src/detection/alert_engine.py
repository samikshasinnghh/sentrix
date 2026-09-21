import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import psycopg2
from src.utils.config import DATABASE_URL


def generate_alerts():
    conn = psycopg2.connect(DATABASE_URL)

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO alerts (event_id, severity, status)
            SELECT r.event_id, r.severity, 'OPEN'
            FROM risk_scores r
            WHERE r.severity IN ('HIGH', 'CRITICAL')
              AND NOT EXISTS (
                  SELECT 1 FROM alerts a WHERE a.event_id = r.event_id
              );
        """)
        new_alerts_count = cur.rowcount
        conn.commit()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM alerts;")
        total_alerts = cur.fetchone()[0]

    conn.close()

    return {"new_alerts_created": new_alerts_count, "total_alerts": total_alerts}


if __name__ == "__main__":
    result = generate_alerts()
    print(f"New alerts created: {result['new_alerts_created']}")
    print(f"Total alerts in table: {result['total_alerts']}")