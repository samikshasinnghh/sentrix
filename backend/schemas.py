from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class AlertOut(BaseModel):
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    risk_score: float
    severity: str
    attack_type: Optional[str] = None


class UserRiskOut(BaseModel):
    user_id: str
    role: str
    total_events: int
    total_flagged_attacks: int
    avg_risk_score: float
    max_risk_score: float
    recent_high_severity_events: list[AlertOut]