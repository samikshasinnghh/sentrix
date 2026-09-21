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


class EventIn(BaseModel):
    user_id: str
    timestamp: datetime
    source_ip: str
    country: str
    action: str
    status: str
    is_privileged_action: bool


class UserRegisterIn(BaseModel):
    username: str
    password: str
    role: str


class UserLoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AlertGenerateOut(BaseModel):
    new_alerts_created: int
    total_alerts: int


class AlertStatusUpdateIn(BaseModel):
    status: str