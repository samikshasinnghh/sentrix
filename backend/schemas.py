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