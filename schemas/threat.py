from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from models.threat import ThreatSeverity, ThreatStatus


class ThreatCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.low
    status: ThreatStatus = ThreatStatus.open


class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[ThreatSeverity] = None
    status: Optional[ThreatStatus] = None


class ThreatResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: ThreatSeverity
    status: ThreatStatus
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True
