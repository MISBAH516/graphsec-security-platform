from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from models.security_event import EventSeverity, EventStatus


class SecurityEventCreate(BaseModel):
    event_type: str
    description: Optional[str] = None
    severity: EventSeverity = EventSeverity.low
    source_ip: Optional[str] = None


class SecurityEventUpdate(BaseModel):
    status: Optional[EventStatus] = None
    description: Optional[str] = None


class SecurityEventResponse(BaseModel):
    id: int
    event_type: str
    description: Optional[str]
    severity: EventSeverity
    status: EventStatus
    source_ip: Optional[str]
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True
