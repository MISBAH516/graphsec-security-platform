from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum
from datetime import datetime
import enum
from backend.database import Base


class EventSeverity(str, enum.Enum):
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class EventStatus(str, enum.Enum):
    open     = "open"
    resolved = "resolved"
    ignored  = "ignored"


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id          = Column(Integer, primary_key=True, index=True)
    event_type  = Column(String, nullable=False)
    description = Column(String)
    severity    = Column(Enum(EventSeverity), default=EventSeverity.low)
    status      = Column(Enum(EventStatus), default=EventStatus.open)
    source_ip   = Column(String, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
