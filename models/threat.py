from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum
from datetime import datetime
import enum
from backend.database import Base


class ThreatSeverity(str, enum.Enum):
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class ThreatStatus(str, enum.Enum):
    open        = "open"
    investigating = "investigating"
    resolved    = "resolved"


class Threat(Base):
    __tablename__ = "threats"

    id          = Column(Integer, primary_key=True, index=True)
    title       = Column(String, nullable=False)
    description = Column(String)
    severity    = Column(Enum(ThreatSeverity), default=ThreatSeverity.low)
    status      = Column(Enum(ThreatStatus), default=ThreatStatus.open)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
