from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database import get_db
from models.user import User
from models.threat import Threat
from models.security_event import SecurityEvent
from auth.oauth2 import get_current_user

router = APIRouter()


@router.get("/")
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns summary stats for the logged-in user's dashboard."""
    uid = current_user.id

    threats       = db.query(Threat).filter(Threat.user_id == uid).all()
    events        = db.query(SecurityEvent).filter(SecurityEvent.user_id == uid).all()

    return {
        "user": current_user.username,
        "role": current_user.role,
        "threats": {
            "total":       len(threats),
            "open":        sum(1 for t in threats if t.status == "open"),
            "critical":    sum(1 for t in threats if t.severity == "critical"),
            "resolved":    sum(1 for t in threats if t.status == "resolved"),
        },
        "events": {
            "total":       len(events),
            "open":        sum(1 for e in events if e.status == "open"),
            "critical":    sum(1 for e in events if e.severity == "critical"),
            "resolved":    sum(1 for e in events if e.status == "resolved"),
        }
    }
