"""
GraphSec Auto Monitor
=====================
Yeh file automatically threats aur events generate karti hai
bina user ke manually enter kiye.
"""
from datetime import datetime
from sqlalchemy.orm import Session
from models.threat import Threat
from models.security_event import SecurityEvent
from models.user import User
from collections import defaultdict

# ── IN-MEMORY TRACKING ────────────────────────────────────────
request_counts   = defaultdict(list)   # DDoS detection
admin_attempts   = defaultdict(int)    # Unauthorized admin access


def get_admin_id(db: Session) -> int:
    admin = db.query(User).filter(User.role == "admin").first()
    if admin:
        return admin.id
    first = db.query(User).first()
    return first.id if first else 1


def auto_event(db, event_type, description, severity, source_ip, user_id):
    try:
        db.add(SecurityEvent(
            event_type=event_type,
            description=description,
            severity=severity,
            status="open",
            source_ip=source_ip,
            user_id=user_id
        ))
        db.commit()
    except Exception:
        db.rollback()


def auto_threat(db, title, description, severity, user_id):
    try:
        db.add(Threat(
            title=title,
            description=description,
            severity=severity,
            status="open",
            user_id=user_id
        ))
        db.commit()
    except Exception:
        db.rollback()


def check_ddos(db: Session, ip: str, user_id: int):
    """Agar ek IP se 20+ requests 1 minute mein aaye to DDoS threat create karo."""
    now = datetime.utcnow()
    request_counts[ip].append(now)
    # Sirf last 60 second ki requests rakho
    request_counts[ip] = [t for t in request_counts[ip]
                          if (now - t).seconds < 60]
    count = len(request_counts[ip])

    if count == 20:
        auto_event(db,
            event_type="High Request Rate Detected",
            description=f"IP {ip} sent {count} requests in last 60 seconds.",
            severity="high",
            source_ip=ip,
            user_id=user_id
        )
    elif count == 50:
        auto_threat(db,
            title=f"Possible DDoS Attack from {ip}",
            description=f"IP {ip} sent {count} requests in 60 seconds. Possible DDoS attack.",
            severity="critical",
            user_id=user_id
        )


def check_unauthorized_admin(db: Session, ip: str, user_id: int, username: str):
    """Agar normal user admin route access karne ki koshish kare."""
    admin_attempts[ip] += 1
    count = admin_attempts[ip]

    auto_event(db,
        event_type="Unauthorized Admin Access Attempt",
        description=f"User '{username}' tried to access admin route from IP {ip}. Attempt #{count}",
        severity="high",
        source_ip=ip,
        user_id=user_id
    )

    if count >= 3:
        auto_threat(db,
            title=f"Repeated Admin Access Violation by {username}",
            description=f"User '{username}' (IP: {ip}) attempted admin access {count} times.",
            severity="critical",
            user_id=user_id
        )


def check_inactive_login(db: Session, ip: str, email: str, user_id: int):
    """Agar deactivated account pe login try hو."""
    auto_event(db,
        event_type="Deactivated Account Login Attempt",
        description=f"Someone tried to login to deactivated account: {email} from IP {ip}",
        severity="high",
        source_ip=ip,
        user_id=user_id
    )
    auto_threat(db,
        title=f"Login Attempt on Deactivated Account",
        description=f"Deactivated account {email} login attempted from IP {ip}.",
        severity="high",
        user_id=user_id
    )


def check_odd_hours_login(db: Session, ip: str, username: str, user_id: int):
    """Raat 11 baje se subah 5 baje ke beech login hو to suspicious."""
    hour = datetime.utcnow().hour  # UTC time (Pakistan = UTC+5)
    # Pakistan time = UTC + 5
    pak_hour = (hour + 5) % 24

    if pak_hour >= 23 or pak_hour <= 5:
        auto_event(db,
            event_type="Odd Hours Login Detected",
            description=f"User '{username}' logged in at {pak_hour}:00 PKT from IP {ip}. Unusual login time.",
            severity="medium",
            source_ip=ip,
            user_id=user_id
        )


def check_threat_deleted(db: Session, ip: str, username: str, threat_title: str, user_id: int):
    """Jab koi threat delete kare to log karo."""
    auto_event(db,
        event_type="Threat Record Deleted",
        description=f"User '{username}' deleted threat: '{threat_title}' from IP {ip}",
        severity="medium",
        source_ip=ip,
        user_id=user_id
    )


def check_event_deleted(db: Session, ip: str, username: str, user_id: int):
    """Jab koi event delete kare to log karo."""
    auto_event(db,
        event_type="Security Event Deleted",
        description=f"User '{username}' deleted a security event from IP {ip}",
        severity="low",
        source_ip=ip,
        user_id=user_id
    )


def check_new_threat_created(db_session: Session, ip: str, username: str,
                              threat_title: str, severity: str, user_id: int):
    """Jab critical threat create ho to extra event log karo."""
    if severity == "critical":
        auto_event(db_session,
            event_type="Critical Threat Reported",
            description=f"User '{username}' reported a CRITICAL threat: '{threat_title}' from IP {ip}",
            severity="critical",
            source_ip=ip,
            user_id=user_id
        )
