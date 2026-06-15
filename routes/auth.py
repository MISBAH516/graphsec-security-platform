from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from collections import defaultdict
from datetime import datetime, timedelta
from backend.database import get_db
from models.user import User
from models.threat import Threat
from models.security_event import SecurityEvent
from schemas.user import UserRegister, UserLogin, TokenResponse, RefreshRequest
from auth.hashing import hash_password, verify_password
from auth.jwt_handler import create_access_token, create_refresh_token, verify_token

router = APIRouter()

# Track failed login attempts per IP in memory
failed_attempts = defaultdict(lambda: {"count": 0, "last_attempt": datetime.utcnow()})

MAX_FAILED_ATTEMPTS = 3   # threat create hoga 3 baar fail pe
BLOCK_MINUTES = 15        # 15 min baad count reset


def get_admin_id(db: Session) -> int:
    admin = db.query(User).filter(User.role == "admin").first()
    if admin:
        return admin.id
    first = db.query(User).first()
    return first.id if first else 1


def auto_create_threat(db: Session, title: str, description: str, severity: str, user_id: int):
    threat = Threat(
        title=title,
        description=description,
        severity=severity,
        status="open",
        user_id=user_id
    )
    db.add(threat)
    db.commit()


def auto_log_event(db: Session, event_type: str, description: str, severity: str, source_ip: str, user_id: int):
    event = SecurityEvent(
        event_type=event_type,
        description=description,
        severity=severity,
        status="open",
        source_ip=source_ip,
        user_id=user_id
    )
    db.add(event)
    db.commit()


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(request: Request, user: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    try:
        ip = request.client.host
        auto_log_event(
            db,
            event_type="New User Registration",
            description=f"New user registered: {user.username} ({user.email}) from IP {ip}",
            severity="low",
            source_ip=ip,
            user_id=new_user.id
        )
    except Exception:
        pass

    return {"message": "User registered successfully", "user_id": new_user.id}


@router.post("/login", response_model=TokenResponse)
def login(request: Request, user: UserLogin, db: Session = Depends(get_db)):
    ip = request.client.host

    # Reset counter if last attempt was more than BLOCK_MINUTES ago
    last = failed_attempts[ip]["last_attempt"]
    if datetime.utcnow() - last > timedelta(minutes=BLOCK_MINUTES):
        failed_attempts[ip] = {"count": 0, "last_attempt": datetime.utcnow()}

    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        failed_attempts[ip]["count"] += 1
        failed_attempts[ip]["last_attempt"] = datetime.utcnow()
        count = failed_attempts[ip]["count"]
        try:
            admin_id = get_admin_id(db)
            auto_log_event(db,
                event_type="Failed Login Attempt",
                description=f"Login attempted with unknown email: {user.email} from IP {ip}. Attempt #{count}",
                severity="medium" if count < MAX_FAILED_ATTEMPTS else "high",
                source_ip=ip,
                user_id=admin_id
            )
            if count >= MAX_FAILED_ATTEMPTS:
                auto_create_threat(db,
                    title=f"Brute Force Attack Detected from {ip}",
                    description=f"{count} failed login attempts from IP {ip}. Possible brute force attack.",
                    severity="critical",
                    user_id=admin_id
                )
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(user.password, db_user.password_hash):
        failed_attempts[ip]["count"] += 1
        failed_attempts[ip]["last_attempt"] = datetime.utcnow()
        count = failed_attempts[ip]["count"]
        try:
            auto_log_event(db,
                event_type="Failed Login Attempt",
                description=f"Wrong password for: {db_user.email} from IP {ip}. Attempt #{count}",
                severity="medium" if count < MAX_FAILED_ATTEMPTS else "high",
                source_ip=ip,
                user_id=db_user.id
            )
            if count >= MAX_FAILED_ATTEMPTS:
                auto_create_threat(db,
                    title=f"Brute Force Attack on {db_user.email} from {ip}",
                    description=f"{count} failed password attempts on {db_user.email} from IP {ip}.",
                    severity="critical",
                    user_id=db_user.id
                )
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid password")

    if not db_user.is_active:
        try:
            from auth.monitor import check_inactive_login
            check_inactive_login(db, ip, db_user.email, db_user.id)
        except Exception:
            pass
        raise HTTPException(status_code=403, detail="Account is deactivated")

    # Successful login - reset counter
    failed_attempts[ip] = {"count": 0, "last_attempt": datetime.utcnow()}

    try:
        auto_log_event(db,
            event_type="Successful Login",
            description=f"User {db_user.username} logged in successfully from IP {ip}",
            severity="low",
            source_ip=ip,
            user_id=db_user.id
        )
        # Check odd hours login
        from auth.monitor import check_odd_hours_login
        check_odd_hours_login(db, ip, db_user.username, db_user.id)
    except Exception:
        pass

    data = {"sub": str(db_user.id), "email": db_user.email, "role": db_user.role}
    return TokenResponse(
        access_token=create_access_token(data),
        refresh_token=create_refresh_token(data)
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest):
    payload = verify_token(body.refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    data = {"sub": payload["sub"], "email": payload["email"], "role": payload["role"]}
    return TokenResponse(
        access_token=create_access_token(data),
        refresh_token=create_refresh_token(data)
    )
