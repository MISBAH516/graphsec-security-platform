from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List
from backend.database import get_db
from models.threat import Threat
from models.user import User
from schemas.threat import ThreatCreate, ThreatUpdate, ThreatResponse
from auth.oauth2 import get_current_user, require_admin
from auth.monitor import check_threat_deleted, check_new_threat_created, check_ddos

router = APIRouter()


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=ThreatResponse)
def create_threat(
    request: Request,
    threat: ThreatCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ip = request.client.host
    new_threat = Threat(**threat.dict(), user_id=current_user.id)
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)

    # Auto log agar critical threat create hua
    check_new_threat_created(db, ip, current_user.username,
                              threat.title, threat.severity, current_user.id)
    # DDoS check
    check_ddos(db, ip, current_user.id)

    return new_threat


@router.get("/", response_model=List[ThreatResponse])
def get_threats(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    check_ddos(db, request.client.host, current_user.id)
    if current_user.role == "admin":
        return db.query(Threat).all()
    return db.query(Threat).filter(Threat.user_id == current_user.id).all()


@router.get("/{threat_id}", response_model=ThreatResponse)
def get_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    if threat.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return threat


@router.put("/{threat_id}", response_model=ThreatResponse)
def update_threat(
    threat_id: int,
    updates: ThreatUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    if threat.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    for field, value in updates.dict(exclude_unset=True).items():
        setattr(threat, field, value)

    db.commit()
    db.refresh(threat)
    return threat


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_threat(
    request: Request,
    threat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    if threat.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Log deletion
    check_threat_deleted(db, request.client.host,
                         current_user.username, threat.title, current_user.id)

    db.delete(threat)
    db.commit()
