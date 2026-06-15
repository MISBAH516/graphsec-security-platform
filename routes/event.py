from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List
from backend.database import get_db
from models.security_event import SecurityEvent
from models.user import User
from schemas.security_event import SecurityEventCreate, SecurityEventUpdate, SecurityEventResponse
from auth.oauth2 import get_current_user
from auth.monitor import check_event_deleted, check_ddos

router = APIRouter()


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=SecurityEventResponse)
def create_event(
    request: Request,
    event: SecurityEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    check_ddos(db, request.client.host, current_user.id)
    new_event = SecurityEvent(**event.dict(), user_id=current_user.id)
    db.add(new_event)
    db.commit()
    db.refresh(new_event)
    return new_event


@router.get("/", response_model=List[SecurityEventResponse])
def get_events(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    check_ddos(db, request.client.host, current_user.id)
    if current_user.role == "admin":
        return db.query(SecurityEvent).all()
    return db.query(SecurityEvent).filter(SecurityEvent.user_id == current_user.id).all()


@router.get("/{event_id}", response_model=SecurityEventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return event


@router.put("/{event_id}", response_model=SecurityEventResponse)
def update_event(
    event_id: int,
    updates: SecurityEventUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    for field, value in updates.dict(exclude_unset=True).items():
        setattr(event, field, value)

    db.commit()
    db.refresh(event)
    return event


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_event(
    request: Request,
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    check_event_deleted(db, request.client.host, current_user.username, current_user.id)

    db.delete(event)
    db.commit()
