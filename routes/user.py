from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List
from backend.database import get_db
from models.user import User
from schemas.user import UserResponse, UserUpdate
from auth.hashing import hash_password
from auth.oauth2 import get_current_user, require_admin
from auth.monitor import check_unauthorized_admin, check_ddos

router = APIRouter()


@router.get("/me", response_model=UserResponse)
def get_my_profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.put("/me", response_model=UserResponse)
def update_my_profile(
    updates: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if updates.email:
        existing = db.query(User).filter(User.email == updates.email, User.id != current_user.id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = updates.email

    if updates.username:
        existing = db.query(User).filter(User.username == updates.username, User.id != current_user.id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already taken")
        current_user.username = updates.username

    if updates.password:
        current_user.password_hash = hash_password(updates.password)

    db.commit()
    db.refresh(current_user)
    return current_user


# ── ADMIN ONLY ROUTES ─────────────────────────────────────────

@router.get("/", response_model=List[UserResponse])
def get_all_users(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if non-admin trying to access
    if current_user.role != "admin":
        check_unauthorized_admin(db, request.client.host,
                                  current_user.id, current_user.username)
        raise HTTPException(status_code=403, detail="Admin access required")
    return db.query(User).all()


@router.put("/{user_id}/deactivate")
def deactivate_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        check_unauthorized_admin(db, request.client.host,
                                  current_user.id, current_user.username)
        raise HTTPException(status_code=403, detail="Admin access required")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    db.commit()
    return {"message": f"User {user.username} deactivated"}


@router.put("/{user_id}/make-admin")
def make_admin(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        check_unauthorized_admin(db, request.client.host,
                                  current_user.id, current_user.username)
        raise HTTPException(status_code=403, detail="Admin access required")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = "admin"
    db.commit()
    return {"message": f"User {user.username} is now an admin"}
