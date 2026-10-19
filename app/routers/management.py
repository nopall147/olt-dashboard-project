from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional, List

from app.database import get_db
from app.models import User
from app.core.rbac import require_roles, Role

router = APIRouter(tags=["Management"])

class UserCreateSchema(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    role: str
    password: str
    is_active: bool = True

class UserEditSchema(BaseModel):
    full_name: str
    email: EmailStr
    role: str
    password: Optional[str] = None
    is_active: bool = True

# 1. Endpoint pembuatan user baru oleh Super Admin
@router.post("/api/user/create")
def create_new_user(
    payload: UserCreateSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN]))
):
    existing_user = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username atau Email sudah terdaftar di sistem."
        )

    # Hash sederhana / plain sesuai arsitektur project
    new_user = User(
        username=payload.username,
        full_name=payload.full_name,
        email=payload.email,
        role=payload.role,
        plain_password=payload.password,
        password_hash=payload.password,
        is_active=payload.is_active
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"status": "success", "message": f"User {new_user.username} berhasil dibuat.", "id": new_user.id}

# 2. Endpoint edit profil / role user oleh Super Admin
@router.post("/api/user/{user_id}/edit")
def edit_user(
    user_id: int,
    payload: UserEditSchema,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN]))
):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User tidak ditemukan.")

    target_user.full_name = payload.full_name
    target_user.email = payload.email
    target_user.role = payload.role
    target_user.is_active = payload.is_active

    if payload.password:
        target_user.plain_password = payload.password
        target_user.password_hash = payload.password

    db.commit()
    return {"status": "success", "message": f"Data user {target_user.username} berhasil diperbarui."}

# 3. Endpoint hapus / revoke user oleh Super Admin
@router.delete("/api/user/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN]))
):
    if current_user.id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tidak dapat menghapus akun sendiri.")

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User tidak ditemukan.")

    db.delete(target_user)
    db.commit()
    return {"status": "success", "message": f"User {target_user.username} berhasil dihapus."}

# 4. Endpoint list ONU untuk semua role yang berizin
@router.get("/api/onu/list")
def list_onu(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))
):
    return {"status": "success", "data": []}