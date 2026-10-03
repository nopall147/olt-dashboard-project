# app/routers/management.py
from fastapi import APIRouter, Depends
from app.core.rbac import require_roles, Role
from app.models import User

router = APIRouter()

# 1. User Management hanya untuk Super Admin
@router.get("/user-management")
def user_management_page(user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    return {"message": "Halaman User Management hanya untuk Super Admin"}

# 2. Perubahan Konfigurasi OLT (Hanya Super Admin & NOC)
@router.post("/api/olt/configure")
def configure_olt(user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    return {"message": "Konfigurasi berhasil disimpan"}

# 3. Viewer hanya diizinkan memanggil endpoint baca (GET)
@router.get("/api/onu/list")
def list_onu(user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    return {"data": []}