from enum import Enum
from typing import List
from fastapi import HTTPException, status, Request
from app.models import User

class Role(str, Enum):
    SUPER_ADMIN = "Super Admin"
    NOC = "NOC"
    VIEWER = "Viewer"

def get_current_user_from_session(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi diperlukan untuk mengakses resource ini."
        )
    return user

def require_roles(allowed_roles: List[Role]):
    def role_checker(request: Request) -> User:
        user = get_current_user_from_session(request)
        user_role = getattr(user, "role", None)
        allowed_values = [r.value if isinstance(r, Role) else str(r) for r in allowed_roles]
        
        if user_role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Anda tidak memiliki izin (clearance role) untuk tindakan ini."
            )
        return user
    return role_checker