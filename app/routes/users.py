"""
Endpoints protegidos para la gestión del perfil del usuario.
"""
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserResponse, UserProfileUpdate
from app.middleware import get_current_user

router = APIRouter(prefix="/users", tags=["Usuarios"])

@router.get("/profile", response_model=UserResponse, status_code=status.HTTP_200_OK)
def get_profile(auth_data: tuple[User, str] = Depends(get_current_user)):
    """Obtiene la información del perfil del usuario autenticado."""
    user, _ = auth_data
    return user

@router.put("/profile", response_model=UserResponse, status_code=status.HTTP_200_OK)
def update_profile(
    profile_in: UserProfileUpdate,
    auth_data: tuple[User, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Actualiza el nombre completo del perfil del usuario autenticado."""
    user, _ = auth_data
    user.full_name = profile_in.full_name
    db.commit()
    db.refresh(user)
    return user