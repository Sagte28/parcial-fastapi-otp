"""
Endpoints de autenticación: Registro, Login, Verificación OTP, Reenvío OTP, Refresh y Logout.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, LoginSession
from app.schemas import (
    UserRegister, UserLogin, OTPVerify, OTPResend, UserResponse, TokenResponse
)
from app.services.otp_service import (
    hash_password, verify_password, generate_and_save_otp, verify_otp_code, create_jwt_session
)
from app.services.email_service import send_otp_email
from app.middleware import get_current_user

router = APIRouter(prefix="/auth", tags=["Autenticación"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    """Registra un nuevo usuario validando que el correo electrónico sea único."""
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo electrónico ya está registrado."
        )
    
    new_user = User(
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        full_name=user_in.full_name
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", status_code=status.HTTP_200_OK)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """Valida credenciales de usuario y envía un código OTP de 6 dígitos al correo electrónico."""
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas."
        )
    
    otp_code = generate_and_save_otp(db, user.id)
    email_sent = send_otp_email(user.email, otp_code)
    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No fue posible enviar el código OTP por correo."
        )
    
    return {"message": "Credenciales válidas. Se ha enviado un código OTP a su correo electrónico."}

@router.post("/verify-otp", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    """Verifica el código OTP de 6 dígitos y retorna un token JWT de sesión activa."""
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")
    
    is_valid = verify_otp_code(db, user.id, data.code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código OTP inválido, expirado o ya utilizado."
        )
    
    token, expires_at = create_jwt_session(db, user.id, user.email)
    return TokenResponse(access_token=token, expires_at=expires_at)

@router.post("/resend-otp", status_code=status.HTTP_200_OK)
def resend_otp(data: OTPResend, db: Session = Depends(get_db)):
    """Genera y reenvía un nuevo código OTP al correo electrónico del usuario."""
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")
    
    otp_code = generate_and_save_otp(db, user.id)
    send_otp_email(user.email, otp_code)
    return {"message": "Se ha enviado un nuevo código OTP a su correo electrónico."}

@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def refresh_token(
    auth_data: tuple[User, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoca el token JWT actual y emite uno nuevo con tiempo de expiración renovado."""
    user, old_token = auth_data
    db.query(LoginSession).filter(LoginSession.token == old_token).delete()
    db.commit()
    
    new_token, expires_at = create_jwt_session(db, user.id, user.email)
    return TokenResponse(access_token=new_token, expires_at=expires_at)

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    auth_data: tuple[User, str] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cierra la sesión activa eliminando y revocando el token JWT de la base de datos."""
    _, current_token = auth_data
    db.query(LoginSession).filter(LoginSession.token == current_token).delete()
    db.commit()
    return {"message": "Sesión cerrada exitosamente. El token ha sido revocado."}