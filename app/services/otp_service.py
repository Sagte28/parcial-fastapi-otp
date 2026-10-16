"""
Servicio de seguridad: Generación/validación de OTP con PyOTP, hashing con bcrypt y emisión de JWT.
"""
import os
import pyotp
import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.models import OTPCode, LoginSession

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_por_defecto")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

def hash_password(password: str) -> str:
    """Hashea una contraseña en texto plano utilizando bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si una contraseña en texto plano coincide con su hash bcrypt."""
    return pwd_context.verify(plain_password, hashed_password)

def generate_and_save_otp(db: Session, user_id: int) -> str:
    """
    Genera un código OTP de 6 dígitos usando PyOTP y lo almacena en la BD con validez de 15 minutos.
    Invalida cualquier código anterior no utilizado del mismo usuario.
    """
    # Marcar códigos anteriores como usados
    db.query(OTPCode).filter(OTPCode.user_id == user_id, OTPCode.used == False).update({"used": True})
    
    # Generar secreto aleatorio base32 y extraer código de 6 dígitos con PyOTP
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, digits=6)
    code = totp.now()

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    otp_record = OTPCode(
        user_id=user_id,
        code=code,
        expires_at=expires_at,
        used=False
    )
    db.add(otp_record)
    db.commit()
    return code

def verify_otp_code(db: Session, user_id: int, code: str) -> bool:
    """
    Verifica que el código OTP exista, pertenezca al usuario, no haya sido usado y no esté expirado.
    """
    otp_record = db.query(OTPCode).filter(
        OTPCode.user_id == user_id,
        OTPCode.code == code,
        OTPCode.used == False
    ).order_by(OTPCode.created_at.desc()).first()

    if not otp_record:
        return False

    now = datetime.now(timezone.utc)
    expires_at = otp_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now > expires_at:
        return False

    # Marcar código como usado tras validación exitosa
    otp_record.used = True
    db.commit()
    return True

def create_jwt_session(db: Session, user_id: int, email: str) -> tuple[str, datetime]:
    """
    Crea un token JWT firmado con expiración y registra la sesión activa en la tabla login_sessions.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": expires_at,
        "iat": now
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    session_record = LoginSession(
        user_id=user_id,
        token=token,
        expires_at=expires_at
    )
    db.add(session_record)
    db.commit()
    return token, expires_at