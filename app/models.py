"""
Modelos ORM de SQLAlchemy para las tablas users, otp_codes y login_sessions.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

def utc_now():
    """Retorna la fecha y hora actual en UTC."""
    return datetime.now(timezone.utc)

class User(Base):
    """
    Modelo que almacena los datos de los usuarios registrados.
    Ejemplo: id=1, email='juan@example.com', full_name='Juan Pérez'
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    otp_codes = relationship("OTPCode", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("LoginSession", back_populates="user", cascade="all, delete-orphan")


class OTPCode(Base):
    """
    Modelo que registra los códigos OTP generados con su fecha de expiración (15 min) y estado de uso.
    """
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code = Column(String(6), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)

    user = relationship("User", back_populates="otp_codes")


class LoginSession(Base):
    """
    Modelo que mantiene el registro de sesiones y tokens JWT activos para permitir su revocación en logout.
    """
    __tablename__ = "login_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utc_now)

    user = relationship("User", back_populates="sessions")