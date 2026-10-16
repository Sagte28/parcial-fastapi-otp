"""
Esquemas Pydantic para validación de datos y documentación en OpenAPI (Swagger).
"""
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime

class UserRegister(BaseModel):
    """Esquema para el registro de un nuevo usuario."""
    email: EmailStr = Field(..., json_schema_extra={"example": "estudiante@unisimon.edu.co"})
    password: str = Field(..., min_length=6, json_schema_extra={"example": "Segura123*"})
    full_name: str = Field(..., min_length=2, json_schema_extra={"example": "Said Charris"})

class UserLogin(BaseModel):
    """Esquema para inicio de sesión con credenciales."""
    email: EmailStr = Field(..., json_schema_extra={"example": "estudiante@unisimon.edu.co"})
    password: str = Field(..., json_schema_extra={"example": "Segura123*"})

class OTPVerify(BaseModel):
    """Esquema para verificar el código OTP de 6 dígitos."""
    email: EmailStr = Field(..., json_schema_extra={"example": "estudiante@unisimon.edu.co"})
    code: str = Field(..., min_length=6, max_length=6, json_schema_extra={"example": "482910"})

class OTPResend(BaseModel):
    """Esquema para solicitar el reenvío de un código OTP."""
    email: EmailStr = Field(..., json_schema_extra={"example": "estudiante@unisimon.edu.co"})

class UserProfileUpdate(BaseModel):
    """Esquema para actualizar la información del perfil del usuario."""
    full_name: str = Field(..., min_length=2, json_schema_extra={"example": "Said Jose Charris"})

class UserResponse(BaseModel):
    """Esquema de respuesta con los datos públicos del usuario."""
    id: int
    email: EmailStr
    full_name: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    """Esquema de respuesta al emitir o refrescar un token JWT."""
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime