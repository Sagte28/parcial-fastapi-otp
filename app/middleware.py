"""
Middleware de seguridad para Rate Limiting y validación de tokens JWT en rutas protegidas.
"""
import time
import jwt
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, LoginSession
from app.services.otp_service import SECRET_KEY, ALGORITHM

security = HTTPBearer()

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware que limita el número de peticiones por IP en endpoints críticos de autenticación
    para prevenir ataques de fuerza bruta.
    """
    def __init__(self, app, max_requests: int = 15, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        """Intercepta peticiones a rutas /auth/ y verifica el límite por ventana de tiempo."""
        if request.url.path.startswith("/auth/"):
            client_ip = request.client.host if request.client else "127.0.0.1"
            now = time.time()
            # Limpiar registros antiguos fuera de la ventana de tiempo
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if now - req_time < self.window_seconds
            ]
            if len(self.requests[client_ip]) >= self.max_requests:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Demasiadas solicitudes. Por favor, intente más tarde."}
                )
            self.requests[client_ip].append(now)

        return await call_next(request)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> tuple[User, str]:
    """
    Valida el token JWT, verifica su expiración y comprueba que la sesión siga activa en BD.
    Retorna la instancia del usuario autenticado y el token actual.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
        user_id = int(user_id_str)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="El token ha expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido o malformado")

    # Verificar que el token exista en login_sessions (que no haya sido revocado con logout)
    session_record = db.query(LoginSession).filter(LoginSession.token == token).first()
    if not session_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión cerrada o revocada. Inicie sesión nuevamente."
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado")

    return user, token