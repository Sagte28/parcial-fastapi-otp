"""
Punto de entrada principal de la aplicación FastAPI.
"""
from fastapi import FastAPI
from app.database import engine, Base
from app.middleware import RateLimitMiddleware
from app.routes import auth, users

# Crear tablas en la base de datos SQLite
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Sistema de Autenticación con OTP - FastAPI",
    description="API RESTful con autenticación de dos factores (2FA) por correo, JWT y SQLite.",
    version="1.0.0"
)

# Agregar middleware de Rate Limiting
app.add_middleware(RateLimitMiddleware, max_requests=25, window_seconds=60)

# Registrar routers
app.include_router(auth.router)
app.include_router(users.router)

@app.get("/", tags=["Health Check"])
def root():
    """Endpoint de verificación de estado del servidor."""
    return {"status": "ok", "service": "FastAPI OTP Auth System"}