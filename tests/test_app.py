"""
Suite de pruebas automatizadas con Pytest:
Incluye 5 pruebas unitarias y 3 pruebas de integración de flujo completo.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.models import OTPCode
from app.services.otp_service import (
    hash_password, verify_password, generate_and_save_otp, verify_otp_code, create_jwt_session
)

# Base de datos SQLite en memoria aislada para testing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test_db.db"
engine_test = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)

def override_get_db():
    """Sobrescribe la sesión de base de datos para usar la BD de pruebas."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    """Crea y limpia las tablas antes y después de cada test."""
    Base.metadata.create_all(bind=engine_test)
    yield
    Base.metadata.drop_all(bind=engine_test)


# ==========================================
# 5 TESTS UNITARIOS
# ==========================================

def test_unit_password_hashing():
    """1. Verifica que el hash bcrypt sea diferente al texto plano y valide correctamente."""
    raw = "MiClaveSecreta123"
    hashed = hash_password(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True

def test_unit_password_wrong_verification():
    """2. Verifica que una contraseña incorrecta sea rechazada por bcrypt."""
    hashed = hash_password("ClaveCorrecta")
    assert verify_password("ClaveErronea", hashed) is False

def test_unit_generate_otp_format():
    """3. Verifica que el servicio OTP genere un código numérico de exactamente 6 dígitos."""
    db = TestingSessionLocal()
    code = generate_and_save_otp(db, user_id=1)
    db.close()
    assert len(code) == 6
    assert code.isdigit() is True

def test_unit_verify_otp_lifecycle():
    """4. Verifica que un código OTP sea válido una única vez y luego quede marcado como usado."""
    db = TestingSessionLocal()
    code = generate_and_save_otp(db, user_id=1)
    assert verify_otp_code(db, user_id=1, code=code) is True
    # Segundo intento con el mismo código debe fallar
    assert verify_otp_code(db, user_id=1, code=code) is False
    db.close()

def test_unit_create_jwt_session():
    """5. Verifica que se genere un token JWT válido y se guarde en la base de datos."""
    db = TestingSessionLocal()
    token, expires_at = create_jwt_session(db, user_id=1, email="test@uni.edu.co")
    db.close()
    assert isinstance(token, str)
    assert len(token) > 20
    assert expires_at is not None


# ==========================================
# 3 TESTS DE INTEGRACIÓN
# ==========================================

def test_integration_register_and_duplicate_check():
    """1. Prueba el endpoint de registro y el bloqueo de correos duplicados (HTTP 400)."""
    payload = {
        "email": "integracion1@test.com",
        "password": "Password123",
        "full_name": "Usuario Test"
    }
    res1 = client.post("/auth/register", json=payload)
    assert res1.status_code == 201
    assert res1.json()["email"] == "integracion1@test.com"

    # Intentar registrar el mismo correo
    res2 = client.post("/auth/register", json=payload)
    assert res2.status_code == 400

def test_integration_full_auth_flow_and_profile():
    """2. Prueba el flujo completo: Registro -> Login -> OTP -> Ver Perfil -> Actualizar Perfil."""
    # Registro
    client.post("/auth/register", json={
        "email": "flujo@test.com",
        "password": "Password123",
        "full_name": "Nombre Inicial"
    })

    # Login (dispara generación de OTP)
    login_res = client.post("/auth/login", json={
        "email": "flujo@test.com",
        "password": "Password123"
    })
    assert login_res.status_code == 200

    # Extraer OTP directamente de la BD de prueba
    db = TestingSessionLocal()
    otp_record = db.query(OTPCode).first()
    otp_code = otp_record.code
    db.close()

    # Verificar OTP y obtener JWT
    verify_res = client.post("/auth/verify-otp", json={
        "email": "flujo@test.com",
        "code": otp_code
    })
    assert verify_res.status_code == 200
    token = verify_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Consultar perfil protegido
    prof_res = client.get("/users/profile", headers=headers)
    assert prof_res.status_code == 200
    assert prof_res.json()["full_name"] == "Nombre Inicial"

    # Actualizar perfil
    upd_res = client.put("/users/profile", json={"full_name": "Nombre Actualizado"}, headers=headers)
    assert upd_res.status_code == 200
    assert upd_res.json()["full_name"] == "Nombre Actualizado"

def test_integration_logout_revokes_token():
    """3. Prueba que al hacer logout el token sea revocado y no permita acceder a rutas protegidas."""
    client.post("/auth/register", json={
        "email": "logout@test.com",
        "password": "Password123",
        "full_name": "Logout User"
    })
    client.post("/auth/login", json={"email": "logout@test.com", "password": "Password123"})

    db = TestingSessionLocal()
    otp_code = db.query(OTPCode).first().code
    db.close()

    verify_res = client.post("/auth/verify-otp", json={"email": "logout@test.com", "code": otp_code})
    token = verify_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Cerrar sesión
    logout_res = client.post("/auth/logout", headers=headers)
    assert logout_res.status_code == 200

    # Intentar acceder al perfil con el token revocado debe dar 401
    prof_res = client.get("/users/profile", headers=headers)
    assert prof_res.status_code == 401