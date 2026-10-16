# 🔐 Sistema de Autenticación con OTP (2FA) - FastAPI

Sistema de autenticación backend robusto y seguro desarrollado con **FastAPI**, **SQLAlchemy**, base de datos **SQLite** y autenticación de dos factores (2FA) mediante códigos **OTP (One-Time Password)** de 6 dígitos enviados por correo electrónico a través de SMTP.

---

## 📋 1. Características y Requisitos Técnicos

* **Backend Framework:** FastAPI (Python 3.9+)
* **ORM y Base de Datos:** SQLAlchemy con SQLite (`sql_app.db`)
* **Autenticación OTP:** `PyOTP` (Códigos de 6 dígitos con expiración estricta de 15 minutos y validación de único uso)
* **Envío de Correos:** Librería estándar `smtplib` con soporte TLS (Gmail SMTP) y modo fallback para entorno de pruebas
* **Seguridad y Sesiones:**
  * Hashing de contraseñas con `bcrypt` (`passlib`)
  * Emisión de tokens **JWT (JSON Web Tokens)** firmados con claim de expiración (`exp`)
  * Persistencia y revocación activa de sesiones en base de datos (`login_sessions`)
  * Middleware de **Rate Limiting** por IP para mitigar ataques de fuerza bruta en rutas `/auth/*`
* **Testing Automatizado:** Suite con `pytest` (5 pruebas unitarias y 3 pruebas de integración)

---

## 📂 2. Estructura del Proyecto

```text
proyecto_parcial/
├── app/
│   ├── __init__.py
│   ├── main.py              # Punto de entrada de la aplicación FastAPI
│   ├── database.py          # Configuración de conexión SQLAlchemy + SQLite
│   ├── models.py            # Modelos ORM (users, otp_codes, login_sessions)
│   ├── schemas.py           # Esquemas Pydantic con validaciones y ejemplos
│   ├── middleware.py        # RateLimitMiddleware y validación de JWT activo
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth.py          # Endpoints de registro, login, OTP, refresh y logout
│   │   └── users.py         # Endpoints protegidos de perfil de usuario
│   └── services/
│       ├── __init__.py
│       ├── email_service.py # Servicio de envío de correos vía smtplib
│       └── otp_service.py   # Lógica de bcrypt, PyOTP y creación de sesiones JWT
├── tests/
│   ├── __init__.py
│   └── test_app.py          # 5 tests unitarios + 3 tests de integración (pytest)
├── .env                     # Variables de entorno (no incluido en Git)
├── .gitignore               # Archivos excluidos del control de versiones
├── requirements.txt         # Dependencias del proyecto
└── README.md                # Documentación general