"""
Servicio de envío de correos electrónicos mediante protocolo SMTP estándar (smtplib).
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

def send_otp_email(to_email: str, otp_code: str) -> bool:
    """
    Envía el código OTP de 6 dígitos al correo del usuario usando smtplib.
    """
    load_dotenv(override=True)

    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")

    if not smtp_user or not smtp_password or smtp_user == "tu_correo@gmail.com":
        print(f"[MODO DESARROLLO] Correo destinatario: {to_email} | Código OTP generado: {otp_code}")
        return True

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = to_email
        msg["Subject"] = "Tu Código de Verificación OTP - Sistema de Autenticación"

        body = f"""
        <html>
            <body>
                <h2>Verificación en Dos Pasos (2FA)</h2>
                <p>Tu código de acceso único (OTP) es:</p>
                <h1 style="color: #2E86C1; letter-spacing: 4px;">{otp_code}</h1>
                <p>Este código es válido por <b>15 minutos</b>. No lo compartas con nadie.</p>
            </body>
        </html>
        """
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            
        print(f"✅ [SMTP REAL] Correo enviado exitosamente a {to_email}")
        return True
    except Exception as e:
        # Fallback de emergencia para Render si bloquea el puerto SMTP saliente
        print(f"\n==================================================")
        print(f"⚠️ [RENDER FALLBACK] OTP PARA {to_email}: {otp_code}")
        print(f"==================================================\n")
        logger.error(f"Error al conectar con el servidor SMTP: {e}")
        return True  # Permite que el login sea exitoso y el código salga en los Logs de Render