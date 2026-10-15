import os
import aiosmtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# Load environment variables dari file .env
load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

async def send_otp_email(to_email: str, otp_code: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        print("Error: Kredensial SMTP belum diatur di file .env")
        return False

    msg = EmailMessage()
    msg["From"] = f"OLT Dashboard <{SMTP_USER}>"
    msg["To"] = to_email
    msg["Subject"] = "Kode OTP Pemulihan Password - OLT Dashboard"
    
    # Desain template email HTML
    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="max-width: 500px; margin: auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px;">
                <h2 style="color: #0f2942;">Pemulihan Password</h2>
                <p>Anda telah meminta untuk mengatur ulang sandi akun OLT Dashboard Anda.</p>
                <p>Gunakan kode OTP berikut untuk melanjutkan proses pemulihan:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <span style="background-color: #f3f4f6; padding: 15px 25px; font-size: 24px; font-weight: bold; letter-spacing: 8px; border-radius: 6px; color: #1d4ed8;">
                        {otp_code}
                    </span>
                </div>
                
                <p style="font-size: 12px; color: #6b7280;">Kode ini hanya berlaku selama 10 menit. Jika Anda tidak pernah meminta pemulihan password, silakan abaikan email ini.</p>
            </div>
        </body>
    </html>
    """
    
    msg.set_content("Harap gunakan aplikasi email yang mendukung HTML.")
    msg.add_alternative(html_content, subtype='html')

    try:
        await aiosmtplib.send(
            msg,
            hostname=SMTP_SERVER,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
            use_tls=True
        )
        return True
    except Exception as e:
        print(f"Gagal mengirim email OTP ke {to_email}: {e}")
        return False