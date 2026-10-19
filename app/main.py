import os
import re
import json
import asyncio
import bcrypt
import random
from enum import Enum
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, available_timezones
from fastapi import FastAPI, Request, Depends, HTTPException, Form, status
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.sql import func as sql_func
from sqlalchemy import text
from contextlib import asynccontextmanager
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

# Load environment variables (wajib dieksekusi sebelum modul yang membaca env)
load_dotenv()

# MAIL LUPA PASSWORD
from app.services.email_service import send_otp_email

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str

# Database models and clients
from app.database import Base, SessionLocal, engine, get_db
from app.models import ActivityEvent, OLTConfig, OLTConfigBackup, OLTSettingEntry, OnuDevice, TrafficSample, User
from app.services.olt_client import (
    encrypt_olt_secret, env_key, get_telnet_password, 
    open_telnet, 
    read_onu_traffic, read_pon_snapshot, read_pon_state, 
    test_snmp, test_telnet
)
from app.services.netmiko_driver import deploy_onu_zte

# Inisialisasi tabel database
Base.metadata.create_all(bind=engine)

# Migrasi idempotent skema database
with engine.begin() as connection:
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS snmp_status VARCHAR(40)"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS telnet_status VARCHAR(40)"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS snmp_community_encrypted TEXT"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS telnet_password_encrypted TEXT"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS last_connection_test TIMESTAMP WITH TIME ZONE"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS system_description TEXT"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS uptime_ticks BIGINT"))
    connection.execute(text("ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS user_agent VARCHAR(255)"))
    connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT TRUE"))
    connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS image TEXT"))
    connection.execute(text("ALTER TABLE olt_setting_entries ADD COLUMN IF NOT EXISTS olt_id INTEGER"))
    connection.execute(text("ALTER TABLE olt_setting_entries ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()"))
    connection.execute(text("ALTER TABLE olt_setting_entries ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE"))

# ==============================================================================
# RBAC ENUM & HELPER
# ==============================================================================
class Role(str, Enum):
    SUPER_ADMIN = "Super Admin"
    NOC = "NOC"
    VIEWER = "Viewer"

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def get_current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.cookies.get("user_session")
    if not user_id:
        return None
    try:
        return db.query(User).filter(User.id == int(user_id), User.is_active == True).first()
    except (ValueError, TypeError):
        return None

def login_required(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/login"})
    return user

def require_roles(allowed_roles: list[Role]):
    def role_checker(current_user: User = Depends(login_required)):
        if current_user.role not in [r.value for r in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Akses Ditolak: Anda tidak memiliki izin untuk halaman/tindakan ini."
            )
        return current_user
    return role_checker

def audit_event(request: Request, event_type: str, information: str):
    user_id = request.cookies.get("user_session")
    username = "system"
    if user_id:
        with SessionLocal() as db:
            u = db.query(User).filter(User.id == int(user_id)).first()
            if u:
                username = u.username
    return ActivityEvent(
        event_type=event_type, username=username, information=information,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:255]
    )

def format_uptime(ticks):
    if ticks is None:
        return "Belum tersedia"
    seconds = int(ticks) // 100
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{days} hari {hours} jam {minutes} menit"

# ==============================================================================
# API: ONU ADVANCED SETTINGS & MANAGEMENT ENGINE
# ==============================================================================

class OnuUpdateMetaInput(BaseModel):
    customer_name: str
    description: str | None = None

class OnuMoveInput(BaseModel):
    mode: str  # 'auto' atau 'manual'
    target_slot: int
    target_port: int
    target_onu_id: int | None = None

class OnuMetadataUpdate(BaseModel):
    customer_name: str
    description: str = ""

class OnuReplaceSnInput(BaseModel):
    new_sn: str

# ==============================================================================
# INISIALISASI DATA AWAL (OLT & ADMIN DEFAULT)
# ==============================================================================
Base.metadata.create_all(bind=engine)

with SessionLocal() as startup_db:
    for name, ip in (("OLT-C300 Tajur", "192.168.100.20"), ("OLT-C320 Anggraeni", "10.10.10.5")):
        existing_seed_olt = startup_db.query(OLTConfig).filter(
            (OLTConfig.name == name) | (OLTConfig.ip_address == ip)
        ).first()
        if not existing_seed_olt:
            startup_db.add(OLTConfig(name=name, ip_address=ip, model="ZTE C300/C320"))
    admin_user = startup_db.query(User).filter(
        (User.email == "admin@olt.local") | (User.username == "hari")
    ).first()

    if not admin_user:
        startup_db.add(User(
            fullname="Hari Pujianto",
            username="hari",
            email="hari@olt.local",
            password_hash=hash_password("hari123"),
            plain_password="hari123",
            role="Super Admin",
            is_active=True,
            is_verified=True
        ))
    else:
        admin_user.fullname = "Hari Pujianto"
        admin_user.username = "hari"
        if admin_user.role in ["admin", "operator", "Viewer"]:
            admin_user.role = "Super Admin"
        if not admin_user.plain_password:
            admin_user.plain_password = "admin123"

    startup_db.commit()

# ==============================================================================
# LIFESPAN (AUTO MIGRATE & SEED SUPER ADMIN)
# ==============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "superadmin").first()
        if not admin_user:
            new_superadmin = User(
                fullname="Super Administrator",
                username="superadmin",
                email="superadmin@olt.local",
                password_hash=hash_password("adminpassword123"),
                plain_password="adminpassword123",
                role="Super Admin",
                is_active=True,
                is_verified=True
            )
            db.add(new_superadmin)
            db.commit()
            print("INFO: Tabel berhasil dibuat dan Akun Super Admin ('superadmin') siap digunakan.")
    except Exception as e:
        print(f"WARNING: Gagal inisialisasi superadmin: {e}")
        db.rollback()
    finally:
        db.close()
    yield

# =========================================================
# === TARUH DI SINI (Background Worker Telemetri) =======
# =========================================================
async def periodic_telemetry_poller():
    """Tugas latar belakang untuk memperbarui redaman optik dan status ONU secara berkala."""
    while True:
        try:
            await asyncio.sleep(300)
            
            is_mock = os.getenv("MOCK_OLT", "false").lower() in ("true", "1", "yes")
            if is_mock:
                continue

            def run_sync_job():
                from app.database import SessionLocal
                from app.services.olt_fetcher import fetch_onu_realtime
                
                db = SessionLocal()
                try:
                    olts = db.query(OLTConfig).all()
                    for olt in olts:
                        live_data = fetch_onu_realtime(olt)
                        for item in live_data:
                            onu = db.query(OnuDevice).filter(
                                OnuDevice.olt_id == olt.id,
                                OnuDevice.sn_mac == item.get("sn_mac")
                            ).first()
                            if onu:
                                onu.status = item.get("status", onu.status)
                                if "rx_onu" in item:
                                    onu.rx_power = item["rx_onu"]
                                onu.updated_at = datetime.utcnow()
                        db.commit()
                except Exception as err:
                    db.rollback()
                    print(f"[POLLER ERROR] Gagal update telemetri: {err}")
                finally:
                    db.close()

            await asyncio.to_thread(run_sync_job)

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[WORKER ERROR] Poller crash: {e}")
            await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dijalankan saat server Uvicorn booting
    poller_task = asyncio.create_task(periodic_telemetry_poller())
    yield
    # Dijalankan saat server Uvicorn shutdown
    poller_task.cancel()
    try:
        await poller_task
    except asyncio.CancelledError:
        pass


# --- INISIALISASI ASLI MILIK PROYEK ANDA (Tambahkan parameter lifespan) ---
app = FastAPI(
    title="OLT Monitoring System",
    lifespan=lifespan
)

# ==============================================================================
# INISIALISASI FASTAPI & CONTEXT GLOBAL
# ==============================================================================
app = FastAPI(
    title="OLT Monitoring & Provisioning System",
    lifespan=lifespan
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def shared_navigation_context(request: Request):
    db = SessionLocal()
    try:
        counts = dict(db.query(OnuDevice.status, sql_func.count(OnuDevice.id)).group_by(OnuDevice.status).all())
        user_id = request.cookies.get("user_session")
        user = db.query(User).filter(User.id == int(user_id)).first() if user_id and user_id.isdigit() else None
        account_profile = {
            "full_name": user.fullname if user else "Tamu",
            "username": user.username if user else "guest",
            "role": user.role if user else "Viewer",
            "image": (getattr(user, "image", "") or "") if user else ""
        }
    finally:
        db.close()
    return {
        "nav_counts": {
            "dying_gasp": counts.get("DyingGasp", 0), 
            "los": counts.get("LOS", 0),
            "DyingGasp": counts.get("DyingGasp", 0),
            "LOS": counts.get("LOS", 0)
        },
        "account_profile": account_profile
    }

templates.context_processors.append(shared_navigation_context)

# ==============================================================================
# ROUTES: AUTHENTICATION
# ==============================================================================
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={})

@app.post("/login")
def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    clean_user = username.strip()
    user = db.query(User).filter(User.username == clean_user).first()

    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Username atau password salah!"})

    if not user.is_active:
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Akun ini dinonaktifkan."})

    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="user_session", value=str(user.id), httponly=True)
    db.add(audit_event(request, "Login", f"User {user.username} ({user.role}) berhasil login"))
    db.commit()
    return response

@app.get("/logout")
def handle_logout(request: Request):
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("user_session")
    return response

@app.get("/signup")
def redirect_signup():
    return RedirectResponse(url="/login")

# ==============================================================================
# ROUTES: MY ACCOUNT
# ==============================================================================
@app.get("/my-account", response_class=HTMLResponse)
def my_account_page(request: Request, user: User = Depends(login_required)):
    return templates.TemplateResponse(request=request, name="my_account.html", context={
        "profile": {
            "id": user.id,
            "full_name": user.fullname,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "image": user.image or ""
        }
    })

class ProfileUpdateInput(BaseModel):
    full_name: str
    image: str | None = None
    new_password: str | None = None

@app.post("/api/user/profile")
def api_update_profile(
    payload: ProfileUpdateInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(login_required)
):
    full_name = payload.full_name.strip()
    if not full_name:
        raise HTTPException(status_code=400, detail="Nama lengkap tidak boleh kosong.")
    user.fullname = full_name
    if payload.image is not None:
        user.image = payload.image
    if payload.new_password is not None:
        new_password = payload.new_password.strip()
        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="Password minimal 6 karakter.")
        user.password_hash = hash_password(new_password)
        user.plain_password = new_password

    db.add(audit_event(request, "Update", f"User {user.username} memperbarui profil"))
    db.commit()
    return {"status": "success", "message": "Profil berhasil disimpan"}

# ==============================================================================
# ROUTES: LUPA PASSWORD
# ==============================================================================
@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request=request, name="forgot_password.html", context={})
    
@app.post("/api/auth/forgot-password")
async def api_forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        return {"message": "Jika email terdaftar, OTP akan dikirim."}

    otp = str(random.randint(100000, 999999))
    expire_time = datetime.now(timezone.utc) + timedelta(minutes=10)

    from app.models import PasswordResetOTP
    new_otp = PasswordResetOTP(email=req.email, otp_code=otp, expires_at=expire_time)
    db.add(new_otp)
    db.commit()

    email_sent = await send_otp_email(req.email, otp)
    if not email_sent:
        raise HTTPException(status_code=500, detail="Gagal mengirim email server.")

    return {"message": "OTP berhasil dikirim"}

@app.post("/api/auth/reset-password")
async def api_reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    from app.models import PasswordResetOTP
    otp_record = db.query(PasswordResetOTP).filter(
        PasswordResetOTP.email == req.email,
        PasswordResetOTP.otp_code == req.otp_code
    ).order_by(PasswordResetOTP.id.desc()).first()

    if not otp_record:
        raise HTTPException(status_code=400, detail="Kode OTP salah atau tidak ditemukan.")

    if otp_record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Kode OTP sudah kedaluwarsa. Silakan minta ulang.")

    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Akun tidak ditemukan.")

    user.password_hash = hash_password(req.new_password)
    user.plain_password = req.new_password

    db.query(PasswordResetOTP).filter(PasswordResetOTP.email == req.email).delete()
    db.commit()

    return {"message": "Password berhasil diubah"}

# ==============================================================================
# ROUTES: USER MANAGEMENT (KHUSUS SUPER ADMIN)
# ==============================================================================
@app.get("/user-management", response_class=HTMLResponse)
def user_management_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    users = db.query(User).order_by(User.id.asc()).all()
    return templates.TemplateResponse(request=request, name="user_management.html", context={"users": users, "current_user": user})

class AdminUserCreateInput(BaseModel):
    fullname: str
    username: str
    email: str
    password: str
    role: str = "NOC"

class AdminUserUpdateInput(BaseModel):
    fullname: str
    role: str
    is_active: bool
    new_password: str | None = None

class RevealPasswordRequest(BaseModel):
    admin_password: str

@app.get("/api/users")
def api_get_users(db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    users = db.query(User).order_by(User.id.asc()).all()
    return [{
        "id": u.id, "fullname": u.fullname, "username": u.username, "email": u.email,
        "role": u.role, "is_active": u.is_active,
        "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S") if u.created_at else "—"
    } for u in users]

@app.post("/api/users")
def api_create_user(payload: AdminUserCreateInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    if db.query(User).filter((User.username == payload.username.strip()) | (User.email == payload.email.strip().lower())).first():
        raise HTTPException(status_code=400, detail="Username atau Email sudah terdaftar")
    
    new_user = User(
        fullname=payload.fullname.strip(),
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        password_hash=hash_password(payload.password),
        plain_password=payload.password,
        role=payload.role,
        is_verified=True,
        is_active=True
    )
    db.add(new_user)
    db.add(audit_event(request, "Create", f"Super Admin {user.username} membuat user baru: {new_user.username} ({new_user.role})"))
    db.commit()
    return {"status": "success", "message": "User berhasil dibuat"}

@app.post("/api/users/{target_id}/update")
def api_update_user(target_id: int, payload: AdminUserUpdateInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")

    target.fullname = payload.fullname.strip()
    target.role = payload.role
    target.is_active = payload.is_active
    if payload.new_password and len(payload.new_password.strip()) >= 6:
        clean_pwd = payload.new_password.strip()
        target.password_hash = hash_password(clean_pwd)
        target.plain_password = clean_pwd

    db.add(audit_event(request, "Update", f"Super Admin {user.username} mengubah data user: {target.username}"))
    db.commit()
    return {"status": "success", "message": "Data user diperbarui"}

@app.delete("/api/users/{target_id}")
def api_delete_user(target_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    if user.id == target_id:
        raise HTTPException(status_code=400, detail="Anda tidak dapat menghapus akun Anda sendiri")
    target = db.query(User).filter(User.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")

    db.delete(target)
    db.add(audit_event(request, "Delete", f"Super Admin {user.username} menghapus user: {target.username}"))
    db.commit()
    return {"status": "success"}

@app.post("/api/users/{user_id}/reveal-password")
def reveal_user_password(
    user_id: int,
    payload: RevealPasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN]))
):
    if not verify_password(payload.admin_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Password Super Admin salah!")

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")

    return {
        "status": "success",
        "password": target_user.plain_password or "(Belum disetel)"
    }

# ==============================================================================
# ROUTES: OLT, MONITORING & DASHBOARD
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    onus = db.query(OnuDevice).all()
    counts = {status: sum(onu.status == status for onu in onus) for status in ("Online", "DyingGasp", "LOS", "Offline")}
    total = len(onus)
    olt_configs = db.query(OLTConfig).all()
    config_by_name = {olt.name: olt for olt in olt_configs}
    names = sorted(({onu.olt_name for onu in onus if onu.olt_name}) | set(config_by_name))
    olt_rows = []
    for name in names:
        devices = [onu for onu in onus if onu.olt_name == name]
        config = config_by_name.get(name)
        olt_rows.append({"id": config.id if config else None, "name": name, "model": config.model if config else "OLT", "ip": config.ip_address if config else "—", "status": "Terdaftar" if config else "ONU database", "uptime": "Tidak tersedia dari database", "temperature": "—", "total_fan": "—", "total_onu": len(devices), "online": sum(x.status == "Online" for x in devices), "los": sum(x.status == "LOS" for x in devices), "dying_gasp": sum(x.status == "DyingGasp" for x in devices), "offline": sum(x.status == "Offline" for x in devices), "other": sum(x.status not in ("Online", "DyingGasp", "LOS", "Offline") for x in devices), "fans": []})
    percentage = lambda value: round(value / total * 100, 2) if total else 0
    selected_olt = max(olt_configs, key=lambda config: sum(onu.olt_name == config.name for onu in onus), default=None)
    dashboard_data = {"summary": {"total_olts": len(names), "total_onus": total, "selected_olt_id": selected_olt.id if selected_olt else None, "online_onus": counts["Online"], "online_percentage": percentage(counts["Online"]), "dying_gasp_onus": counts["DyingGasp"], "dying_gasp_percentage": percentage(counts["DyingGasp"]), "los_onus": counts["LOS"], "los_percentage": percentage(counts["LOS"]), "offline_onus": counts["Offline"], "offline_percentage": percentage(counts["Offline"])}, "olts": olt_rows}
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"data": dashboard_data})

@app.get("/api/onu/{onu_id}/detail")
def get_onu_detail(
    onu_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    
    # Ambil telemetri live jika OLT tersedia
    online_duration = "N/A"
    rx_onu = onu.rx_onu
    rx_olt = onu.rx_olt
    state = onu.status

    if olt:
        try:
            conn = open_telnet(olt)
            # Ambil status detail
            status_out = conn.send_command(f"show gpon onu state {onu.gpon_port}", read_timeout=10)
            for line in status_out.splitlines():
                if onu.gpon_port in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        state = parts[3]
            
            # Ambil detail optical power
            opt_out = conn.send_command(f"show gpon onu optical-power {onu.gpon_port}", read_timeout=10)
            rx_onu_match = re.search(r"Rx optical power\s*:\s*([-\d.]+)\s*\(dbm\)", opt_out, re.IGNORECASE)
            if rx_onu_match:
                rx_onu = float(rx_onu_match.group(1))

            rx_olt_match = re.search(r"OLT Rx optical power\s*:\s*([-\d.]+)\s*\(dbm\)", opt_out, re.IGNORECASE)
            if rx_olt_match:
                rx_olt = float(rx_olt_match.group(1))

            # Ambil online duration / uptime
            detail_out = conn.send_command(f"show gpon onu detail-info {onu.gpon_port}", read_timeout=10)
            duration_match = re.search(r"Online Duration\s*:\s*([^\r\n]+)", detail_out, re.IGNORECASE)
            if duration_match:
                online_duration = duration_match.group(1).strip()

            conn.disconnect()
        except Exception as e:
            print(f"Gagal mengambil live optical ONU {onu.sn_mac}: {e}")

    return {
        "status": "success",
        "data": {
            "id": onu.id,
            "olt_name": onu.olt_name,
            "gpon_port": onu.gpon_port,
            "sn_mac": onu.sn_mac,
            "actual_type": onu.actual_type or "ZTE-GPON",
            "onu_type": getattr(onu, "onu_type", onu.actual_type or "ZTE-GPON"),
            "customer_name": onu.customer_name,
            "description": onu.description or "",
            "state": state,
            "rx_onu": rx_onu,
            "rx_olt": rx_olt,
            "online_duration": online_duration
        }
    }

# 1. Endpoint alias agar pemanggilan /full-details tetap kompatibel
@app.get("/api/onu/{onu_id}/full-details")
def get_onu_full_details_alias(
    onu_id: int, 
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))
):
    return get_onu_detail(onu_id=onu_id, db=db, user=user)

@app.post("/api/onu/{onu_id}/move")
def move_onu_port(
    onu_id: int, 
    payload: OnuMoveInput, 
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan di database.")
    
    target_slot = payload.target_slot
    target_port = payload.target_port
    
    # 1. Tentukan target_onu_id (auto allocation atau manual)
    if payload.mode == "auto" or payload.target_onu_id is None:
        existing_onus = db.query(OnuDevice).filter(
            OnuDevice.olt_name == onu.olt_name,
            OnuDevice.gpon_port.like(f"%{target_slot}/{target_port}:%")
        ).all()
        
        used_ids = set()
        for dev in existing_onus:
            try:
                used_ids.add(int(dev.gpon_port.split(":")[-1]))
            except (ValueError, IndexError):
                pass
        
        new_onu_id = 1
        while new_onu_id in used_ids:
            new_onu_id += 1
            if new_onu_id > 128:
                raise HTTPException(status_code=400, detail=f"Port {target_slot}/{target_port} sudah penuh (maksimal 128 ONU).")
    else:
        new_onu_id = payload.target_onu_id

    old_port_full = onu.gpon_port  # misal: "gpon-onu_1/1/1:2" atau "1/1/1:2"
    new_port_full = f"gpon-onu_{target_slot}/{target_port}:{new_onu_id}"

    # 2. Parsing interface OLT lama dan ID lama
    # Format GPON ZTE: gpon-olt_1/slot/port
    clean_old = old_port_full.replace("gpon-onu_", "").replace("gpon-olt_", "")
    try:
        old_slot_port, old_onu_index = clean_old.split(":")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Format port lama tidak valid: {old_port_full}")

    # Cek mode mock
    is_mock = os.getenv("MOCK_OLT", "false").lower() in ("true", "1", "yes")

    # Ambil data profil OLT
    olt = None
    if hasattr(onu, "olt_id") and onu.olt_id:
        olt = db.query(OLTConfig).filter(OLTConfig.id == onu.olt_id).first()
    if not olt and hasattr(onu, "olt_name") and onu.olt_name:
        olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()

    # 3. Eksekusi CLI Netmiko ke ZTE OLT Fisik
    if not is_mock and olt:
        password = get_telnet_password(olt) if "get_telnet_password" in globals() else getattr(olt, "telnet_password", None)
        if not password:
            raise HTTPException(status_code=503, detail=f"Kredensial OLT {olt.name} belum disetel di OLT Management.")

        # Interface OLT ZTE C300/C320 menggunakan prefiks 'gpon-olt_'
        old_olt_interface = f"gpon-olt_{old_slot_port}"
        target_olt_interface = f"gpon-olt_{target_slot}/{target_port}"

        # Tipe ONU (default ke ZTE-F660 atau tipe yang tersimpan di field onu_type)
        onu_type = getattr(onu, "onu_type", None) or "ZTE-F660"

        commands = [
            # Hapus ONU di port lama
            f"interface {old_olt_interface}",
            f"no onu {old_onu_index}",
            "exit",
            # Daftarkan ONU di port tujuan
            f"interface {target_olt_interface}",
            f"onu {new_onu_id} type {onu_type} sn {onu.sn_mac}",
            "exit",
            "write"
        ]

        from netmiko import ConnectHandler
        device_params = {
            "device_type": "zte_zxros_telnet",
            "host": olt.ip_address,
            "username": olt.telnet_username,
            "password": password,
            "port": getattr(olt, "telnet_port", 23) or 23,
            "timeout": 15
        }

        try:
            with ConnectHandler(**device_params) as net_connect:
                net_connect.enable()
                output = net_connect.send_config_set(commands)
                if re.search(r"(% Error|% Ambiguous|% Incomplete|% Unknown)", output, re.IGNORECASE):
                    raise HTTPException(status_code=502, detail=f"OLT menolak migrasi port: {output}")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Gagal menghubungkan ke OLT ({olt.ip_address}): {str(exc)[:500]}")

    # 4. Simpan perubahan ke Database
    try:
        onu.gpon_port = new_port_full

        if "audit_event" in globals():
            audit_msg = (
                f"[SIMULASI] Migrasi port ONU {onu.sn_mac} dari {old_port_full} ke {new_port_full}"
                if is_mock
                else f"Push CLI Migrasi port ONU {onu.sn_mac} dari {old_port_full} ke {new_port_full}"
            )
            db.add(audit_event(request, "Update", audit_msg))

        db.commit()
    except Exception as db_err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Gagal menyimpan migrasi ke database: {str(db_err)}")

    return {
        "status": "success",
        "message": f"[{'SIMULASI' if is_mock else 'HARDWARE'}] ONU {onu.customer_name or onu.sn_mac} berhasil dipindahkan ke {new_port_full}."
    }

@app.patch("/api/onu/{onu_id}/metadata")
def update_onu_metadata(
    onu_id: int,
    payload: OnuMetadataUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan.")

    clean_name = re.sub(r"[^A-Za-z0-9_-]", "", payload.customer_name.strip())
    clean_desc = re.sub(r"[^A-Za-z0-9_-]", "", payload.description.strip())
    if not clean_name:
        clean_name = f"ONU_{onu.id}"

    # Cek mode mock
    is_mock = os.getenv("MOCK_OLT", "false").lower() in ("true", "1", "yes")

    # Ambil data OLT terkait ONU ini
    olt = db.query(OLTConfig).filter(OLTConfig.id == onu.olt_id).first() if hasattr(onu, "olt_id") else None

    # Eksekusi ke perangkat fisik jika bukan mode mock
    if not is_mock and olt:
        password = get_telnet_password(olt) if "get_telnet_password" in globals() else getattr(olt, "telnet_password", None)
        if not password:
            raise HTTPException(status_code=503, detail=f"Kredensial OLT {olt.name} belum disetel di OLT Management.")

        # Format interface ZTE: gpon-onu_1/{slot}/{port}:{onu_id}
        # Contoh onu.gpon_port: "1/1/1:1" -> "gpon-onu_1/1/1:1"
        port_identifier = onu.gpon_port if onu.gpon_port.startswith("gpon-onu_") else f"gpon-onu_{onu.gpon_port}"

        commands = [
            f"interface {port_identifier}",
            f"name {clean_name}",
        ]
        if clean_desc:
            commands.append(f"description {clean_desc}")
        commands.extend(["exit", "write"])

        from netmiko import ConnectHandler
        device_params = {
            "device_type": "zte_zxros_telnet",
            "host": olt.ip_address,
            "username": olt.telnet_username,
            "password": password,
            "port": getattr(olt, "telnet_port", 23) or 23,
            "timeout": 15
        }

        try:
            with ConnectHandler(**device_params) as net_connect:
                net_connect.enable()
                output = net_connect.send_config_set(commands)
                if re.search(r"(% Error|% Ambiguous|% Incomplete|% Unknown)", output, re.IGNORECASE):
                    raise HTTPException(status_code=502, detail=f"OLT menolak konfigurasi: {output}")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Gagal menghubungkan ke OLT ({olt.ip_address}): {str(exc)[:500]}")

    # Simpan ke Database
    try:
        onu.customer_name = payload.customer_name.strip()
        onu.description = payload.description.strip()

        if "audit_event" in globals():
            audit_msg = (
                f"[SIMULASI] Update metadata ONU {onu.sn_mac} ({clean_name})"
                if is_mock
                else f"Push CLI Update metadata ONU {onu.sn_mac} ({clean_name}) ke OLT"
            )
            db.add(audit_event(request, "Update", audit_msg))

        db.commit()
    except Exception as db_err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Gagal menyimpan ke database: {str(db_err)}")

    return {
        "status": "success",
        "message": f"[{'SIMULASI' if is_mock else 'HARDWARE'}] Metadata ONU {onu.sn_mac} berhasil diperbarui.",
        "data": {
            "customer_name": onu.customer_name,
            "description": onu.description
        }
    }

@app.post("/api/onu/{onu_id}/action")
def execute_onu_action(
    onu_id: int,
    action: str = Form(...), # reboot, clear-config, show-config, resync
    request: Request = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    if not olt:
        raise HTTPException(status_code=400, detail="OLT tidak terdaftar")

    try:
        conn = open_telnet(olt)
        output = ""
        
        if action == "reboot":
            output = conn.send_command(f"reset onu {onu.gpon_port}", read_timeout=10)
        elif action == "clear-config":
            output = conn.send_command(f"clear gpon onu config {onu.gpon_port}", read_timeout=15)
        elif action == "show-config":
            output = conn.send_command(f"show running-config interface {onu.gpon_port}", read_timeout=15)
        elif action == "resync":
            output = conn.send_command(f"show gpon onu detail-info {onu.gpon_port}", read_timeout=15)
        
        conn.disconnect()
        db.add(audit_event(request, "Action", f"Eksekusi {action} pada ONU {onu.gpon_port} ({onu.sn_mac})"))
        db.commit()
        return {"status": "success", "action": action, "output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal mengeksekusi {action}: {e}")

@app.post("/api/onu/{onu_id}/replace-sn")
def replace_onu_sn(
    onu_id: int,
    payload: OnuReplaceSnInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    clean_sn = payload.new_sn.strip().upper()
    
    # Eksekusi CLI modifikasi SN pada OLT
    if olt:
        try:
            conn = open_telnet(olt)
            port_base = onu.gpon_port.rsplit(":", 1)[0]
            onu_num = onu.gpon_port.rsplit(":", 1)[1]
            cmds = [
                "conf t",
                f"interface {port_base}",
                f"onu {onu_num} sn {clean_sn}",
                "exit",
                "write"
            ]
            for cmd in cmds:
                conn.send_command(cmd, read_timeout=5)
            conn.disconnect()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Gagal update SN di OLT: {e}")

    old_sn = onu.sn_mac
    onu.sn_mac = clean_sn
    db.add(audit_event(request, "Update", f"Ganti SN ONU {onu.gpon_port} dari {old_sn} ke {clean_sn}"))
    db.commit()
    return {"status": "success", "message": f"SN berhasil diganti ke {clean_sn}"}

@app.delete("/api/onu/{onu_id}")
def delete_onu_config(
    onu_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    if olt:
        try:
            conn = open_telnet(olt)
            port_base = onu.gpon_port.rsplit(":", 1)[0]
            onu_num = onu.gpon_port.rsplit(":", 1)[1]
            cmds = [
                "conf t",
                f"interface {port_base}",
                f"no onu {onu_num}",
                "exit",
                "write"
            ]
            for cmd in cmds:
                conn.send_command(cmd, read_timeout=5)
            conn.disconnect()
        except Exception as e:
            print(f"Warning: Gagal menghapus ONU dari OLT hardware: {e}")

    db.delete(onu)
    db.add(audit_event(request, "Delete", f"Hapus konfigurasi ONU {onu.sn_mac} ({onu.customer_name})"))
    db.commit()
    return {"status": "success", "message": "Konfigurasi ONU berhasil dihapus"}

# =========================================================
# === TARUH DI SINI (Di bawah move_onu_port / blok ONU) ===
# =========================================================

@app.get("/api/traffic/{onu_id}/history")
def get_traffic_history(
    onu_id: int,
    range: str = "1h",
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))
):
    samples = db.query(TrafficSample).filter(
        TrafficSample.onu_id == onu_id
    ).order_by(TrafficSample.timestamp.desc()).limit(60).all()

    return {
        "status": "success",
        "data": [
            {
                "timestamp": s.timestamp.isoformat() if hasattr(s.timestamp, "isoformat") else str(s.timestamp),
                "in_octets": s.in_octets,
                "out_octets": s.out_octets,
                "in_rate_kbps": getattr(s, "in_rate_kbps", 0),
                "out_rate_kbps": getattr(s, "out_rate_kbps", 0)
            }
            for s in reversed(samples)
        ]
    }


@app.get("/all-onus", response_class=HTMLResponse)
def all_onus_page(request: Request, status: str = "ALL", db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    allowed_statuses = {"ALL", "Online", "DyingGasp", "LOS", "Offline"}
    selected_status = status if status in allowed_statuses else "ALL"
    custom_settings = get_customization_settings(db)
    good_threshold = custom_settings["good_threshold"]
    warning_threshold = custom_settings["warning_threshold"]
    onus = db.query(OnuDevice).order_by(OnuDevice.id.desc()).all()
    total_onus = len(onus)
    good_count = sum(1 for onu in onus if onu.rx_onu is not None and onu.rx_onu >= good_threshold)
    warning_count = sum(1 for onu in onus if onu.rx_onu is not None and warning_threshold <= onu.rx_onu < good_threshold)
    critical_count = sum(1 for onu in onus if onu.rx_onu is not None and onu.rx_onu < warning_threshold)
    other_count = total_onus - (good_count + warning_count + critical_count)
    good_olt_count = sum(1 for onu in onus if onu.rx_olt is not None and onu.rx_olt >= good_threshold)
    warning_olt_count = sum(1 for onu in onus if onu.rx_olt is not None and warning_threshold <= onu.rx_olt < good_threshold)
    critical_olt_count = sum(1 for onu in onus if onu.rx_olt is not None and warning_olt_count <= onu.rx_olt < good_threshold)
    status_counts = {status_name: sum(1 for onu in onus if onu.status == status_name) for status_name in ("Online", "Offline", "LOS", "DyingGasp")}
    olt_names = sorted({onu.olt_name for onu in onus if onu.olt_name})
    card_names = sorted({onu.gpon_port.split("/")[1] for onu in onus if onu.gpon_port and len(onu.gpon_port.split("/")) > 2})
    pon_names = sorted({onu.gpon_port.rsplit(":", 1)[0] for onu in onus if onu.gpon_port and ":" in onu.gpon_port})
    onu_types = sorted({onu.actual_type for onu in onus if onu.actual_type})

    stats = {
        "good_percentage": round((good_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "warning_percentage": round((warning_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "critical_percentage": round((critical_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "other_percentage": round((other_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "good_count": good_count, "warning_count": warning_count, "critical_count": critical_count, "other_count": other_count,
        "good_olt_count": good_olt_count, "warning_olt_count": warning_olt_count, "critical_olt_count": critical_olt_count,
        "los_count": status_counts["LOS"], "na_count": sum(1 for onu in onus if onu.rx_onu is None)
    }

    return templates.TemplateResponse(
        request=request, name="all_onus.html",
        context={"onus": onus, "stats": stats, "selected_status": selected_status, "olt_names": olt_names, "card_names": card_names, "pon_names": pon_names, "onu_types": onu_types, "custom_settings": custom_settings}
    )

CUSTOMIZATION_COLUMNS = [
    ("olt", "OLT"), ("name", "Pelanggan"), ("description", "Deskripsi"),
    ("pppoe", "PPPoE"), ("port", "GPON Port"), ("status", "Status"),
    ("rx_olt", "RX OLT"), ("rx_onu", "RX ONU"), ("serial", "SN / MAC"), ("type", "Tipe ONU"),
]
DEFAULT_CUSTOMIZATION = {
    "desktop_columns": [key for key, _ in CUSTOMIZATION_COLUMNS],
    "mobile_columns": ["name", "port", "status", "rx_onu"],
    "good_threshold": -27.0,
    "warning_threshold": -30.0,
}

def get_customization_settings(db: Session):
    settings = {
        "desktop_columns": list(DEFAULT_CUSTOMIZATION["desktop_columns"]),
        "mobile_columns": list(DEFAULT_CUSTOMIZATION["mobile_columns"]),
        "good_threshold": DEFAULT_CUSTOMIZATION["good_threshold"],
        "warning_threshold": DEFAULT_CUSTOMIZATION["warning_threshold"],
    }
    entry = db.query(OLTSettingEntry).filter(
        OLTSettingEntry.category == "system", OLTSettingEntry.name == "customization"
    ).first()
    if entry:
        try:
            saved = json.loads(entry.data_json)
            for key in settings:
                if key in saved:
                    settings[key] = saved[key]
        except (TypeError, ValueError):
            pass
    allowed_keys = {key for key, _ in CUSTOMIZATION_COLUMNS}
    for key in ("desktop_columns", "mobile_columns"):
        chosen = settings[key]
        settings[key] = [value for value in chosen if value in allowed_keys] if isinstance(chosen, list) else []
        if not settings[key]:
            settings[key] = list(DEFAULT_CUSTOMIZATION[key])
    try:
        settings["good_threshold"] = float(settings["good_threshold"])
        settings["warning_threshold"] = float(settings["warning_threshold"])
        if not -32 <= settings["warning_threshold"] < settings["good_threshold"] <= -20:
            raise ValueError
    except (TypeError, ValueError):
        settings["good_threshold"] = DEFAULT_CUSTOMIZATION["good_threshold"]
        settings["warning_threshold"] = DEFAULT_CUSTOMIZATION["warning_threshold"]
    return settings

@app.get("/customization", response_class=HTMLResponse)
def customization_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    onus = db.query(OnuDevice).order_by(OnuDevice.id.desc()).all()
    settings = get_customization_settings(db)
    return templates.TemplateResponse(request=request, name="customization.html", context={
        "onus": onus, "columns": CUSTOMIZATION_COLUMNS, "mobile_columns": CUSTOMIZATION_COLUMNS,
        "settings": settings,
    })

@app.get("/tr069-profiles", response_class=HTMLResponse)
def tr069_profiles_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    profiles = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "tr069_profile").order_by(OLTSettingEntry.name).all()
    olts = db.query(OLTConfig).order_by(OLTConfig.name).all()
    return templates.TemplateResponse(request=request, name="tr069_profiles.html", context={
        "profiles": [{"id": p.id, "name": p.name, "data": {k: v for k, v in json.loads(p.data_json).items() if k != "password"}, "has_password": bool(json.loads(p.data_json).get("password"))} for p in profiles],
        "olts": olts,
    })

@app.get("/graphs", response_class=HTMLResponse)
def graphs_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    onus = db.query(OnuDevice).order_by(OnuDevice.olt_name, OnuDevice.gpon_port).all()
    olt_names = [row[0] for row in db.query(OnuDevice.olt_name).distinct().order_by(OnuDevice.olt_name).all()]
    card_slots = sorted({onu.gpon_port.split("/")[1] for onu in onus if onu.gpon_port and len(onu.gpon_port.split("/")) > 2})
    pon_ports = sorted({onu.gpon_port.rsplit(":", 1)[0] for onu in onus if onu.gpon_port and ":" in onu.gpon_port})
    return templates.TemplateResponse(request=request, name="graphs.html", context={"onus": onus, "olt_names": olt_names, "card_slots": card_slots, "pon_ports": pon_ports})

@app.get("/olt-management", response_class=HTMLResponse)
def olt_management_page(request: Request, olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    configs = db.query(OLTConfig).order_by(OLTConfig.name).all()
    olts = []
    for config in configs:
        name = config.name
        devices = db.query(OnuDevice).filter(OnuDevice.olt_name == name).all()
        olts.append({
            "id": config.id,
            "name": name,
            "model": config.model,
            "ip": config.ip_address,
            "temperature": "—",
            "total_onu": len(devices),
            "uptime": format_uptime(config.uptime_ticks),
            "synced": config.last_sync.strftime("%Y-%m-%d %H:%M:%S") if config.last_sync else "Belum pernah",
            "telnet": config.telnet_status or "Belum dites",
            "snmp": config.snmp_status or "Belum dites",
            "snmp_version": config.snmp_version,
            "snmp_port": config.snmp_port,
            "telnet_username": config.telnet_username,
            "telnet_port": config.telnet_port,
            "env_suffix": env_key(name),
            "tested": config.last_connection_test.strftime("%Y-%m-%d %H:%M:%S") if config.last_connection_test else "Belum dites",
            "online": sum(x.status == "Online" for x in devices),
            "los": sum(x.status == "LOS" for x in devices),
            "dying_gasp": sum(x.status == "DyingGasp" for x in devices),
            "offline": sum(x.status == "Offline" for x in devices)
        })
    return templates.TemplateResponse(request=request, name="olt_management.html", context={"olts": olts, "selected_olt_id": olt_id})

@app.get("/olt-settings", response_class=HTMLResponse)
def olt_settings_page(request: Request, olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    configs = db.query(OLTConfig).order_by(OLTConfig.name).all()
    selected = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first() if olt_id else None
    if not selected and configs and olt_id is None:
        onu_counts = dict(db.query(OnuDevice.olt_name, sql_func.count(OnuDevice.id)).group_by(OnuDevice.olt_name).all())
        selected = max(configs, key=lambda config: onu_counts.get(config.name, 0))
    devices = db.query(OnuDevice).filter(OnuDevice.olt_name == selected.name).all() if selected else []
    slots = {}
    for device in devices:
        port = device.gpon_port or ""
        match = re.match(r"^(\d+)/(\d+)/(\d+)(?::\d+)?$", port)
        if not match:
            continue
        frame, slot, pon = match.groups()
        card = slots.setdefault(slot, {"slot": slot, "pon_ports": set(), "ports": {}, "total_onu": 0, "online": 0, "los": 0, "offline": 0})
        card["pon_ports"].add(pon)
        port_data = card["ports"].setdefault(pon, {"port": pon, "interface": f"gpon_{frame}/{slot}/{pon}", "total_onu": 0, "online": 0, "los": 0, "offline": 0})
        port_data["total_onu"] += 1
        if device.status == "Online":
            port_data["online"] += 1
        elif device.status == "LOS":
            port_data["los"] += 1
        elif device.status == "Offline":
            port_data["offline"] += 1
        card["total_onu"] += 1
        if device.status == "Online":
            card["online"] += 1
        elif device.status == "LOS":
            card["los"] += 1
        elif device.status == "Offline":
            card["offline"] += 1
    card_inventory = sorted(slots.values(), key=lambda card: int(card["slot"]))
    for card in card_inventory:
        card["pon_port_inventory"] = sorted(card["ports"].values(), key=lambda port: int(port["port"]))
        card["pon_ports"] = len(card["pon_ports"])
    summary = {
        "uplink_cards": "—", "gpon_cards": len(card_inventory) if card_inventory else "—", "epon_cards": "—",
        "total_onu": len(devices), "online": sum(x.status == "Online" for x in devices),
        "los": sum(x.status == "LOS" for x in devices), "dying_gasp": sum(x.status == "DyingGasp" for x in devices),
        "offline": sum(x.status == "Offline" for x in devices), "other": sum(x.status not in ("Online", "DyingGasp", "LOS", "Offline") for x in devices),
    }
    olt = {
        "id": selected.id, "name": selected.name, "ip": selected.ip_address, "model": selected.model,
        "status": "Online" if selected.snmp_status == "Connected" or selected.telnet_status == "Connected" else "Unknown",
        "uptime": format_uptime(selected.uptime_ticks),
        "updated": selected.last_connection_test.strftime("%Y-%m-%d %H:%M:%S") if selected.last_connection_test else "Belum disinkronkan",
    } if selected else None
    now_utc = datetime.now(timezone.utc)
    timezone_options = []
    for zone_name in sorted(available_timezones()):
        local_now = now_utc.astimezone(ZoneInfo(zone_name))
        raw_offset = local_now.strftime("%z") or "+0000"
        formatted_offset = f"{raw_offset[:3]}:{raw_offset[3:]}"
        abbreviation = local_now.tzname()
        suffix = f" ({abbreviation}, UTC{formatted_offset})" if abbreviation and abbreviation != zone_name else f" (UTC{formatted_offset})"
        timezone_options.append({"name": zone_name, "label": f"{zone_name}{suffix}"})
    clock_entry = db.query(OLTSettingEntry).filter(
        OLTSettingEntry.category == "system", OLTSettingEntry.name == "clock"
    ).first()
    selected_timezone = "Asia/Jakarta"
    if clock_entry:
        try:
            saved_timezone = json.loads(clock_entry.data_json).get("timezone", "Asia/Jakarta")
            if saved_timezone in available_timezones():
                selected_timezone = saved_timezone
        except (TypeError, ValueError):
            pass
    return templates.TemplateResponse(request=request, name="olt_settings.html", context={
        "summary": summary, "olt_names": [config.name for config in configs], "selected_olt": olt,
        "card_inventory": card_inventory, "timezone_options": timezone_options,
        "selected_timezone": selected_timezone,
    })

@app.get("/activity-log", response_class=HTMLResponse)
def activity_log_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    events = db.query(ActivityEvent).order_by(ActivityEvent.created_at.desc()).limit(500).all()
    logs = [{"date": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "—", "user": event.username, "type": event.event_type, "info": event.information, "ip": event.client_ip or "—", "agent": event.user_agent or "—"} for event in events]
    totals = {"total": db.query(sql_func.count(ActivityEvent.id)).scalar() or 0}
    for event_type in ("Login", "Delete", "Update"):
        key = "update_count" if event_type == "Update" else event_type.lower()
        totals[key] = db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type == event_type).scalar() or 0

    # Ambil daftar unik event_type dari database untuk mengisi dropdown filter
    raw_types = db.query(ActivityEvent.event_type).distinct().filter(ActivityEvent.event_type.isnot(None)).all()
    event_types = sorted([t[0] for t in raw_types if t[0]])

    return templates.TemplateResponse(
        request=request,
        name="activity_log.html",
        context={
            "logs": logs,
            "totals": totals,
            "event_types": event_types
        }
    )

@app.get("/add-onu", response_class=HTMLResponse)
def manual_add_onu_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    return templates.TemplateResponse(request=request, name="add_onu.html", context={
        "olts": db.query(OLTConfig).order_by(OLTConfig.name).all()
    })

# =====================================================================
# OLT DYNAMIC PROVISIONING DATA (VLAN, T-CONT & TRAFFIC PROFILES)
# =====================================================================

@app.get("/api/olts/{olt_id}/vlans")
def get_olt_vlans(
    olt_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    """Mengambil daftar VLAN aktif langsung dari CLI OLT ZTE (show vlan summary)."""
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")

    try:
        conn = open_telnet(olt)
        output = conn.send_command("show vlan summary", read_timeout=15)
        conn.disconnect()

        vlans = []
        capture = False
        for line in output.splitlines():
            line = line.strip()
            if "Details are following:" in line:
                capture = True
                continue
            if capture:
                if not line or line.endswith("#"):
                    break
                parts = [v.strip() for v in line.split(",") if v.strip().isdigit()]
                vlans.extend([int(v) for v in parts])

        vlans = sorted(list(set(vlans)))
        return {"status": "success", "vlans": vlans}
    except Exception as e:
        print(f"Gagal mengambil VLAN dari OLT {olt.name}: {e}")
        return {"status": "error", "message": str(e), "vlans": []}


@app.get("/api/olts/{olt_id}/profiles")
def get_olt_profiles(
    olt_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    """Mengambil daftar profil T-CONT (Upload) dan Traffic (Download) dari OLT ZTE."""
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")

    try:
        conn = open_telnet(olt)
        
        # 1. Ambil T-CONT Profiles (Upload)
        tcont_out = conn.send_command("show gpon profile tcont", read_timeout=15)
        upload_profiles = re.findall(r"Profile name\s*:\s*([^\r\n\s]+)", tcont_out)
        
        # 2. Ambil Traffic Profiles (Download)
        traffic_out = conn.send_command("show gpon profile traffic", read_timeout=15)
        download_profiles = re.findall(r"Profile name\s*:\s*([^\r\n\s]+)", traffic_out)
        
        conn.disconnect()

        # Hilangkan duplikasi dan letakkan '1G' di posisi teratas
        upload_profiles = sorted(list(set(upload_profiles)), key=lambda x: (x != "1G", x))
        download_profiles = sorted(list(set(download_profiles)), key=lambda x: (x != "1G", x))

        return {
            "status": "success",
            "upload_profiles": upload_profiles,
            "download_profiles": download_profiles
        }
    except Exception as e:
        print(f"Gagal mengambil profil dari OLT {olt.name}: {e}")
        return {
            "status": "error",
            "message": str(e),
            "upload_profiles": [],
            "download_profiles": []
        }

# =====================================================================
# ROUTE HALAMAN UNREGISTERED ONUS
# =====================================================================
@app.get("/unregistered-onus", response_class=HTMLResponse)
def unregistered_onus_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    olts = db.query(OLTConfig).order_by(OLTConfig.name).all()
    unregistered_list = []

    for olt in olts:
        try:
            conn = open_telnet(olt)
            output = conn.send_command("show gpon onu uncfg", read_timeout=15)
            conn.disconnect()

            print(f"[DEBUG UNCFG RAW OUTPUT dari {olt.name}]:\n{output}")

            for line in output.splitlines():
                line = line.strip()
                match = re.search(r"(?:gpon-onu_)?1/(\d+)/(\d+):(\d+)\s+([A-Z0-9]+)\s*(\w+)?", line, re.IGNORECASE)
                if match:
                    slot, port, onu_id, sn, state = match.groups()
                    unregistered_list.append({
                        "olt_id": olt.id,
                        "olt_name": olt.name,
                        "slot": int(slot),
                        "port": int(port),
                        "onu_id": int(onu_id),
                        "sn": sn.upper(),
                        "sn_mac": sn.upper(),
                        "state": state or "unknown",
                        "interface": f"1/{slot}/{port}:{onu_id}",
                        "gpon_port": f"1/{slot}/{port}:{onu_id}"
                    })
        except Exception as e:
            print(f"Gagal mengambil uncfg dari {olt.name}: {e}")

    print(f"[DEBUG UNCFG PARSED LIST]: {unregistered_list}")

    return templates.TemplateResponse(
        request=request,
        name="unregistered_onus.html",
        context={"unregistered_onus": unregistered_list, "olts": olts}
    )

# ==============================================================================
# PYDANTIC SCHEMAS & INPUT MODELS
# ==============================================================================
class ONURequest(BaseModel):
    olt_ip: str | None = None
    olt_name: str | None = None
    olt_id: int | None = None
    slot: int
    port: int
    onu_id: int | None = None
    sn_onu: str
    nama_pelanggan: str
    description: str | None = None
    actual_type: str = "HG6145D2"
    vlan_id: int
    pppoe_user: str
    pppoe_pass: str
    profil_paket: str = "DEFAULT"

class OLTInput(BaseModel):
    id: int | None = None
    name: str
    ip_address: str
    model: str = "ZTE C300/C320"
    snmp_version: str = "2c"
    snmp_port: int = 161
    snmp_community: str | None = None
    telnet_username: str = "admin"
    telnet_password: str | None = None
    telnet_port: int = 23

class SettingEntryInput(BaseModel):
    category: str
    name: str
    data: dict = Field(default_factory=dict)
    id: int | None = None
    olt_id: int | None = None

class DirectVlanCreateInput(BaseModel):
    olt_id: int
    vlan_id: int
    vlan_name: str

class CustomizationInput(BaseModel):
    desktop_columns: list[str]
    mobile_columns: list[str]
    good_threshold: float
    warning_threshold: float

# ==============================================================================
# API: OLT & TELEMETRY SUMMARY
# ==============================================================================
@app.get("/api/olts")
def api_list_olts(db: Session = Depends(get_db)):
    return [{"id": olt.id, "name": olt.name, "ip_address": olt.ip_address, "model": olt.model, "snmp_version": olt.snmp_version, "snmp_port": olt.snmp_port, "telnet_username": olt.telnet_username, "telnet_port": olt.telnet_port} for olt in db.query(OLTConfig).order_by(OLTConfig.name).all()]

@app.get("/api/summary")
def api_summary(db: Session = Depends(get_db)):
    counts = dict(db.query(OnuDevice.status, sql_func.count(OnuDevice.id)).group_by(OnuDevice.status).all())
    d_gasp = counts.get("DyingGasp", 0)
    los_val = counts.get("LOS", 0)
    return {
        "DyingGasp": d_gasp, 
        "LOS": los_val,
        "dying_gasp": d_gasp,
        "los": los_val
    }

@app.post("/api/olts")
def api_save_olt(payload: OLTInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    name = payload.name.strip()
    ip_address = payload.ip_address.strip()
    if not name or not ip_address or payload.snmp_version != "2c":
        raise HTTPException(status_code=400, detail="Isi nama/IP OLT; versi SNMP yang didukung saat ini v2c.")
    if not 1 <= payload.snmp_port <= 65535 or not 1 <= payload.telnet_port <= 65535:
        raise HTTPException(status_code=400, detail="Port SNMP dan Telnet harus berada pada rentang 1–65535.")
    olt = db.query(OLTConfig).filter(OLTConfig.id == payload.id).first() if payload.id else db.query(OLTConfig).filter(OLTConfig.name == name).first()
    if payload.id and not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")
    if db.query(OLTConfig).filter(OLTConfig.name == name, OLTConfig.id != (olt.id if olt else 0)).first():
        raise HTTPException(status_code=409, detail="Nama OLT sudah digunakan.")
    if not olt:
        olt = OLTConfig(name=name, ip_address=ip_address)
        db.add(olt)
        event_type, verb = "Create", "Menambahkan"
        old_name = None
    else:
        old_name = olt.name
        event_type, verb = "Update", "Memperbarui"
    if db.query(OLTConfig).filter(OLTConfig.ip_address == ip_address, OLTConfig.id != (olt.id if olt else 0)).first():
        raise HTTPException(status_code=409, detail="IP address sudah digunakan OLT lain.")
    olt.name, olt.ip_address, olt.model = name, ip_address, payload.model.strip()
    if old_name and old_name != name:
        db.query(OnuDevice).filter(OnuDevice.olt_name == old_name).update({OnuDevice.olt_name: name}, synchronize_session=False)
    olt.snmp_version, olt.snmp_port = payload.snmp_version, payload.snmp_port
    olt.telnet_username, olt.telnet_port = payload.telnet_username.strip(), payload.telnet_port
    if payload.snmp_community:
        olt.snmp_community_encrypted = encrypt_olt_secret(payload.snmp_community)
    if payload.telnet_password:
        olt.telnet_password_encrypted = encrypt_olt_secret(payload.telnet_password)
    db.add(audit_event(request, event_type, f"{verb} konfigurasi OLT {name} ({ip_address})"))
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Perubahan OLT gagal disimpan: {str(exc)[:500]}") from exc
    return {"status": "success", "id": olt.id}

# ==============================================================================
# API: OLT SETTINGS CRUD
# ==============================================================================
@app.get("/api/olt-settings/data")
def api_list_setting_entries(category: str, olt_id: int | None = None, db: Session = Depends(get_db)):
    allowed = {"uplink", "pon", "vlan", "onu_type", "vlan_profile", "ip_profile", "speed_profile", "system", "tr069_profile"}
    if category not in allowed:
        raise HTTPException(status_code=400, detail="Kategori pengaturan tidak dikenal")
    
    query = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == category)
    if olt_id is not None and hasattr(OLTSettingEntry, "olt_id"):
        query = query.filter((OLTSettingEntry.olt_id == olt_id) | (OLTSettingEntry.olt_id.is_(None)))
        
    entries = query.order_by(OLTSettingEntry.name).all()
    return [{"id": entry.id, "category": entry.category, "name": entry.name, "olt_id": getattr(entry, "olt_id", None), "data": json.loads(entry.data_json), "updated_at": entry.updated_at.isoformat() if entry.updated_at else None} for entry in entries]

@app.post("/api/olt-settings/data")
def api_save_setting_entry(payload: SettingEntryInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    allowed = {"uplink", "pon", "vlan", "onu_type", "vlan_profile", "ip_profile", "speed_profile", "system", "tr069_profile"}
    category, name = payload.category.strip(), payload.name.strip()
    if category not in allowed or not name or len(name) > 120:
        raise HTTPException(status_code=400, detail="Kategori atau nama pengaturan tidak valid")
    
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.id == payload.id, OLTSettingEntry.category == category).first() if payload.id else None
    
    dup_query = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == category, OLTSettingEntry.name == name)
    if hasattr(OLTSettingEntry, "olt_id") and payload.olt_id:
        dup_query = dup_query.filter(OLTSettingEntry.olt_id == payload.olt_id)
    if entry:
        dup_query = dup_query.filter(OLTSettingEntry.id != entry.id)
    if dup_query.first():
        raise HTTPException(status_code=409, detail="Nama profile sudah digunakan pada OLT ini")

    if not entry:
        match_query = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == category, OLTSettingEntry.name == name)
        if hasattr(OLTSettingEntry, "olt_id") and payload.olt_id:
            match_query = match_query.filter(OLTSettingEntry.olt_id == payload.olt_id)
        entry = match_query.first()

    if not entry:
        entry = OLTSettingEntry(category=category, name=name)
        if hasattr(entry, "olt_id"):
            entry.olt_id = payload.olt_id
        db.add(entry)
        event_type = "Create"
    else:
        event_type = "Update"
        if hasattr(entry, "olt_id") and payload.olt_id:
            entry.olt_id = payload.olt_id

    entry.name = name
    setting_data = dict(payload.data)
    if entry.id and category == "tr069_profile" and not setting_data.get("password"):
        setting_data["password"] = json.loads(entry.data_json).get("password", "")
    entry.data_json = json.dumps(setting_data, ensure_ascii=False)
    db.add(audit_event(request, event_type, f"{event_type} konfigurasi {category}: {name}"))
    db.commit()
    return {"status": "success", "id": entry.id}

@app.delete("/api/olt-settings/data/{entry_id}")
def api_delete_setting_entry(entry_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Konfigurasi tidak ditemukan")
    db.add(audit_event(request, "Delete", f"Menghapus konfigurasi {entry.category}: {entry.name}"))
    db.delete(entry)
    db.commit()
    return {"status": "success"}

# ==============================================================================
# API: DIRECT HARDWARE CLI CONFIGURATION ENGINE
# ==============================================================================
@app.post("/api/v1/olt/create-vlan")
def api_create_vlan_direct(
    payload: DirectVlanCreateInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    # 1. Validasi Rentang VLAN
    if not (1 <= payload.vlan_id <= 4094):
        raise HTTPException(status_code=400, detail="VLAN ID harus berada pada rentang 1-4094.")
    
    clean_vlan_name = re.sub(r"[^A-Za-z0-9_-]", "", payload.vlan_name.strip())
    if not clean_vlan_name:
        clean_vlan_name = f"VLAN_{payload.vlan_id}"

    # 2. Ambil Profil OLT
    olt = db.query(OLTConfig).filter(OLTConfig.id == payload.olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="Perangkat OLT tidak ditemukan.")

    # 3. Eksekusi Hardware / Netmiko jika bukan mock
    is_mock = os.getenv("MOCK_OLT", "false").lower() in ("true", "1", "yes")

    if not is_mock:
        password = get_telnet_password(olt) if "get_telnet_password" in globals() else getattr(olt, "telnet_password", None)
        if not password:
            raise HTTPException(status_code=503, detail=f"Kredensial OLT {olt.name} belum disetel di OLT Management.")

        commands = [
            f"vlan {payload.vlan_id}",
            f"name {clean_vlan_name}",
            "exit",
            "write"
        ]

        from netmiko import ConnectHandler
        device_params = {
            "device_type": "zte_zxros_telnet",  # <-- Gunakan driver telnet Netmiko
            "host": olt.ip_address,
            "username": olt.telnet_username,
            "password": password,
            "port": getattr(olt, "telnet_port", 23) or 23,
            "timeout": 15
        }

        try:
            with ConnectHandler(**device_params) as net_connect:
                net_connect.enable()
                output = net_connect.send_config_set(commands)
                if re.search(r"(% Error|% Ambiguous|% Incomplete|% Unknown)", output, re.IGNORECASE):
                    raise HTTPException(status_code=502, detail=f"OLT menolak konfigurasi: {output}")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Gagal menghubungkan ke OLT ({olt.ip_address}): {str(exc)[:500]}")

    # 4. Simpan / Perbarui Record di Database
    vlan_dict = {
        "vlan_id": payload.vlan_id,
        "vlan_name": clean_vlan_name,
        "access_ports": "-",
        "trunk_ports": "-"
    }

    try:
        # Filter spesifik per OLT agar tidak menimpa VLAN sasis lain
        entry_query = db.query(OLTSettingEntry).filter(
            OLTSettingEntry.category == "vlan",
            OLTSettingEntry.name == str(payload.vlan_id)
        )
        if hasattr(OLTSettingEntry, "olt_id"):
            entry_query = entry_query.filter(OLTSettingEntry.olt_id == olt.id)

        entry = entry_query.first()

        if not entry:
            entry = OLTSettingEntry(
                category="vlan",
                name=str(payload.vlan_id),
                data_json=json.dumps(vlan_dict)
            )
            if hasattr(entry, "olt_id"):
                entry.olt_id = olt.id
            db.add(entry)
        else:
            entry.data_json = json.dumps(vlan_dict)
            if hasattr(entry, "olt_id"):
                entry.olt_id = olt.id

        # 5. Catat Audit Log jika fungsi audit tersedia
        if "audit_event" in globals():
            audit_msg = (
                f"[SIMULASI] Buat VLAN {payload.vlan_id} ({clean_vlan_name}) pada {olt.name}"
                if is_mock
                else f"Push CLI VLAN {payload.vlan_id} ({clean_vlan_name}) ke OLT {olt.name}"
            )
            db.add(audit_event(request, "Create", audit_msg))

        db.commit()

    except Exception as db_err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Gagal menyimpan ke database: {str(db_err)}")

    return {
        "status": "success",
        "message": f"[{'SIMULASI' if is_mock else 'HARDWARE'}] VLAN {payload.vlan_id} ({clean_vlan_name}) berhasil dibuat untuk {olt.name}!",
        "vlan_id": payload.vlan_id,
        "vlan_name": clean_vlan_name
    }

@app.post("/api/olt/{olt_id}/sync-hardware")
def sync_olt_hardware(
    olt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan.")

    is_mock = os.getenv("MOCK_OLT", "false").lower() in ("true", "1", "yes")
    if is_mock:
        return {
            "status": "success",
            "message": f"[SIMULASI] Sinkronisasi OLT {olt.name} berhasil disimulasikan."
        }

    password = get_telnet_password(olt) if "get_telnet_password" in globals() else getattr(olt, "telnet_password", None)
    if not password:
        raise HTTPException(status_code=503, detail=f"Kredensial OLT {olt.name} belum disetel di OLT Management.")

    from netmiko import ConnectHandler
    device_params = {
        "device_type": "zte_zxros_telnet",
        "host": olt.ip_address,
        "username": olt.telnet_username,
        "password": password,
        "port": getattr(olt, "telnet_port", 23) or 23,
        "timeout": 20
    }

    try:
        with ConnectHandler(**device_params) as net_connect:
            net_connect.enable()
            output = net_connect.send_command("show gpon onu state", read_timeout=15)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gagal menghubungi OLT ({olt.ip_address}): {str(exc)[:400]}")

    synced_count = 0
    # Parsing baris output CLI ZTE: OnuIndex, Admin State, OMCC State, Phase State, Channel
    for line in output.splitlines():
        line = line.strip()
        if not line or "OnuIndex" in line or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            port_raw = parts[0]
            clean_port = port_raw if port_raw.startswith("gpon-onu_") else f"gpon-onu_{port_raw}"
            phase_state = parts[3].lower()  # working, dyinggasp, los, offline

            onu = db.query(OnuDevice).filter(
                OnuDevice.olt_id == olt.id,
                OnuDevice.gpon_port == clean_port
            ).first()

            if onu:
                onu.status = phase_state
                synced_count += 1

    if "audit_event" in globals():
        db.add(audit_event(request, "Sync", f"Sinkronisasi hardware OLT {olt.name}: {synced_count} ONU terverifikasi."))

    db.commit()

    return {
        "status": "success",
        "message": f"Sinkronisasi selesai. Sebanyak {synced_count} status ONU disesuaikan dengan kondisi fisik OLT {olt.name}."
    }

# ==============================================================================
# API: CUSTOMIZATION & DISPLAY
# ==============================================================================
@app.post("/api/customization")
def api_save_customization(payload: CustomizationInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    allowed = {key for key, _ in CUSTOMIZATION_COLUMNS}
    if not payload.desktop_columns or not payload.mobile_columns:
        raise HTTPException(status_code=400, detail="Pilih minimal satu kolom untuk tampilan desktop dan mobile.")
    if any(key not in allowed for key in payload.desktop_columns + payload.mobile_columns):
        raise HTTPException(status_code=400, detail="Pilihan kolom tidak dikenal.")
    if not -32 <= payload.warning_threshold < payload.good_threshold <= -20:
        raise HTTPException(status_code=400, detail="Ambang Warning dan Good harus berada di -32 sampai -20 dBm, dan Good harus lebih tinggi dari Warning.")

    entry = db.query(OLTSettingEntry).filter(
        OLTSettingEntry.category == "system", OLTSettingEntry.name == "customization"
    ).first()
    if not entry:
        entry = OLTSettingEntry(category="system", name="customization")
        db.add(entry)
    entry.data_json = json.dumps({
        "desktop_columns": list(dict.fromkeys(payload.desktop_columns)),
        "mobile_columns": list(dict.fromkeys(payload.mobile_columns)),
        "good_threshold": payload.good_threshold,
        "warning_threshold": payload.warning_threshold,
    })
    db.add(audit_event(request, "Update", "Memperbarui tampilan tabel All ONUs dan ambang sinyal"))
    try:
        db.commit()
        db.refresh(entry)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Customization gagal disimpan: {str(exc)[:400]}") from exc
    return {"status": "success", "persisted": True, "id": entry.id}

# ==============================================================================
# API: BACKUP REPOSITORY
# ==============================================================================
def _build_olt_backup(olt: OLTConfig, db: Session):
    settings = db.query(OLTSettingEntry).order_by(OLTSettingEntry.category, OLTSettingEntry.name).all()
    onus = db.query(OnuDevice).filter(OnuDevice.olt_name == olt.name).order_by(OnuDevice.gpon_port).all()
    def without_secrets(value):
        if isinstance(value, dict):
            return {key: ("[REDACTED]" if any(secret in key.lower() for secret in ("password", "community", "secret")) and item else without_secrets(item)) for key, item in value.items()}
        if isinstance(value, list):
            return [without_secrets(item) for item in value]
        return value
    return {
        "backup_scope": "application_configuration",
        "note": "Snapshot konfigurasi yang tersimpan di aplikasi; bukan hasil export running-config langsung dari perangkat OLT.",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "olt": {
            "id": olt.id, "name": olt.name, "ip_address": olt.ip_address, "model": olt.model,
            "snmp_version": olt.snmp_version, "snmp_port": olt.snmp_port,
            "telnet_username": olt.telnet_username, "telnet_port": olt.telnet_port,
            "snmp_community_configured": bool(olt.snmp_community_encrypted),
            "telnet_password_configured": bool(olt.telnet_password_encrypted),
        },
        "settings": [{"category": entry.category, "name": entry.name, "data": without_secrets(json.loads(entry.data_json))} for entry in settings],
        "onus": [{
            "customer_name": onu.customer_name, "description": onu.description,
            "pppoe_user": onu.pppoe_user, "gpon_port": onu.gpon_port,
            "status": onu.status, "sn_mac": onu.sn_mac, "actual_type": onu.actual_type,
        } for onu in onus],
    }

@app.post("/api/olt-settings/backups")
def create_olt_backup(request: Request, olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first() if olt_id else None
    if not olt:
        raise HTTPException(status_code=404, detail="OLT yang dipilih tidak ditemukan.")
    created = datetime.now(timezone.utc)
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", olt.name).strip("_") or f"olt-{olt.id}"
    filename = f"{safe_name}-config-{created.strftime('%Y%m%d-%H%M%S')}.json"
    snapshot = _build_olt_backup(olt, db)
    backup = OLTConfigBackup(olt_id=olt.id, filename=filename, backup_type="manual", content_json=json.dumps(snapshot, ensure_ascii=False))
    try:
        db.add(backup)
        db.add(audit_event(request, "Create", f"Membuat backup konfigurasi OLT {olt.name}"))
        db.commit()
        db.refresh(backup)
        older_backups = db.query(OLTConfigBackup).filter(
            OLTConfigBackup.olt_id == olt.id,
            OLTConfigBackup.backup_type == "manual",
            OLTConfigBackup.id != backup.id,
        ).order_by(OLTConfigBackup.created_at.desc(), OLTConfigBackup.id.desc()).all()
        for old_backup in older_backups[6:]:
            db.delete(old_backup)
        if len(older_backups) > 6:
            db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Backup gagal disimpan: {str(exc)[:400]}") from exc
    return {"status": "success", "id": backup.id, "filename": backup.filename}

@app.get("/api/olt-settings/backups")
def list_olt_backups(olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    query = db.query(OLTConfigBackup)
    if olt_id:
        query = query.filter(OLTConfigBackup.olt_id == olt_id)
    backups = query.order_by(OLTConfigBackup.created_at.desc(), OLTConfigBackup.id.desc()).all()
    auto_backups = [backup for backup in backups if backup.backup_type == "auto"][:7]
    manual_backups = [backup for backup in backups if backup.backup_type != "auto"][:7]
    backups = sorted(auto_backups + manual_backups, key=lambda backup: (backup.created_at or datetime.min.replace(tzinfo=timezone.utc), backup.id), reverse=True)
    records = [{
        "id": backup.id, "filename": backup.filename, "type": backup.backup_type,
        "size": len(backup.content_json.encode("utf-8")),
        "created_at": backup.created_at.isoformat() if backup.created_at else None,
    } for backup in backups]
    return {"backups": records, "last_auto": next((item for item in records if item["type"] == "auto"), None)}

@app.get("/api/olt-settings/backups/{backup_id}/download")
def download_olt_backup(backup_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    backup = db.query(OLTConfigBackup).filter(OLTConfigBackup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="File backup tidak ditemukan.")
    return Response(content=backup.content_json, media_type="application/json; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{backup.filename}"'})

# ==============================================================================
# API: PROVISIONING & REGISTRASI ONU
# ==============================================================================
@app.post("/api/v1/register-onu")
def register_onu(
    req: ONURequest, 
    request: Request, 
    db: Session = Depends(get_db), 
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Serial Number {req.sn_onu} sudah terdaftar!")

    # Cari OLT secara fleksibel (berdasarkan IP, ID, atau Nama)
    olt = None
    if req.olt_ip:
        olt = db.query(OLTConfig).filter(OLTConfig.ip_address == req.olt_ip.strip()).first()
    if not olt and req.olt_id:
        olt = db.query(OLTConfig).filter(OLTConfig.id == req.olt_id).first()
    if not olt and req.olt_name:
        olt = db.query(OLTConfig).filter(OLTConfig.name == req.olt_name.strip()).first()
    if not olt and req.olt_ip:
        olt = db.query(OLTConfig).filter(OLTConfig.name == req.olt_ip.strip()).first()

    if not olt:
        raise HTTPException(status_code=400, detail="OLT belum terdaftar.")

    password = get_telnet_password(olt)
    if not password:
        raise HTTPException(status_code=503, detail=f"Kredensial OLT belum diatur: OLT_{env_key(olt.name)}_TELNET_PASSWORD")

    assigned_onu_id = req.onu_id if req.onu_id is not None else 1
    new_onu = OnuDevice(
        olt_name=olt.name,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user,
        gpon_port=f"1/{req.slot}/{req.port}:{assigned_onu_id}",
        status="Offline",
        sn_mac=req.sn_onu.strip().upper(),
        actual_type=req.actual_type or "ZTE-GPON"
    )
    db.add(new_onu)
    db.add(audit_event(request, "Register", f"Registrasi ONU {req.sn_onu} untuk {req.nama_pelanggan}"))
    db.commit()
    return {"status": "success", "message": "Konfigurasi disimpan"}

@app.post("/api/v1/provision-onu")
def provision_onu(req: ONURequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Serial Number {req.sn_onu} sudah terdaftar.")
    
    # Cari OLT secara fleksibel
    olt = None
    if req.olt_ip:
        olt = db.query(OLTConfig).filter(OLTConfig.ip_address == req.olt_ip.strip()).first()
    if not olt and req.olt_id:
        olt = db.query(OLTConfig).filter(OLTConfig.id == req.olt_id).first()
    if not olt and req.olt_name:
        olt = db.query(OLTConfig).filter(OLTConfig.name == req.olt_name.strip()).first()
    if not olt and req.olt_ip:
        olt = db.query(OLTConfig).filter(OLTConfig.name == req.olt_ip.strip()).first()

    if not olt:
        raise HTTPException(status_code=404, detail="OLT yang dipilih tidak ditemukan di OLT Management.")
    if req.onu_id is None or not 1 <= req.onu_id <= 128:
        raise HTTPException(status_code=400, detail="Isi ONU Index ID yang tersedia pada PON tujuan (1–128).")
    if not 1 <= req.slot <= 21 or not 1 <= req.port <= 16:
        raise HTTPException(status_code=400, detail="Slot harus 1–21 dan PON Port harus 1–16.")
    if not 1 <= req.vlan_id <= 4094:
        raise HTTPException(status_code=400, detail="VLAN ID harus berada pada rentang 1–4094.")
    target_port = f"1/{req.slot}/{req.port}:{req.onu_id}"
    if db.query(OnuDevice).filter(OnuDevice.olt_name == olt.name, OnuDevice.gpon_port == target_port).first():
        raise HTTPException(status_code=409, detail=f"ONU ID {req.onu_id} sudah tercatat pada port GPON 1/{req.slot}/{req.port}.")

    cli_values = {
        "Serial Number": (req.sn_onu.strip().upper(), r"[A-Z0-9]{1,16}"),
        "Nama pelanggan": (req.nama_pelanggan.strip(), r"[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,149}"),
        "Tipe ONU": (req.actual_type.strip(), r"[A-Za-z0-9_.\-]{1,50}"),
        "Traffic Profile": (req.profil_paket.strip(), r"[A-Za-z0-9_.\-]{1,64}"),
        "PPPoE Username": (req.pppoe_user.strip(), r"[A-Za-z0-9_.@+\-]{1,100}"),
        "PPPoE Password": (req.pppoe_pass, r"[^\r\n;!]{1,128}"),
    }
    for label, (value, pattern) in cli_values.items():
        if not re.fullmatch(pattern, value):
            raise HTTPException(status_code=400, detail=f"{label} tidak valid. Periksa karakter yang digunakan.")
    if req.description and (len(req.description) > 255 or any(char in req.description for char in "\r\n;!")):
        raise HTTPException(status_code=400, detail="Description terlalu panjang atau mengandung karakter yang tidak didukung.")

    try:
        password = get_telnet_password(olt)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not password:
        raise HTTPException(status_code=503, detail=f"Kredensial Telnet OLT belum diatur. Simpan username dan password OLT di OLT Management untuk {olt.name}.")

    deployment = deploy_onu_zte(olt.ip_address, olt.telnet_username, password, {
        "slot": req.slot,
        "port": req.port,
        "onu_id": req.onu_id,
        "actual_type": req.actual_type.strip(),
        "sn_onu": req.sn_onu.strip().upper(),
        "nama_pelanggan": req.nama_pelanggan.strip(),
        "profil_paket": req.profil_paket.strip(),
        "vlan_id": req.vlan_id,
        "pppoe_user": req.pppoe_user.strip(),
        "pppoe_pass": req.pppoe_pass,
        "telnet_port": olt.telnet_port,
    })
    if deployment.get("status") != "success":
        detail = str(deployment.get("message", "Tidak ada detail dari driver.")).replace(req.pppoe_pass, "[REDACTED]")
        raise HTTPException(status_code=502, detail=f"OLT menolak atau tidak dapat menjalankan konfigurasi: {detail[:2000]}")

    new_onu = OnuDevice(
        olt_name=olt.name,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user.strip(),
        gpon_port=target_port,
        status="Offline",
        sn_mac=req.sn_onu.strip().upper(),
        actual_type=req.actual_type.strip(),
    )
    try:
        db.add(new_onu)
        db.add(audit_event(request, "Register", f"Provision ONU {req.sn_onu} ke OLT {olt.name}, GPON {new_onu.gpon_port}"))
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Konfigurasi kemungkinan sudah diterapkan di OLT, tetapi pencatatan database gagal. Periksa ONU {req.sn_onu} pada OLT sebelum mencoba ulang. Detail: {str(exc)[:500]}") from exc
    return {"status": "success", "message": f"Konfigurasi ONU {req.sn_onu.strip().upper()} berhasil diterapkan ke {olt.name} dan dicatat di database."}

# ==============================================================================
# API: TEST CONNECTION & SYNC OLT
# ==============================================================================
@app.post("/api/olts/{olt_id}/test")
def api_test_olt_connection(
    olt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")

    snmp_status = "Failed"
    snmp_detail = ""
    telnet_status = "Failed"
    telnet_detail = ""

    try:
        snmp_res = test_snmp(olt)
        olt.system_description = str(snmp_res.get("description") or "")
        olt.uptime_ticks = snmp_res.get("uptime_ticks")
        snmp_status = "Connected"
    except Exception as exc:
        snmp_detail = str(exc)

    try:
        prompt = test_telnet(olt)
        telnet_status = "Connected"
        telnet_detail = f"Prompt: {prompt}"
    except Exception as exc:
        telnet_detail = str(exc)

    olt.snmp_status = snmp_status
    olt.telnet_status = telnet_status
    olt.last_connection_test = datetime.now(timezone.utc)
    
    db.add(audit_event(request, "Update", f"Test koneksi OLT {olt.name}: SNMP={snmp_status}, Telnet={telnet_status}"))
    db.commit()

    return {
        "snmp": {
            "status": snmp_status,
            "connected": snmp_status == "Connected",
            "detail": snmp_detail
        },
        "telnet": {
            "status": telnet_status,
            "connected": telnet_status == "Connected",
            "detail": telnet_detail
        }
    }

@app.post("/api/olts/{olt_id}/sync")
def api_sync_olt(
    olt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")

    try:
        snmp_res = test_snmp(olt)
        olt.system_description = str(snmp_res.get("description") or "")
        olt.uptime_ticks = snmp_res.get("uptime_ticks")
        olt.snmp_status = "Connected"
    except Exception:
        olt.snmp_status = "Failed"

    olt.last_sync = datetime.now(timezone.utc)
    db.add(audit_event(request, "Update", f"Sinkronisasi manual OLT {olt.name}"))
    db.commit()

    return {"status": "success", "message": f"Sinkronisasi OLT {olt.name} selesai"}