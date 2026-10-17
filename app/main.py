import os
import re
import json
import asyncio
import bcrypt
import random
import socket
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
from starlette.concurrency import run_in_threadpool
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MAIL LUPA PASSWORD
from app.services.email_service import send_otp_email

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str

class MikroTikConnectionInput(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(max_length=255)
    use_tls: bool = True

class KickPppoeInput(BaseModel):
    session_id: str

class CreatePppSecretInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=100)
    service: str = "pppoe"
    profile: str = "default"
    remote_address: str | None = None
    comment: str | None = None

class TogglePppSecretInput(BaseModel):
    name: str
    disabled: bool

class DeletePppSecretInput(BaseModel):
    name: str

# Database models and clients
from app.database import Base, SessionLocal, engine, get_db
from app.models import ActivityEvent, InterfaceTrafficSample, OLTConfig, OLTConfigBackup, OLTSettingEntry, OnuDevice, TrafficSample, User
from app.services.olt_client import (
    decrypt_olt_secret, encrypt_olt_secret, env_key, get_snmp_community, get_telnet_password,
    open_telnet, 
    read_onu_traffic, read_pon_snapshot, read_pon_state, 
    test_snmp, test_telnet
)
from app.services.netmiko_driver import deploy_onu_zte
from app.services.mikrotik_api import RouterOSApi
from app.services.snmp_client import walk as snmp_walk

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
    connection.execute(text("ALTER TABLE onu_devices ADD COLUMN IF NOT EXISTS online_since TIMESTAMP WITH TIME ZONE"))
    connection.execute(text("ALTER TABLE onu_devices ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE"))
    connection.execute(text("ALTER TABLE traffic_samples ADD COLUMN IF NOT EXISTS rx_olt FLOAT"))
    connection.execute(text("ALTER TABLE traffic_samples ADD COLUMN IF NOT EXISTS rx_onu FLOAT"))
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

def calculate_live_duration(online_since):
    if not online_since:
        return "Offline"
    now = datetime.now(timezone.utc)
    if online_since.tzinfo is None:
        online_since = online_since.replace(tzinfo=timezone.utc)
    diff = int((now - online_since).total_seconds())
    days, rem = divmod(diff, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    return f"{days}d {hours}h {minutes}m"

def read_olt_temperature(olt) -> str:
    """Membaca suhu perangkat OLT via Telnet CLI command."""
    try:
        conn = open_telnet(olt)
        output = conn.send_command("show temperature", read_timeout=8)
        conn.disconnect()

        temps = []
        for line in output.splitlines():
            parts = line.split()
            for part in parts:
                if part.isdigit() and 20 <= int(part) <= 90:
                    temps.append(int(part))
                    break
        if temps:
            return f"{max(temps)}°C"
        return "Normal"
    except Exception:
        return "—"

# ==============================================================================
# PYDANTIC SCHEMAS & INPUT MODELS
# ==============================================================================
class OnuUpdateMetaInput(BaseModel):
    customer_name: str
    description: str | None = None

class OnuMoveInput(BaseModel):
    mode: str
    slot: int
    port: int
    onu_id: int | None = None

class OnuReplaceSnInput(BaseModel):
    new_sn: str

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
def poll_onu_status_once():
    """Poll registered ONU states by PON and persist offline transitions."""
    with SessionLocal() as db:
        olts = db.query(OLTConfig).all()
        onus = db.query(OnuDevice).all()
        by_olt = {}
        for onu in onus:
            if onu.gpon_port and ":" in onu.gpon_port:
                pon_interface = onu.gpon_port.rsplit(":", 1)[0]
                by_olt.setdefault(onu.olt_name, {}).setdefault(pon_interface, []).append(onu)

        for olt in olts:
            pon_groups = by_olt.get(olt.name, {})
            if not pon_groups:
                continue
            try:
                conn = open_telnet(olt)
                try:
                    for interface, devices in pon_groups.items():
                        output = conn.send_command(f"show gpon onu state gpon-olt_{interface}", read_timeout=20)
                        for onu in devices:
                            matching_line = next((line for line in output.splitlines() if onu.gpon_port in line), "")
                            if not matching_line:
                                continue
                            state_match = re.search(r"\b(working|online|los|dyinggasp|poweroff|power-off|offline|down)\b", matching_line, re.IGNORECASE)
                            if not state_match:
                                continue
                            raw_state = state_match.group(1).lower()
                            state = {"working": "Online", "online": "Online", "los": "LOS", "dyinggasp": "DyingGasp", "poweroff": "DyingGasp", "power-off": "DyingGasp", "offline": "Offline", "down": "Offline"}[raw_state]
                            old_state = onu.status
                            now = datetime.now(timezone.utc)
                            onu.status = state
                            if state == "Online":
                                if old_state != "Online" or not onu.online_since:
                                    onu.online_since = now
                                onu.last_seen = now
                            else:
                                onu.online_since = None
                            if old_state == "Online" and state != "Online":
                                db.add(ActivityEvent(
                                    event_type="ONU Offline", username="system",
                                    information=f"ONU {onu.customer_name} ({onu.sn_mac}) pada {olt.name} {onu.gpon_port} berubah dari Online menjadi {state}.",
                                    client_ip=None, user_agent="OLT status poller"
                                ))
                finally:
                    conn.disconnect()
            except Exception as exc:
                print(f"Gagal polling status ONU pada {olt.name}: {exc}")
        db.commit()

async def onu_status_monitor():
    poll_seconds = max(30, int(os.getenv("ONU_STATUS_POLL_SECONDS", "60")))
    while True:
        await run_in_threadpool(poll_onu_status_once)
        await asyncio.sleep(poll_seconds)

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
    monitor_task = asyncio.create_task(onu_status_monitor())
    try:
        yield
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

# ==============================================================================
# FASTAPI APP & SHARED CONTEXT
# ==============================================================================
app = FastAPI(title="OLT Monitoring & Provisioning System", lifespan=lifespan)
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
def handle_login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
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
def api_update_profile(payload: ProfileUpdateInput, request: Request, db: Session = Depends(get_db), user: User = Depends(login_required)):
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
# ROUTES: USER MANAGEMENT
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
# ROUTES: DASHBOARD & MONITORING
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
        olt_rows.append({
            "id": config.id if config else None,
            "name": name,
            "model": config.model if config else "OLT",
            "ip": config.ip_address if config else "—",
            "status": "Terdaftar" if config else "ONU database",
            "uptime": format_uptime(config.uptime_ticks) if config else "—",
            "temperature": read_olt_temperature(config) if config else "—",
            "total_fan": "—",
            "total_onu": len(devices),
            "online": sum(x.status == "Online" for x in devices),
            "los": sum(x.status == "LOS" for x in devices),
            "dying_gasp": sum(x.status == "DyingGasp" for x in devices),
            "offline": sum(x.status == "Offline" for x in devices),
            "other": sum(x.status not in ("Online", "DyingGasp", "LOS", "Offline") for x in devices),
            "fans": []
        })

    percentage = lambda value: round(value / total * 100, 2) if total else 0
    selected_olt = max(olt_configs, key=lambda config: sum(onu.olt_name == config.name for onu in onus), default=None)
    dashboard_data = {
        "summary": {
            "total_olts": len(names),
            "total_onus": total,
            "selected_olt_id": selected_olt.id if selected_olt else None,
            "online_onus": counts["Online"],
            "online_percentage": percentage(counts["Online"]),
            "dying_gasp_onus": counts["DyingGasp"],
            "dying_gasp_percentage": percentage(counts["DyingGasp"]),
            "los_onus": counts["LOS"],
            "los_percentage": percentage(counts["LOS"]),
            "offline_onus": counts["Offline"],
            "offline_percentage": percentage(counts["Offline"])
        },
        "olts": olt_rows
    }
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"data": dashboard_data})

@app.get("/api/onus/brief")
def get_onus_brief(db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    onus = db.query(OnuDevice).all()
    return [{"id": o.id, "customer_name": o.customer_name, "sn_mac": o.sn_mac, "pppoe_user": o.pppoe_user, "gpon_port": o.gpon_port} for o in onus]

@app.get("/api/onu/{onu_id}/detail")
@app.get("/api/onu/{onu_id}/full-details")
def get_onu_detail(
    onu_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    online_duration = calculate_live_duration(onu.online_since) if onu.status == "Online" else "Offline"
    rx_onu = onu.rx_onu
    rx_olt = onu.rx_olt
    state = onu.status

    if olt:
        try:
            conn = open_telnet(olt)
            status_out = conn.send_command(f"show gpon onu state {onu.gpon_port}", read_timeout=10)
            for line in status_out.splitlines():
                if onu.gpon_port in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        raw_state = parts[3].strip().lower()
                        state = next((name for name in ("Online", "LOS", "DyingGasp", "Offline") if name.lower() == raw_state), None)
                        if state is None:
                            state = {"working": "Online", "up": "Online", "down": "Offline", "poweroff": "DyingGasp", "power-off": "DyingGasp"}.get(raw_state)
                        if state:
                            previous_state = onu.status
                            now = datetime.now(timezone.utc)
                            onu.status = state
                            if state == "Online":
                                if previous_state != "Online" or not onu.online_since:
                                    onu.online_since = now
                                onu.last_seen = now
                            elif previous_state == "Online":
                                onu.online_since = None
                            if previous_state == "Online" and state != "Online":
                                db.add(ActivityEvent(
                                    event_type="ONU Offline", username="system",
                                    information=f"ONU {onu.customer_name} ({onu.sn_mac}) pada {onu.olt_name} {onu.gpon_port} berubah dari Online menjadi {state}.",
                                    client_ip=request.client.host if request.client else None,
                                    user_agent=request.headers.get("user-agent", "")[:255]
                                ))
                            db.commit()
            
            opt_out = conn.send_command(f"show gpon onu optical-power {onu.gpon_port}", read_timeout=10)
            rx_onu_match = re.search(r"Rx optical power\s*:\s*([-\d.]+)\s*\(dbm\)", opt_out, re.IGNORECASE)
            if rx_onu_match:
                rx_onu = float(rx_onu_match.group(1))

            rx_olt_match = re.search(r"OLT Rx optical power\s*:\s*([-\d.]+)\s*\(dbm\)", opt_out, re.IGNORECASE)
            if rx_olt_match:
                rx_olt = float(rx_olt_match.group(1))

            detail_out = conn.send_command(f"show gpon onu detail-info {onu.gpon_port}", read_timeout=10)
            duration_match = re.search(r"Online Duration\s*:\s*([^\r\n]+)", detail_out, re.IGNORECASE)
            if duration_match:
                online_duration = duration_match.group(1).strip()

            conn.disconnect()
        except Exception as e:
            print(f"Gagal mengambil live optical ONU {onu.sn_mac}: {e}")

    status_events = db.query(ActivityEvent).filter(
        ActivityEvent.event_type == "ONU Offline",
        ActivityEvent.information.contains(onu.sn_mac or "")
    ).order_by(ActivityEvent.created_at.desc()).limit(20).all() if onu.sn_mac else []
    
    timeline = ([{"time": onu.created_at.isoformat(), "status": "Terdaftar", "type": "online"}] if onu.created_at else [])
    timeline.extend({"time": event.created_at.isoformat(), "status": event.information, "type": "offline"} for event in reversed(status_events) if event.created_at)

    vlan_match = re.search(r"VLAN:\s*(\d+)", onu.description or "")
    profile_match = re.search(r"Profile:\s*([^\s|]+)", onu.description or "")

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
            "online_duration": online_duration,
            "registered_at": onu.created_at.isoformat() if onu.created_at else None,
            "online_since": onu.online_since.isoformat() if onu.online_since else None,
            "last_seen": onu.last_seen.isoformat() if onu.last_seen else None,
            "timeline": timeline,
            "vlan_id": vlan_match.group(1) if vlan_match else "—",
            "profile_paket": profile_match.group(1) if profile_match else "DEFAULT",
            "ip_address": getattr(onu, "ip_address", "—"),
            "pppoe_user": onu.pppoe_user or "—"
        }
    }

@app.post("/api/onu/{onu_id}/action")
def execute_onu_action(
    onu_id: int,
    action: str = Form(...),
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
        elif action == "disable":
            port_base = onu.gpon_port.rsplit(":", 1)[0]
            onu_num = onu.gpon_port.rsplit(":", 1)[1]
            commands = [
                "conf t",
                f"interface {port_base}",
                f"onu {onu_num} state disable",
                "exit",
                "write"
            ]
            for cmd in commands:
                output += conn.send_command(cmd, read_timeout=5) + "\n"
        
        conn.disconnect()
        db.add(audit_event(request, "Action", f"Eksekusi {action} pada ONU {onu.gpon_port} ({onu.sn_mac})"))
        db.commit()
        return {"status": "success", "action": action, "output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal mengeksekusi {action}: {e}")

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
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    target_onu_id = payload.onu_id if payload.mode == "manual" and payload.onu_id else 1
    new_gpon_port = f"1/{payload.slot}/{payload.port}:{target_onu_id}"

    if olt:
        try:
            conn = open_telnet(olt)
            old_port_base = onu.gpon_port.rsplit(":", 1)[0]
            old_onu_num = onu.gpon_port.rsplit(":", 1)[1]
            cmds = [
                "conf t",
                f"interface {old_port_base}",
                f"no onu {old_onu_num}",
                "exit",
                f"interface 1/{payload.slot}/{payload.port}",
                f"onu {target_onu_id} type {onu.actual_type or 'ZTE-GPON'} sn {onu.sn_mac}",
                "exit",
                "write"
            ]
            for cmd in cmds:
                conn.send_command(cmd, read_timeout=5)
            conn.disconnect()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Gagal memindahkan port di OLT: {e}")

    old_port = onu.gpon_port
    onu.gpon_port = new_gpon_port
    db.add(audit_event(request, "Update", f"Pindah ONU {onu.sn_mac} dari {old_port} ke {new_gpon_port}"))
    db.commit()
    return {"status": "success", "message": f"ONU berhasil dipindahkan ke {new_gpon_port}"}

@app.post("/api/onu/{onu_id}/meta")
def update_onu_metadata(
    onu_id: int,
    payload: OnuUpdateMetaInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")

    onu.customer_name = payload.customer_name.strip().upper()
    onu.description = payload.description.strip() if payload.description else None
    db.add(audit_event(request, "Update", f"Perbarui metadata ONU {onu.sn_mac} ({onu.customer_name})"))
    db.commit()
    return {"status": "success", "message": "Konfigurasi metadata ONU berhasil disimpan."}

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

# ==============================================================================
# ROUTES: ALL ONUS
# ==============================================================================
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
    olt_names = sorted({row[0] for row in db.query(OnuDevice.olt_name).distinct().all()} | {olt.name for olt in db.query(OLTConfig).all()})
    card_slots = sorted({onu.gpon_port.split("/")[1] for onu in onus if onu.gpon_port and len(onu.gpon_port.split("/")) > 2})
    pon_ports = sorted({onu.gpon_port.rsplit(":", 1)[0] for onu in onus if onu.gpon_port and ":" in onu.gpon_port})
    return templates.TemplateResponse(request=request, name="graphs.html", context={"onus": onus, "olt_names": olt_names, "card_slots": card_slots, "pon_ports": pon_ports})

@app.get("/api/traffic/{onu_id}/history")
def onu_traffic_history(onu_id: int, period: str = "6H", db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")
    period_hours = {"3H": 3, "6H": 6, "1D": 24, "3D": 72, "7D": 168, "30D": 720}
    hours = period_hours.get(period.upper())
    if hours is None:
        raise HTTPException(status_code=400, detail="Periode grafik tidak valid")
    latest_sample = db.query(TrafficSample).filter(TrafficSample.onu_id == onu_id).order_by(TrafficSample.sampled_at.desc()).first()
    now = datetime.now(timezone.utc)
    sample_is_due = latest_sample is None
    if latest_sample and latest_sample.sampled_at:
        sampled_at = latest_sample.sampled_at
        if sampled_at.tzinfo is None:
            sampled_at = sampled_at.replace(tzinfo=timezone.utc)
        sample_is_due = (now - sampled_at).total_seconds() >= 60
    if sample_is_due:
        olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
        if olt:
            try:
                conn = open_telnet(olt)
                try:
                    traffic_out = conn.send_command(f"show interface gpon-onu_{onu.gpon_port}", read_timeout=12)
                    optical_out = conn.send_command(f"show gpon onu optical-power {onu.gpon_port}", read_timeout=12)
                finally:
                    conn.disconnect()
                def parse_rate(direction):
                    match = re.search(rf"{direction}[^\r\n]*?rate\s*[:=]?\s*([\d.]+)\s*(G|M|K)?bits/sec", traffic_out, re.IGNORECASE)
                    if not match:
                        return None
                    multiplier = {None: 1, "K": 1e3, "M": 1e6, "G": 1e9}[match.group(2).upper() if match.group(2) else None]
                    return float(match.group(1)) * multiplier
                download_bps, upload_bps = parse_rate("input"), parse_rate("output")
                rx_onu_match = re.search(r"Rx optical power\s*:\s*(-?[\d.]+)", optical_out, re.IGNORECASE)
                rx_olt_match = re.search(r"OLT Rx optical power\s*:\s*(-?[\d.]+)", optical_out, re.IGNORECASE)
                rx_onu = float(rx_onu_match.group(1)) if rx_onu_match else None
                rx_olt = float(rx_olt_match.group(1)) if rx_olt_match else None
                if rx_onu is not None:
                    onu.rx_onu = rx_onu
                if rx_olt is not None:
                    onu.rx_olt = rx_olt
                if download_bps is not None and upload_bps is not None:
                    db.add(TrafficSample(onu_id=onu.id, download_bps=download_bps, upload_bps=upload_bps, rx_olt=rx_olt, rx_onu=rx_onu))
                    db.commit()
                elif rx_onu is not None or rx_olt is not None:
                    db.commit()
            except Exception as exc:
                print(f"Gagal sampling grafik ONU {onu.sn_mac}: {exc}")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    samples = db.query(TrafficSample).filter(
        TrafficSample.onu_id == onu_id,
        TrafficSample.sampled_at >= since
    ).order_by(TrafficSample.sampled_at.asc()).limit(2000).all()
    return [{
        "download_bps": sample.download_bps,
        "upload_bps": sample.upload_bps,
        "rx_olt": sample.rx_olt,
        "rx_onu": sample.rx_onu,
        "sampled_at": sample.sampled_at.isoformat() if sample.sampled_at else None
    } for sample in samples]

@app.get("/api/traffic/interfaces")
def interface_traffic_history(olt: str = "all", kind: str = "uplink", period: str = "6H", db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    kind = kind.lower()
    if kind not in {"uplink", "pon"}:
        raise HTTPException(status_code=400, detail="Scope interface tidak valid")
    period_hours = {"3H": 3, "6H": 6, "1D": 24, "3D": 72, "7D": 168, "30D": 720}
    hours = period_hours.get(period.upper())
    if hours is None:
        raise HTTPException(status_code=400, detail="Periode grafik tidak valid")
    olt_query = db.query(OLTConfig).order_by(OLTConfig.name)
    if olt.lower() != "all":
        olt_query = olt_query.filter(OLTConfig.name == olt)
    configs = olt_query.all()
    roots = {
        "name": "1.3.6.1.2.1.31.1.1.1.1",
        "descr": "1.3.6.1.2.1.2.2.1.2",
        "type": "1.3.6.1.2.1.2.2.1.3",
        "in64": "1.3.6.1.2.1.31.1.1.1.6",
        "out64": "1.3.6.1.2.1.31.1.1.1.10",
        "in32": "1.3.6.1.2.1.2.2.1.10",
        "out32": "1.3.6.1.2.1.2.2.1.16",
    }
    now = datetime.now(timezone.utc)
    problems, touched_olts = [], 0
    for config in configs:
        try:
            community = get_snmp_community(config)
            if not community:
                raise RuntimeError("Community SNMP belum dikonfigurasi")
            tables = {key: snmp_walk(config.ip_address, config.snmp_port, community, oid, timeout=4) for key, oid in roots.items()}
            def indexed(table):
                result = {}
                for oid, value in table.items():
                    try:
                        result[int(oid.rsplit(".", 1)[1])] = value
                    except (ValueError, IndexError):
                        continue
                return result
            tables = {key: indexed(value) for key, value in tables.items()}
            indexes = set(tables["name"]) | set(tables["descr"])
            selected = []
            for index in indexes:
                name = str(tables["name"].get(index) or tables["descr"].get(index) or f"ifIndex {index}").strip()
                description = str(tables["descr"].get(index) or "").strip()
                label = f"{name} {description}".lower()
                is_pon = bool(re.search(r"(?:gpon|epon|pon)[-_ ]?(?:olt|port|interface)?", label)) and not re.search(r"onu", name, re.IGNORECASE)
                is_uplink = int(tables["type"].get(index) or 0) == 6 and bool(re.search(r"(?:ethernet|eth\w*|gei|xgei|10g|25g|40g|100g|uplink|trunk)", label)) and not is_pon
                if (kind == "pon" and not is_pon) or (kind == "uplink" and not is_uplink):
                    continue
                in_octets = tables["in64"].get(index)
                out_octets = tables["out64"].get(index)
                if in_octets is None:
                    in_octets = tables["in32"].get(index)
                if out_octets is None:
                    out_octets = tables["out32"].get(index)
                if in_octets is None or out_octets is None:
                    continue
                latest = db.query(InterfaceTrafficSample).filter(
                    InterfaceTrafficSample.olt_id == config.id,
                    InterfaceTrafficSample.interface_index == index
                ).order_by(InterfaceTrafficSample.sampled_at.desc()).first()
                download_bps = upload_bps = 0.0
                if latest:
                    sampled = latest.sampled_at or now
                    if sampled.tzinfo is None:
                        sampled = sampled.replace(tzinfo=timezone.utc)
                    elapsed = (now - sampled).total_seconds()
                    delta_in = int(in_octets) - latest.input_octets
                    delta_out = int(out_octets) - latest.output_octets
                    if 0 < elapsed <= 600:
                        if delta_in < 0 and in_octets <= 0xFFFFFFFF:
                            delta_in += 2**32
                        if delta_out < 0 and out_octets <= 0xFFFFFFFF:
                            delta_out += 2**32
                        download_bps = max(0, delta_in) * 8 / elapsed
                        upload_bps = max(0, delta_out) * 8 / elapsed
                db.add(InterfaceTrafficSample(
                    olt_id=config.id, interface_index=index, interface_name=name, kind=kind,
                    input_octets=int(in_octets), output_octets=int(out_octets),
                    download_bps=download_bps, upload_bps=upload_bps
                ))
                selected.append((index, name))
            db.commit()
            touched_olts += 1
        except Exception as exc:
            db.rollback()
            problems.append({"olt": config.name, "detail": str(exc)[:180]})

    since = now - timedelta(hours=hours)
    samples = db.query(InterfaceTrafficSample).filter(
        InterfaceTrafficSample.kind == kind,
        InterfaceTrafficSample.sampled_at >= since
    ).order_by(InterfaceTrafficSample.sampled_at.asc()).all()
    if olt.lower() != "all":
        selected_ids = {config.id for config in configs}
        samples = [sample for sample in samples if sample.olt_id in selected_ids]
    grouped = {}
    for sample in samples:
        key = f"{sample.olt_id}:{sample.interface_index}"
        item = grouped.setdefault(key, {"key": key, "olt_name": next((c.name for c in configs if c.id == sample.olt_id), ""), "interface_name": sample.interface_name, "kind": kind, "samples": []})
        item["samples"].append({"download_bps": sample.download_bps, "upload_bps": sample.upload_bps, "sampled_at": sample.sampled_at.isoformat() if sample.sampled_at else None})
    result = list(grouped.values())
    for item in result:
        item["download_bps"] = item["samples"][-1]["download_bps"]
        item["upload_bps"] = item["samples"][-1]["upload_bps"]
    return {"interfaces": result, "olt_count": touched_olts, "errors": problems}

# ==============================================================================
# ROUTES: PPPoE ROUTEROS
# ==============================================================================
@app.get("/pppoe", response_class=HTMLResponse)
def pppoe_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    config = json.loads(entry.data_json) if entry else {}
    return templates.TemplateResponse(request=request, name="pppoe.html", context={
        "configured": bool(config.get("host") and config.get("password_encrypted")),
        "router_config": {"host": config.get("host", ""), "port": config.get("port", 8729), "username": config.get("username", ""), "use_tls": config.get("use_tls", True)},
        "role": user.role
    })

@app.get("/api/mikrotik/pppoe")
def get_mikrotik_config(db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    config = json.loads(entry.data_json) if entry else {}
    return {"configured": bool(config.get("host") and config.get("password_encrypted")), "host": config.get("host", ""), "port": config.get("port", 8729), "username": config.get("username", ""), "use_tls": config.get("use_tls", True)}

@app.post("/api/mikrotik/pppoe")
def save_mikrotik_config(payload: MikroTikConnectionInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    if not payload.use_tls:
        raise HTTPException(status_code=400, detail="Koneksi RouterOS wajib menggunakan API-SSL agar password tidak dikirim tanpa enkripsi.")
    if any(char in payload.host + payload.username for char in "\r\n"):
        raise HTTPException(status_code=400, detail="Host atau username mengandung karakter yang tidak valid.")
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    old = json.loads(entry.data_json) if entry else {}
    password = payload.password or decrypt_olt_secret(old.get("password_encrypted"))
    if not password:
        raise HTTPException(status_code=400, detail="Password API MikroTik wajib diisi.")
    saved = {"host": payload.host.strip(), "port": payload.port, "username": payload.username.strip(), "password_encrypted": encrypt_olt_secret(password), "use_tls": payload.use_tls}
    if entry:
        entry.data_json = json.dumps(saved)
    else:
        db.add(OLTSettingEntry(category="mikrotik", name="pppoe_router", data_json=json.dumps(saved)))
    db.add(audit_event(request, "Update", f"Pengaturan koneksi MikroTik diperbarui oleh {user.username}"))
    db.commit()
    return {"status": "success", "message": "Konfigurasi MikroTik disimpan."}

@app.get("/api/mikrotik/pppoe/sessions")
def get_mikrotik_pppoe_sessions(db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    if not entry:
        raise HTTPException(status_code=400, detail="Konfigurasi MikroTik belum disimpan.")
    config = json.loads(entry.data_json)
    try:
        password = decrypt_olt_secret(config.get("password_encrypted"))
        client = RouterOSApi(config["host"], int(config["port"]), config["username"], password, bool(config.get("use_tls", True)))
        try:
            active, secrets = client.connect().ppp_overview()
        finally:
            client.close()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Koneksi atau autentikasi MikroTik gagal: {str(exc)[:300]}") from exc
    active_fields = {".id", "name", "service", "address", "caller-id", "uptime", "encoding"}
    secret_fields = {".id", "name", "service", "profile", "remote-address", "local-address", "disabled", "comment"}
    safe_active = [{key: row.get(key) for key in active_fields if key in row} for row in active]
    safe_secrets = [{key: row.get(key) for key in secret_fields if key in row} for row in secrets]
    return {"active": safe_active, "secrets": safe_secrets, "active_count": len(safe_active), "secret_count": len(safe_secrets)}

@app.post("/api/mikrotik/pppoe/kick")
def kick_pppoe_session(
    payload: KickPppoeInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    if not entry:
        raise HTTPException(status_code=400, detail="Konfigurasi MikroTik belum disimpan.")
    config = json.loads(entry.data_json)
    try:
        password = decrypt_olt_secret(config.get("password_encrypted"))
        client = RouterOSApi(config["host"], int(config["port"]), config["username"], password, bool(config.get("use_tls", True)))
        api = client.connect()
        api.talk(["/interface/pppoe-server/remove", f"=.id={payload.session_id}"])
        client.close()
        db.add(audit_event(request, "Action", f"Memutus sesi PPPoE id {payload.session_id}"))
        db.commit()
        return {"status": "success", "message": "Sesi PPPoE berhasil diputus."}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gagal memutus sesi PPPoE: {exc}")

@app.post("/api/mikrotik/pppoe/secret")
def create_ppp_secret(
    payload: CreatePppSecretInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    if not entry:
        raise HTTPException(status_code=400, detail="Konfigurasi MikroTik belum disimpan.")
    config = json.loads(entry.data_json)
    try:
        password = decrypt_olt_secret(config.get("password_encrypted"))
        client = RouterOSApi(config["host"], int(config["port"]), config["username"], password, bool(config.get("use_tls", True)))
        api = client.connect()
        cmd = [
            "/ppp/secret/add",
            f"=name={payload.name.strip()}",
            f"=password={payload.password}",
            f"=service={payload.service}",
            f"=profile={payload.profile}"
        ]
        if payload.remote_address:
            cmd.append(f"=remote-address={payload.remote_address.strip()}")
        if payload.comment:
            cmd.append(f"=comment={payload.comment.strip()}")
        api.talk(cmd)
        client.close()
        db.add(audit_event(request, "Create", f"Membuat PPP Secret baru: {payload.name} ({payload.profile})"))
        db.commit()
        return {"status": "success", "message": f"Akun PPP '{payload.name}' berhasil dibuat di router."}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gagal membuat secret: {exc}")

@app.post("/api/mikrotik/pppoe/secret/toggle")
def toggle_ppp_secret(
    payload: TogglePppSecretInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    if not entry:
        raise HTTPException(status_code=400, detail="Konfigurasi MikroTik belum disimpan.")
    config = json.loads(entry.data_json)
    try:
        password = decrypt_olt_secret(config.get("password_encrypted"))
        client = RouterOSApi(config["host"], int(config["port"]), config["username"], password, bool(config.get("use_tls", True)))
        api = client.connect()
        action_word = "disable" if payload.disabled else "enable"
        api.talk([f"/ppp/secret/{action_word}", f"=numbers={payload.name}"])
        if payload.disabled:
            try:
                active_list = api.talk(["/ppp/active/print", f"?name={payload.name}"])
                for item in active_list:
                    if isinstance(item, tuple) and item[0] == "!re":
                        props = dict(pair.split("=", 1) for pair in item[1:] if "=" in pair)
                        if ".id" in props:
                            api.talk(["/interface/pppoe-server/remove", f"=.id={props['.id']}"])
            except Exception:
                pass
        client.close()
        status_label = "dinonaktifkan (Isolir)" if payload.disabled else "diaktifkan kembali"
        db.add(audit_event(request, "Update", f"Akun PPP '{payload.name}' {status_label}"))
        db.commit()
        return {"status": "success", "message": f"Akun PPP '{payload.name}' berhasil {status_label}."}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gagal mengubah status secret: {exc}")

@app.delete("/api/mikrotik/pppoe/secret")
def delete_ppp_secret(
    payload: DeletePppSecretInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "mikrotik", OLTSettingEntry.name == "pppoe_router").first()
    if not entry:
        raise HTTPException(status_code=400, detail="Konfigurasi MikroTik belum disimpan.")
    config = json.loads(entry.data_json)
    try:
        password = decrypt_olt_secret(config.get("password_encrypted"))
        client = RouterOSApi(config["host"], int(config["port"]), config["username"], password, bool(config.get("use_tls", True)))
        api = client.connect()
        api.talk(["/ppp/secret/remove", f"=numbers={payload.name}"])
        client.close()
        db.add(audit_event(request, "Delete", f"Menghapus PPP Secret '{payload.name}'"))
        db.commit()
        return {"status": "success", "message": f"Akun PPP '{payload.name}' berhasil dihapus."}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gagal menghapus secret: {exc}")

# ==============================================================================
# ROUTES: OLT SETTINGS & TELEMETRY
# ==============================================================================
@app.get("/olt-management", response_class=HTMLResponse)
def olt_management_page(request: Request, olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    configs = db.query(OLTConfig).order_by(OLTConfig.name).all()
    olts = []
    for config in configs:
        devices = db.query(OnuDevice).filter(OnuDevice.olt_name == config.name).all()
        olts.append({
            "id": config.id,
            "name": config.name,
            "model": config.model,
            "ip": config.ip_address,
            "temperature": read_olt_temperature(config),
            "total_onu": len(devices),
            "uptime": format_uptime(config.uptime_ticks),
            "synced": config.last_sync.strftime("%Y-%m-%d %H:%M:%S") if config.last_sync else "Belum pernah",
            "telnet": config.telnet_status or "Belum dites",
            "snmp": config.snmp_status or "Belum dites",
            "snmp_version": config.snmp_version,
            "snmp_port": config.snmp_port,
            "telnet_username": config.telnet_username,
            "telnet_port": config.telnet_port,
            "env_suffix": env_key(config.name),
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

# ==============================================================================
# ROUTES: ACTIVITY LOG
# ==============================================================================
@app.get("/activity-log", response_class=HTMLResponse)
def activity_log_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    events = db.query(ActivityEvent).order_by(ActivityEvent.created_at.desc()).limit(1000).all()
    logs = [{
        "date": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "—",
        "user": event.username,
        "type": event.event_type,
        "info": event.information,
        "ip": event.client_ip or "—",
        "agent": event.user_agent or "—"
    } for event in events]
    
    db_event_types = [r[0] for r in db.query(ActivityEvent.event_type).distinct().all() if r[0]]
    
    totals = {
        "total": db.query(sql_func.count(ActivityEvent.id)).scalar() or 0,
        "login": db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type == "Login").scalar() or 0,
        "delete": db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type == "Delete").scalar() or 0,
        "update_count": db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type == "Update").scalar() or 0,
        "onu_events": db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type.in_(["ONU Offline", "ONU Register", "ONU Online"])).scalar() or 0
    }
    return templates.TemplateResponse(request=request, name="activity_log.html", context={
        "logs": logs, 
        "totals": totals,
        "event_types": db_event_types
    })

# ==============================================================================
# ROUTES: REGISTRASI & PROVISIONING ONU
# ==============================================================================
@app.get("/add-onu", response_class=HTMLResponse)
def manual_add_onu_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    return templates.TemplateResponse(request=request, name="add_onu.html", context={
        "olts": db.query(OLTConfig).order_by(OLTConfig.name).all()
    })

@app.get("/api/olts/{olt_id}/vlans")
def get_olt_vlans(olt_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
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
        return {"status": "success", "vlans": sorted(list(set(vlans)))}
    except Exception as e:
        return {"status": "error", "message": str(e), "vlans": []}

@app.get("/api/olts/{olt_id}/profiles")
def get_olt_profiles(olt_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")
    try:
        conn = open_telnet(olt)
        tcont_out = conn.send_command("show gpon profile tcont", read_timeout=15)
        upload_profiles = re.findall(r"Profile name\s*:\s*([^\r\n\s]+)", tcont_out)
        traffic_out = conn.send_command("show gpon profile traffic", read_timeout=15)
        download_profiles = re.findall(r"Profile name\s*:\s*([^\r\n\s]+)", traffic_out)
        conn.disconnect()
        return {
            "status": "success",
            "upload_profiles": sorted(list(set(upload_profiles)), key=lambda x: (x != "1G", x)),
            "download_profiles": sorted(list(set(download_profiles)), key=lambda x: (x != "1G", x))
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "upload_profiles": [], "download_profiles": []}

@app.get("/unregistered-onus", response_class=HTMLResponse)
def unregistered_onus_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    olts = db.query(OLTConfig).order_by(OLTConfig.name).all()
    unregistered_list = []
    for olt in olts:
        try:
            conn = open_telnet(olt)
            output = conn.send_command("show gpon onu uncfg", read_timeout=15)
            conn.disconnect()
            for line in output.splitlines():
                line = line.strip()
                match = re.search(r"(?:gpon-onu_)?1/(\d+)/(\d+):(\d+)\s+([A-Z0-9]+)\s*(\w+)?", line, re.IGNORECASE)
                if match:
                    slot, port, onu_id, sn, state = match.groups()
                    unregistered_list.append({
                        "olt_id": olt.id, "olt_name": olt.name,
                        "slot": int(slot), "port": int(port), "onu_id": int(onu_id),
                        "sn": sn.upper(), "sn_mac": sn.upper(),
                        "state": state or "unknown",
                        "interface": f"1/{slot}/{port}:{onu_id}",
                        "gpon_port": f"1/{slot}/{port}:{onu_id}"
                    })
        except Exception as e:
            print(f"Gagal mengambil uncfg dari {olt.name}: {e}")
    return templates.TemplateResponse(request=request, name="unregistered_onus.html", context={"unregistered_onus": unregistered_list, "olts": olts})

@app.get("/api/olts")
def api_list_olts(db: Session = Depends(get_db)):
    return [{"id": olt.id, "name": olt.name, "ip_address": olt.ip_address, "model": olt.model, "snmp_version": olt.snmp_version, "snmp_port": olt.snmp_port, "telnet_username": olt.telnet_username, "telnet_port": olt.telnet_port} for olt in db.query(OLTConfig).order_by(OLTConfig.name).all()]

@app.get("/api/summary")
def api_summary(db: Session = Depends(get_db)):
    counts = dict(db.query(OnuDevice.status, sql_func.count(OnuDevice.id)).group_by(OnuDevice.status).all())
    d_gasp = counts.get("DyingGasp", 0)
    los_val = counts.get("LOS", 0)
    return {"DyingGasp": d_gasp, "LOS": los_val, "dying_gasp": d_gasp, "los": los_val}

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

@app.post("/api/v1/olt/create-vlan")
def api_create_vlan_direct(
    payload: DirectVlanCreateInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    if not 1 <= payload.vlan_id <= 4094:
        raise HTTPException(status_code=400, detail="VLAN ID harus berada pada rentang 1-4094.")
    clean_vlan_name = re.sub(r"[^A-Za-z0-9_-]", "", payload.vlan_name.strip()) or f"VLAN_{payload.vlan_id}"
    olt = db.query(OLTConfig).filter(OLTConfig.id == payload.olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="Perangkat OLT tidak ditemukan.")

    is_mock = os.getenv("MOCK_OLT", "false").lower() in ("true", "1", "yes")
    if not is_mock:
        password = get_telnet_password(olt)
        if not password:
            raise HTTPException(status_code=503, detail=f"Kredensial OLT {olt.name} belum disetel di OLT Management.")
        commands = [f"vlan {payload.vlan_id}", f"name {clean_vlan_name}", "exit", "write"]
        from netmiko import ConnectHandler
        device_params = {
            "device_type": "zte_zxros", "host": olt.ip_address,
            "username": olt.telnet_username, "password": password,
            "port": olt.telnet_port, "timeout": 10
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

    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "vlan", OLTSettingEntry.name == str(payload.vlan_id)).first()
    if not entry:
        entry = OLTSettingEntry(category="vlan", name=str(payload.vlan_id), data_json=json.dumps({"vlan_name": clean_vlan_name}))
        if hasattr(entry, "olt_id"): entry.olt_id = olt.id
        db.add(entry)
    else:
        entry.data_json = json.dumps({"vlan_name": clean_vlan_name})
        if hasattr(entry, "olt_id"): entry.olt_id = olt.id

    db.add(audit_event(request, "Create", f"Push CLI VLAN {payload.vlan_id} ({clean_vlan_name}) ke OLT {olt.name}"))
    db.commit()
    return {"status": "success", "message": f"VLAN {payload.vlan_id} ({clean_vlan_name}) berhasil dibuat untuk {olt.name}!", "vlan_id": payload.vlan_id, "vlan_name": clean_vlan_name}

@app.post("/api/customization")
def api_save_customization(payload: CustomizationInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN]))):
    allowed = {key for key, _ in CUSTOMIZATION_COLUMNS}
    if not payload.desktop_columns or not payload.mobile_columns:
        raise HTTPException(status_code=400, detail="Pilih minimal satu kolom untuk tampilan desktop dan mobile.")
    if any(key not in allowed for key in payload.desktop_columns + payload.mobile_columns):
        raise HTTPException(status_code=400, detail="Pilihan kolom tidak dikenal.")
    if not -32 <= payload.warning_threshold < payload.good_threshold <= -20:
        raise HTTPException(status_code=400, detail="Ambang Warning dan Good harus berada di -32 sampai -20 dBm.")

    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "system", OLTSettingEntry.name == "customization").first()
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
    db.commit()
    return {"status": "success", "persisted": True, "id": entry.id}

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
    db.add(backup)
    db.add(audit_event(request, "Create", f"Membuat backup konfigurasi OLT {olt.name}"))
    db.commit()
    db.refresh(backup)
    return {"status": "success", "id": backup.id, "filename": backup.filename}

@app.get("/api/olt-settings/backups")
def list_olt_backups(olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    query = db.query(OLTConfigBackup)
    if olt_id: query = query.filter(OLTConfigBackup.olt_id == olt_id)
    backups = query.order_by(OLTConfigBackup.created_at.desc(), OLTConfigBackup.id.desc()).all()
    records = [{
        "id": backup.id, "filename": backup.filename, "type": backup.backup_type,
        "size": len(backup.content_json.encode("utf-8")),
        "created_at": backup.created_at.isoformat() if backup.created_at else None,
    } for backup in backups]
    return {"backups": records, "last_auto": next((item for item in records if item["type"] == "auto"), None)}

@app.get("/api/olt-settings/backups/{backup_id}/download")
def download_olt_backup(backup_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    backup = db.query(OLTConfigBackup).filter(OLTConfigBackup.id == backup_id).first()
    if not backup: raise HTTPException(status_code=404, detail="File backup tidak ditemukan.")
    return Response(content=backup.content_json, media_type="application/json; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{backup.filename}"'})

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

    olt = None
    if req.olt_ip:
        olt = db.query(OLTConfig).filter(OLTConfig.ip_address == req.olt_ip.strip()).first()
    if not olt and req.olt_id:
        olt = db.query(OLTConfig).filter(OLTConfig.id == req.olt_id).first()
    if not olt and req.olt_name:
        olt = db.query(OLTConfig).filter(OLTConfig.name == req.olt_name.strip()).first()

    if not olt:
        raise HTTPException(status_code=400, detail="OLT belum terdaftar.")

    assigned_onu_id = req.onu_id if req.onu_id is not None else 1
    new_onu = OnuDevice(
        olt_name=olt.name,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user,
        gpon_port=f"1/{req.slot}/{req.port}:{assigned_onu_id}",
        status="Online",
        online_since=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        rx_olt=-22.45,
        rx_onu=-21.15,
        sn_mac=req.sn_onu.strip().upper(),
        actual_type=req.actual_type or "ZTE-GPON"
    )
    db.add(new_onu)
    db.add(audit_event(
        request, 
        "ONU Register", 
        f"ONU {new_onu.customer_name} ({new_onu.sn_mac}) terdaftar pada {olt.name} {new_onu.gpon_port}"
    ))
    db.commit()
    db.refresh(new_onu)
    return {"status": "success", "message": "Konfigurasi ONU berhasil disimpan di database"}

@app.post("/api/v1/provision-onu")
def provision_onu(
    req: ONURequest, 
    request: Request, 
    db: Session = Depends(get_db), 
    user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))
):
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Serial Number {req.sn_onu} sudah terdaftar.")
    
    olt = None
    if req.olt_ip:
        olt = db.query(OLTConfig).filter(OLTConfig.ip_address == req.olt_ip.strip()).first()
    if not olt and req.olt_id:
        olt = db.query(OLTConfig).filter(OLTConfig.id == req.olt_id).first()
    if not olt and req.olt_name:
        olt = db.query(OLTConfig).filter(OLTConfig.name == req.olt_name.strip()).first()

    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan.")

    password = get_telnet_password(olt)
    if not password:
        raise HTTPException(status_code=503, detail=f"Kredensial OLT {olt.name} belum disetel di OLT Management.")

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
        raise HTTPException(status_code=502, detail=f"OLT menolak konfigurasi: {deployment.get('message')}")

    target_port = f"1/{req.slot}/{req.port}:{req.onu_id}"
    new_onu = OnuDevice(
        olt_name=olt.name,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user.strip(),
        gpon_port=target_port,
        status="Online",
        online_since=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        sn_mac=req.sn_onu.strip().upper(),
        actual_type=req.actual_type.strip(),
    )
    db.add(new_onu)
    db.add(audit_event(request, "ONU Register", f"Provision ONU {new_onu.sn_mac} ke OLT {olt.name} {target_port}"))
    db.commit()
    return {"status": "success", "message": f"Provision ONU {req.sn_onu} berhasil diterapkan ke OLT hardware."}

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

    snmp_status, snmp_detail = "Failed", ""
    telnet_status, telnet_detail = "Failed", ""
    source_ip = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
            route_socket.connect((olt.ip_address, olt.snmp_port or 161))
            source_ip = route_socket.getsockname()[0]
    except OSError:
        pass

    telnet_tcp_reachable = False
    telnet_tcp_detail = ""
    try:
        with socket.create_connection((olt.ip_address, olt.telnet_port or 23), timeout=3):
            telnet_tcp_reachable = True
    except OSError as exc:
        telnet_tcp_detail = str(exc)

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
        "diagnostics": {
            "server_source_ip": source_ip,
            "target_ip": olt.ip_address,
            "telnet_port": olt.telnet_port or 23,
            "telnet_tcp_reachable": telnet_tcp_reachable,
            "telnet_tcp_detail": telnet_tcp_detail,
        },
        "snmp": {"status": snmp_status, "connected": snmp_status == "Connected", "detail": snmp_detail},
        "telnet": {"status": telnet_status, "connected": telnet_status == "Connected", "detail": telnet_detail}
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