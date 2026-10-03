import os
import re
import json
import asyncio
import bcrypt
from enum import Enum
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Request, Depends, HTTPException, Form, status
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.sql import func as sql_func
from sqlalchemy import text
from app.database import Base, SessionLocal, engine, get_db
from app.models import ActivityEvent, OLTConfig, OLTConfigBackup, OLTSettingEntry, OnuDevice, TrafficSample, User
from app.services.olt_client import encrypt_olt_secret, env_key, get_telnet_password, read_onu_traffic, read_pon_snapshot, read_pon_state, test_snmp, test_telnet
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
# INISIALISASI DATA AWAL (OLT & ADMIN DEFAULT)
# ==============================================================================
with SessionLocal() as startup_db:
    for name, ip in (("OLT-C300 Tajur", "192.168.100.20"), ("OLT-C320 Anggraeni", "10.10.10.5")):
        if not startup_db.query(OLTConfig).filter(OLTConfig.name == name).first():
            startup_db.add(OLTConfig(name=name, ip_address=ip, model="ZTE C300/C320"))
    
    admin_user = startup_db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        startup_db.add(User(
            fullname="Hari Pujianto",
            username="admin",
            email="admin@olt.local",
            password_hash=hash_password("admin123"),
            role="Super Admin",
            is_active=True,
            is_verified=True
        ))
    else:
        # Otomatis perbaiki role akun admin lama jika masih bernama "admin"
        if admin_user.role in ["admin", "operator", "Viewer"]:
            admin_user.role = "Super Admin"
    startup_db.commit()

# ==============================================================================
# INISIALISASI FASTAPI & CONTEXT GLOBAL
# ==============================================================================
app = FastAPI(title="OLT Monitoring & Provisioning System")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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
        "nav_counts": {"dying_gasp": counts.get("DyingGasp", 0), "los": counts.get("LOS", 0)},
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
    user.fullname = payload.full_name.strip()
    if payload.image is not None:
        user.image = payload.image
    if payload.new_password and len(payload.new_password.strip()) >= 6:
        user.password_hash = hash_password(payload.new_password.strip())

    db.add(audit_event(request, "Update", f"User {user.username} memperbarui profil"))
    db.commit()
    return {"status": "success", "message": "Profil berhasil disimpan"}

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
        target.password_hash = hash_password(payload.new_password.strip())

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

# ==============================================================================
# ROUTES: OLT, MONITORING & DASHBOARD (SESUAI MATRIKS RBAC)
# ==============================================================================

# Dashboard: Semua Role (Super Admin, NOC, Viewer)
@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    onus = db.query(OnuDevice).all()
    counts = {status: sum(onu.status == status for onu in onus) for status in ("Online", "DyingGasp", "LOS", "Offline")}
    total = len(onus)
    olt_configs = db.query(OLTConfig).all()
    config_by_name = {olt.name: olt for olt in olt_configs}
    names = sorted(({onu.olt_name for onu in onus if onu.olt_name}) | set(config_by_name))
    olt_rows = []
    for idx, name in enumerate(names, 1):
        devices = [onu for onu in onus if onu.olt_name == name]
        config = config_by_name.get(name)
        olt_rows.append({"id": config.id if config else idx, "name": name, "model": config.model if config else "OLT", "ip": config.ip_address if config else "—", "status": "Terdaftar" if config else "ONU database", "uptime": "Tidak tersedia dari database", "temperature": "—", "total_fan": "—", "total_onu": len(devices), "online": sum(x.status == "Online" for x in devices), "los": sum(x.status == "LOS" for x in devices), "dying_gasp": sum(x.status == "DyingGasp" for x in devices), "offline": sum(x.status == "Offline" for x in devices), "other": sum(x.status not in ("Online", "DyingGasp", "LOS", "Offline") for x in devices), "fans": []})
    percentage = lambda value: round(value / total * 100, 2) if total else 0
    dashboard_data = {"summary": {"total_olts": len(names), "total_onus": total, "online_onus": counts["Online"], "online_percentage": percentage(counts["Online"]), "dying_gasp_onus": counts["DyingGasp"], "dying_gasp_percentage": percentage(counts["DyingGasp"]), "los_onus": counts["LOS"], "los_percentage": percentage(counts["LOS"]), "offline_onus": counts["Offline"], "offline_percentage": percentage(counts["Offline"])}, "olts": olt_rows}
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"data": dashboard_data})

# ONU & All ONUs: Semua Role (Super Admin, NOC, Viewer)
@app.get("/all-onus", response_class=HTMLResponse)
def all_onus_page(request: Request, status: str = "ALL", db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    allowed_statuses = {"ALL", "Online", "DyingGasp", "LOS", "Offline"}
    selected_status = status if status in allowed_statuses else "ALL"
    onus = db.query(OnuDevice).order_by(OnuDevice.id.desc()).all()
    total_onus = len(onus)
    good_count = sum(1 for onu in onus if onu.rx_onu is not None and onu.rx_onu >= -27.00)
    warning_count = sum(1 for onu in onus if onu.rx_onu is not None and -30.00 <= onu.rx_onu < -27.00)
    critical_count = sum(1 for onu in onus if onu.rx_onu is not None and onu.rx_onu < -30.00)
    other_count = total_onus - (good_count + warning_count + critical_count)
    good_olt_count = sum(1 for onu in onus if onu.rx_olt is not None and onu.rx_olt >= -27.00)
    warning_olt_count = sum(1 for onu in onus if onu.rx_olt is not None and -30.00 <= onu.rx_olt < -27.00)
    critical_olt_count = sum(1 for onu in onus if onu.rx_olt is not None and onu.rx_olt < -30.00)
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
        context={"onus": onus, "stats": stats, "selected_status": selected_status, "olt_names": olt_names, "card_names": card_names, "pon_names": pon_names, "onu_types": onu_types}
    )

# Template TR069: Semua Role (Super Admin, NOC, Viewer)
@app.get("/tr069-profiles", response_class=HTMLResponse)
def tr069_profiles_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    profiles = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "tr069_profile").order_by(OLTSettingEntry.name).all()
    olts = db.query(OLTConfig).order_by(OLTConfig.name).all()
    return templates.TemplateResponse(request=request, name="tr069_profiles.html", context={
        "profiles": [{"id": p.id, "name": p.name, "data": {k: v for k, v in json.loads(p.data_json).items() if k != "password"}, "has_password": bool(json.loads(p.data_json).get("password"))} for p in profiles],
        "olts": olts,
    })

# Traffic Graphs: Semua Role (Super Admin, NOC, Viewer)
@app.get("/graphs", response_class=HTMLResponse)
def graphs_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC, Role.VIEWER]))):
    onus = db.query(OnuDevice).order_by(OnuDevice.olt_name, OnuDevice.gpon_port).all()
    olt_names = [row[0] for row in db.query(OnuDevice.olt_name).distinct().order_by(OnuDevice.olt_name).all()]
    card_slots = sorted({onu.gpon_port.split("/")[1] for onu in onus if onu.gpon_port and len(onu.gpon_port.split("/")) > 2})
    pon_ports = sorted({onu.gpon_port.rsplit(":", 1)[0] for onu in onus if onu.gpon_port and ":" in onu.gpon_port})
    return templates.TemplateResponse(request=request, name="graphs.html", context={"onus": onus, "olt_names": olt_names, "card_slots": card_slots, "pon_ports": pon_ports})

# OLT Management: Super Admin & NOC Saja (Viewer Ditolak)
@app.get("/olt-management", response_class=HTMLResponse)
def olt_management_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
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
    return templates.TemplateResponse(request=request, name="olt_management.html", context={"olts": olts})

# OLT Settings: Super Admin & NOC Saja (Viewer Ditolak)
@app.get("/olt-settings", response_class=HTMLResponse)
def olt_settings_page(request: Request, olt_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    configs = db.query(OLTConfig).order_by(OLTConfig.name).all()
    selected = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first() if olt_id else None
    if not selected and configs:
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
    return templates.TemplateResponse(request=request, name="olt_settings.html", context={
        "summary": summary, "olt_names": [config.name for config in configs], "selected_olt": olt,
        "card_inventory": card_inventory,
    })

# Activity Log: Super Admin & NOC Saja (Viewer Ditolak)
@app.get("/activity-log", response_class=HTMLResponse)
def activity_log_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    events = db.query(ActivityEvent).order_by(ActivityEvent.created_at.desc()).limit(500).all()
    logs = [{"date": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "—", "user": event.username, "type": event.event_type, "info": event.information, "ip": event.client_ip or "—", "agent": event.user_agent or "—"} for event in events]
    totals = {"total": db.query(sql_func.count(ActivityEvent.id)).scalar() or 0}
    for event_type in ("Login", "Delete", "Update"):
        key = "update_count" if event_type == "Update" else event_type.lower()
        totals[key] = db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type == event_type).scalar() or 0
    return templates.TemplateResponse(request=request, name="activity_log.html", context={"logs": logs, "totals": totals})

# Registrasi ONU: Hanya Super Admin & NOC yang bisa menambahkan
@app.get("/add-onu", response_class=HTMLResponse)
def manual_add_onu_page(request: Request, user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    return templates.TemplateResponse(request=request, name="add_onu.html", context={
        "olts": [{"name": "OLT-C300 Tajur", "ip_address": "192.168.100.20"}, {"name": "OLT-C320 Anggraeni", "ip_address": "10.10.10.5"}], "ui_demo": True
    })

@app.get("/unregistered-onus", response_class=HTMLResponse)
def unregistered_onus_page(request: Request, user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    olts = [{"name": "OLT-C300 Tajur", "ip_address": "192.168.100.20"}, {"name": "OLT-C320 Anggraeni", "ip_address": "10.10.10.5"}]
    return templates.TemplateResponse(request=request, name="unregistered_onus.html", context={"unregistered_onus": [], "olts": olts})

# API Endpoints
class ONURequest(BaseModel):
    olt_ip: str
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

@app.get("/api/olts")
def api_list_olts(db: Session = Depends(get_db)):
    return [{"id": olt.id, "name": olt.name, "ip_address": olt.ip_address, "model": olt.model, "snmp_version": olt.snmp_version, "snmp_port": olt.snmp_port, "telnet_username": olt.telnet_username, "telnet_port": olt.telnet_port} for olt in db.query(OLTConfig).order_by(OLTConfig.name).all()]

@app.get("/api/summary")
def api_summary(db: Session = Depends(get_db)):
    counts = dict(db.query(OnuDevice.status, sql_func.count(OnuDevice.id)).group_by(OnuDevice.status).all())
    return {"DyingGasp": counts.get("DyingGasp", 0), "LOS": counts.get("LOS", 0)}

@app.post("/api/olts")
def api_save_olt(payload: OLTInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    name = payload.name.strip()
    ip_address = payload.ip_address.strip()
    if not name or not ip_address or payload.snmp_version != "2c":
        raise HTTPException(status_code=400, detail="Isi nama/IP OLT; versi SNMP yang didukung saat ini v2c.")
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
    if db.query(OLTConfig).filter(OLTConfig.ip_address == ip_address, OLTConfig.name != name).first():
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
    db.commit()
    return {"status": "success", "id": olt.id}

@app.get("/api/olt-settings/data")
def api_list_setting_entries(category: str, db: Session = Depends(get_db)):
    allowed = {"uplink", "pon", "vlan", "onu_type", "vlan_profile", "ip_profile", "speed_profile", "system", "tr069_profile"}
    if category not in allowed:
        raise HTTPException(status_code=400, detail="Kategori pengaturan tidak dikenal")
    entries = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == category).order_by(OLTSettingEntry.name).all()
    return [{"id": entry.id, "category": entry.category, "name": entry.name, "data": json.loads(entry.data_json), "updated_at": entry.updated_at.isoformat() if entry.updated_at else None} for entry in entries]

@app.post("/api/olt-settings/data")
def api_save_setting_entry(payload: SettingEntryInput, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    allowed = {"uplink", "pon", "vlan", "onu_type", "vlan_profile", "ip_profile", "speed_profile", "system", "tr069_profile"}
    category, name = payload.category.strip(), payload.name.strip()
    if category not in allowed or not name or len(name) > 120:
        raise HTTPException(status_code=400, detail="Kategori atau nama pengaturan tidak valid")
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.id == payload.id, OLTSettingEntry.category == category).first() if payload.id else None
    if entry and db.query(OLTSettingEntry).filter(OLTSettingEntry.category == category, OLTSettingEntry.name == name, OLTSettingEntry.id != entry.id).first():
        raise HTTPException(status_code=409, detail="Nama profile sudah digunakan")
    if not entry:
        entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == category, OLTSettingEntry.name == name).first()
    if not entry:
        entry = OLTSettingEntry(category=category, name=name)
        db.add(entry)
        event_type = "Create"
    else:
        event_type = "Update"
    entry.name = name
    setting_data = dict(payload.data)
    if entry.id and category == "tr069_profile" and not setting_data.get("password"):
        setting_data["password"] = json.loads(entry.data_json).get("password", "")
    entry.data_json = json.dumps(setting_data, ensure_ascii=False)
    db.add(audit_event(request, event_type, f"{event_type} konfigurasi lokal {category}: {name}"))
    db.commit()
    return {"status": "success", "id": entry.id}

@app.delete("/api/olt-settings/data/{entry_id}")
def api_delete_setting_entry(entry_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Konfigurasi tidak ditemukan")
    db.add(audit_event(request, "Delete", f"Menghapus konfigurasi lokal {entry.category}: {entry.name}"))
    db.delete(entry)
    db.commit()
    return {"status": "success"}

@app.post("/api/v1/register-onu")
def register_onu(req: ONURequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.NOC]))):
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Serial Number {req.sn_onu} sudah terdaftar!")
    olt = db.query(OLTConfig).filter(OLTConfig.ip_address == req.olt_ip).first()
    if not olt:
        raise HTTPException(status_code=400, detail="OLT belum terdaftar.")
    password = get_telnet_password(olt)
    if not password:
        raise HTTPException(status_code=503, detail=f"Kredensial OLT belum diatur: OLT_{env_key(olt.name)}_TELNET_PASSWORD")
    new_onu = OnuDevice(
        olt_name=olt.name, customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user, gpon_port=f"1/{req.slot}/{req.port}:1",
        status="Offline", sn_mac=req.sn_onu.strip().upper(), actual_type=req.actual_type or "ZTE-GPON"
    )
    db.add(new_onu)
    db.add(audit_event(request, "Register", f"Registrasi ONU {req.sn_onu} untuk {req.nama_pelanggan}"))
    db.commit()
    return {"status": "success", "message": "Konfigurasi disimpan"}