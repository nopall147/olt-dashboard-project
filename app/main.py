import os
import re
import json
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.sql import func as sql_func
from sqlalchemy import text
from app.database import Base, SessionLocal, engine, get_db
from app.models import ActivityEvent, OLTConfig, OLTSettingEntry, OnuDevice, TrafficSample
from app.services.olt_client import env_key, read_onu_traffic, read_pon_snapshot, read_pon_state, snmp_community, telnet_password, test_snmp, test_telnet
from app.services.netmiko_driver import deploy_onu_zte

# Models dan database didefinisikan bersama di app.models dan app.database.
Base.metadata.create_all(bind=engine)

# Migrasi idempotent untuk skema lama.
with engine.begin() as connection:
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS snmp_status VARCHAR(40)"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS telnet_status VARCHAR(40)"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS last_connection_test TIMESTAMP WITH TIME ZONE"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS system_description TEXT"))
    connection.execute(text("ALTER TABLE olt_configs ADD COLUMN IF NOT EXISTS uptime_ticks BIGINT"))
    connection.execute(text("ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS user_agent VARCHAR(255)"))

with SessionLocal() as startup_db:
    for name, ip in (("OLT-C300 Tajur", "192.168.100.20"), ("OLT-C320 Anggraeni", "10.10.10.5")):
        if not startup_db.query(OLTConfig).filter(OLTConfig.name == name).first():
            startup_db.add(OLTConfig(name=name, ip_address=ip, model="ZTE C300/C320"))
    startup_db.commit()

def audit_event(request: Request, event_type: str, information: str):
    return ActivityEvent(event_type=event_type, username="karlink", information=information,
                         client_ip=request.client.host if request.client else None,
                         user_agent=request.headers.get("user-agent", "")[:255])

def format_uptime(ticks):
    if ticks is None:
        return "Belum tersedia"
    seconds = int(ticks) // 100
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{days} hari {hours} jam {minutes} menit"

# ==============================================================================
# 2. INISIALISASI FASTAPI & TEMPLATES
# ==============================================================================
app = FastAPI(title="OLT Monitoring & Provisioning System")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def shared_navigation_context(request: Request):
    db = SessionLocal()
    try:
        counts = dict(db.query(OnuDevice.status, sql_func.count(OnuDevice.id)).group_by(OnuDevice.status).all())
    finally:
        db.close()
    return {"nav_counts": {"dying_gasp": counts.get("DyingGasp", 0), "los": counts.get("LOS", 0)}}

templates.context_processors.append(shared_navigation_context)

@app.get("/olt-management", response_class=HTMLResponse)
def olt_management_page(request: Request, db: Session = Depends(get_db)):
    configs = db.query(OLTConfig).order_by(OLTConfig.name).all()
    olts = []
    for config in configs:
        name = config.name
        devices = db.query(OnuDevice).filter(OnuDevice.olt_name == name).all()
        olts.append({"id": config.id, "name": name, "model": config.model, "ip": config.ip_address, "temperature": "—", "total_onu": len(devices), "uptime": format_uptime(config.uptime_ticks), "synced": config.last_sync.strftime("%Y-%m-%d %H:%M:%S") if config.last_sync else "Belum pernah", "telnet": config.telnet_status or "Belum dites", "snmp": config.snmp_status or "Belum dites", "snmp_version": config.snmp_version, "snmp_port": config.snmp_port, "telnet_username": config.telnet_username, "telnet_port": config.telnet_port, "env_suffix": env_key(name), "tested": config.last_connection_test.strftime("%Y-%m-%d %H:%M:%S") if config.last_connection_test else "Belum dites", "online": sum(x.status == "Online" for x in devices), "los": sum(x.status == "LOS" for x in devices), "dying_gasp": sum(x.status == "DyingGasp" for x in devices), "offline": sum(x.status == "Offline" for x in devices)})
    return templates.TemplateResponse(request=request, name="olt_management.html", context={"olts": olts})

@app.get("/olt-settings", response_class=HTMLResponse)
def olt_settings_page(request: Request, db: Session = Depends(get_db)):
    onus = db.query(OnuDevice).all()
    names = {onu.olt_name for onu in onus if onu.olt_name} | {olt.name for olt in db.query(OLTConfig).all()}
    summary = {"uplink_cards": "—", "gpon_cards": "—", "epon_cards": "—", "total_onu": len(onus), "online": sum(x.status == "Online" for x in onus), "los": sum(x.status == "LOS" for x in onus), "dying_gasp": sum(x.status == "DyingGasp" for x in onus), "offline_other": sum(x.status in ("Offline", "Other") for x in onus)}
    return templates.TemplateResponse(request=request, name="olt_settings.html", context={"summary": summary, "olt_names": sorted(names)})

@app.get("/activity-log", response_class=HTMLResponse)
def activity_log_page(request: Request, db: Session = Depends(get_db)):
    events = db.query(ActivityEvent).order_by(ActivityEvent.created_at.desc()).limit(500).all()
    logs = [{"date": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "—", "user": event.username, "type": event.event_type, "info": event.information, "ip": event.client_ip or "—", "agent": event.user_agent or "—"} for event in events]
    totals = {"total": db.query(sql_func.count(ActivityEvent.id)).scalar() or 0}
    for event_type in ("Login", "Delete", "Update"):
        key = "update_count" if event_type == "Update" else event_type.lower()
        totals[key] = db.query(sql_func.count(ActivityEvent.id)).filter(ActivityEvent.event_type == event_type).scalar() or 0
    return templates.TemplateResponse(request=request, name="activity_log.html", context={"logs": logs, "totals": totals})

@app.get("/graphs", response_class=HTMLResponse)
def graphs_page(request: Request, db: Session = Depends(get_db)):
    onus = db.query(OnuDevice).order_by(OnuDevice.olt_name, OnuDevice.gpon_port).all()
    olt_names = [row[0] for row in db.query(OnuDevice.olt_name).distinct().order_by(OnuDevice.olt_name).all()]
    card_slots = sorted({onu.gpon_port.split("/")[1] for onu in onus if onu.gpon_port and len(onu.gpon_port.split("/")) > 2})
    pon_ports = sorted({onu.gpon_port.rsplit(":", 1)[0] for onu in onus if onu.gpon_port and ":" in onu.gpon_port})
    return templates.TemplateResponse(request=request, name="graphs.html", context={"onus": onus, "olt_names": olt_names, "card_slots": card_slots, "pon_ports": pon_ports})

@app.get("/tr069-profiles", response_class=HTMLResponse)
def tr069_profiles_page(request: Request, db: Session = Depends(get_db)):
    profiles = db.query(OLTSettingEntry).filter(OLTSettingEntry.category == "tr069_profile").order_by(OLTSettingEntry.name).all()
    olts = db.query(OLTConfig).order_by(OLTConfig.name).all()
    return templates.TemplateResponse(request=request, name="tr069_profiles.html", context={
        "profiles": [{"id": p.id, "name": p.name, "data": {k: v for k, v in json.loads(p.data_json).items() if k != "password"}, "has_password": bool(json.loads(p.data_json).get("password"))} for p in profiles],
        "olts": olts,
    })

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
    telnet_username: str = "admin"
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
def api_save_olt(payload: OLTInput, request: Request, db: Session = Depends(get_db)):
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
def api_save_setting_entry(payload: SettingEntryInput, request: Request, db: Session = Depends(get_db)):
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
def api_delete_setting_entry(entry_id: int, request: Request, db: Session = Depends(get_db)):
    entry = db.query(OLTSettingEntry).filter(OLTSettingEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Konfigurasi tidak ditemukan")
    db.add(audit_event(request, "Delete", f"Menghapus konfigurasi lokal {entry.category}: {entry.name}"))
    db.delete(entry)
    db.commit()
    return {"status": "success"}

@app.post("/api/olts/{olt_id}/test")
def api_test_olt(olt_id: int, request: Request, db: Session = Depends(get_db)):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")
    results = {}
    for protocol, operation in (("SNMP", test_snmp), ("Telnet", test_telnet)):
        try:
            result = operation(olt)
            results[protocol] = {"ok": True, "detail": result if isinstance(result, dict) else str(result)[:240]}
        except Exception as exc:
            results[protocol] = {"ok": False, "detail": str(exc)[:240]}
    olt.snmp_status = "Connected" if results["SNMP"]["ok"] else "Failed"
    olt.telnet_status = "Connected" if results["Telnet"]["ok"] else "Failed"
    if results["SNMP"]["ok"] and isinstance(results["SNMP"].get("detail"), dict):
        olt.system_description = str(results["SNMP"]["detail"].get("description") or "")
        olt.uptime_ticks = results["SNMP"]["detail"].get("uptime_ticks")
    olt.last_connection_test = datetime.now(timezone.utc)
    db.add(audit_event(request, "Connection Test", f"Test koneksi OLT {olt.name}: SNMP {'OK' if results['SNMP']['ok'] else 'gagal'}, Telnet {'OK' if results['Telnet']['ok'] else 'gagal'}"))
    db.commit()
    return results

@app.post("/api/olts/{olt_id}/sync")
def api_sync_olt(olt_id: int, request: Request, db: Session = Depends(get_db)):
    olt = db.query(OLTConfig).filter(OLTConfig.id == olt_id).first()
    if not olt:
        raise HTTPException(status_code=404, detail="OLT tidak ditemukan")
    onus = db.query(OnuDevice).filter(OnuDevice.olt_name == olt.name).all()
    pon_interfaces = sorted({onu.gpon_port.rsplit(":", 1)[0] for onu in onus if onu.gpon_port and ":" in onu.gpon_port})
    if not pon_interfaces:
        raise HTTPException(status_code=400, detail="Belum ada ONU dengan port GPON di database untuk OLT ini.")
    updated = 0
    try:
        states, powers = read_pon_snapshot(olt, pon_interfaces, [onu.gpon_port for onu in onus if onu.gpon_port])
        for interface, output in states.items():
            for line in output.splitlines():
                match = re.search(r"gpon-onu_(\d+/\d+/\d+):(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)", line, re.I)
                if not match:
                    continue
                port_id = f"{match.group(1)}:{match.group(2)}"
                phase = match.group(3).lower()
                status = "Online" if phase in {"working", "operation", "online"} else "LOS" if phase in {"los", "losi"} else "DyingGasp" if "dying" in phase else "Offline"
                onu = next((item for item in onus if item.gpon_port == port_id), None)
                if onu:
                    onu.status = status
                    updated += 1
        for onu in onus:
            power_output = powers.get(onu.gpon_port, "")
            upstream_rx = re.search(r"up Rx\s*:\s*(-?[\d.]+)\s*\(dbm\)", power_output, re.I)
            downstream_rx = re.search(r"down Tx\s*:[^\r\n]*?Rx\s*:\s*(-?[\d.]+)\s*\(dbm\)", power_output, re.I)
            onu.rx_olt = float(upstream_rx.group(1)) if upstream_rx else None
            onu.rx_onu = float(downstream_rx.group(1)) if downstream_rx else None
        olt.last_sync = datetime.now(timezone.utc)
        db.add(audit_event(request, "Sync", f"Sync OLT {olt.name}: {updated} ONU diperbarui dari {len(pon_interfaces)} PON"))
        db.commit()
    except Exception as exc:
        db.rollback()
        db.add(audit_event(request, "Sync Error", f"Sync OLT {olt.name} gagal: {str(exc)[:180]}"))
        db.commit()
        raise HTTPException(status_code=502, detail=f"Sinkronisasi gagal: {exc}")
    return {"status": "success", "updated": updated, "interfaces": len(pon_interfaces), "synced_at": olt.last_sync.isoformat()}

@app.post("/api/traffic/{onu_id}/sample")
def api_sample_onu_traffic(onu_id: int, db: Session = Depends(get_db)):
    onu = db.query(OnuDevice).filter(OnuDevice.id == onu_id).first()
    if not onu:
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")
    olt = db.query(OLTConfig).filter(OLTConfig.name == onu.olt_name).first()
    if not olt or not onu.gpon_port:
        raise HTTPException(status_code=400, detail="OLT atau port ONU belum dikonfigurasi")
    try:
        output = read_onu_traffic(olt, onu.gpon_port)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Gagal membaca trafik dari OLT: {exc}")
    input_match = re.search(r"Input rate\s*:\s*([\d.]+)\s*([KMG]?)\s*Bps", output, re.I)
    output_match = re.search(r"Output rate\s*:\s*([\d.]+)\s*([KMG]?)\s*Bps", output, re.I)
    if not input_match or not output_match:
        raise HTTPException(status_code=502, detail="Output trafik OLT tidak dikenali; periksa format CLI firmware.")
    def to_bps(match):
        return float(match.group(1)) * {"": 8, "K": 8_000, "M": 8_000_000, "G": 8_000_000_000}[match.group(2).upper()]
    # On the ONU interface, input is traffic arriving from the subscriber (upload);
    # output is traffic sent toward the subscriber (download).
    sample = TrafficSample(onu_id=onu.id, download_bps=to_bps(output_match), upload_bps=to_bps(input_match))
    db.add(sample)
    db.query(TrafficSample).filter(TrafficSample.sampled_at < datetime.now(timezone.utc) - timedelta(days=30)).delete(synchronize_session=False)
    db.commit()
    db.refresh(sample)
    return {"onu_id": onu.id, "sampled_at": sample.sampled_at.isoformat(), "download_bps": sample.download_bps, "upload_bps": sample.upload_bps}

@app.get("/api/traffic/{onu_id}/history")
def api_onu_traffic_history(onu_id: int, period: str = "3H", db: Session = Depends(get_db)):
    if not db.query(OnuDevice.id).filter(OnuDevice.id == onu_id).first():
        raise HTTPException(status_code=404, detail="ONU tidak ditemukan")
    windows = {"3H": 3, "6H": 6, "1D": 24, "3D": 72, "7D": 168, "30D": 720}
    if period not in windows:
        raise HTTPException(status_code=400, detail="Rentang waktu tidak valid")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=windows[period])
    samples = db.query(TrafficSample).filter(TrafficSample.onu_id == onu_id, TrafficSample.sampled_at >= cutoff).order_by(TrafficSample.sampled_at.asc()).limit(1000).all()
    return [{"sampled_at": sample.sampled_at.isoformat(), "download_bps": sample.download_bps, "upload_bps": sample.upload_bps} for sample in samples]


# ==============================================================================
# 3. ROUTE HALAMAN UTAMA (DASHBOARD)
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request, db: Session = Depends(get_db)):
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
    return templates.TemplateResponse(
        request=request, 
        name="dashboard.html",
        context={"data": dashboard_data}
    )


# ==============================================================================
# 4. ROUTE HALAMAN UNREGISTERED ONUS (Daftar ONU Unconfigured dari OLT)
# ==============================================================================
@app.get("/add-onu", response_class=HTMLResponse)
@app.get("/unregistered-onus", response_class=HTMLResponse)
def unregistered_onus_page(request: Request, db: Session = Depends(get_db)):
    # Placeholder until ONU discovery from the OLT is available.
    unregistered_list = []
    return templates.TemplateResponse(
        request=request, 
        name="unregistered_onus.html",
        context={"unregistered_onus": unregistered_list}
    )


# ==============================================================================
# 5. ENDPOINT API PROVISIONING & SIMPAN KE DATABASE
# ==============================================================================
@app.post("/api/v1/register-onu")
def register_onu(req: ONURequest, request: Request, db: Session = Depends(get_db)):
    # Validasi apakah SN sudah pernah terdaftar
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Serial Number {req.sn_onu} sudah terdaftar!")

    olt = db.query(OLTConfig).filter(OLTConfig.ip_address == req.olt_ip).first()
    if not olt:
        raise HTTPException(status_code=400, detail="OLT belum terdaftar pada OLT Management.")
    password = telnet_password(olt.name)
    if not password:
        raise HTTPException(status_code=503, detail=f"Kredensial OLT belum diatur: OLT_{env_key(olt.name)}_TELNET_PASSWORD")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,50}", req.sn_onu.strip()):
        raise HTTPException(status_code=400, detail="Serial Number hanya boleh berisi huruf, angka, titik, underscore, titik dua, atau strip.")
    if not (1 <= req.slot <= 21 and 1 <= req.port <= 16 and 1 <= req.vlan_id <= 4094):
        raise HTTPException(status_code=400, detail="Slot, PON, atau VLAN berada di luar rentang yang didukung.")
    if not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", req.nama_pelanggan.strip()) or not re.fullmatch(r"[A-Za-z0-9_.@+-]{1,100}", req.pppoe_user) or not re.fullmatch(r"[A-Za-z0-9!#$%&*()+,./:=?@^_~-]{1,100}", req.pppoe_pass) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", req.actual_type) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", req.profil_paket):
        raise HTTPException(status_code=400, detail="Nama atau kredensial PPPoE tidak valid.")
    # Reserve an unused ONU ID on the selected PON when the user chooses Auto.
    interface = f"1/{req.slot}/{req.port}"
    try:
        pon_output = read_pon_state(olt, interface)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Tidak dapat membaca OLT sebelum provisioning: {exc}")
    used_ids = {int(value) for value in re.findall(r"gpon-onu_\d+/\d+/\d+:(\d+)", pon_output, re.I)}
    onu_idx = req.onu_id if req.onu_id is not None else next((value for value in range(1, 129) if value not in used_ids), None)
    if onu_idx is None or not 1 <= onu_idx <= 128 or onu_idx in used_ids:
        raise HTTPException(status_code=409, detail="ONU ID tidak tersedia pada PON yang dipilih.")
    try:
        deployment = deploy_onu_zte(olt.ip_address, olt.telnet_username, password, {"slot": req.slot, "port": req.port, "onu_id": onu_idx, "sn_onu": req.sn_onu.strip().upper(), "nama_pelanggan": req.nama_pelanggan.strip(), "actual_type": req.actual_type, "vlan_id": req.vlan_id, "pppoe_user": req.pppoe_user, "pppoe_pass": req.pppoe_pass, "profil_paket": req.profil_paket, "telnet_port": olt.telnet_port})
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Provisioning ke OLT gagal: {exc}")
    if deployment.get("status") != "success":
        raise HTTPException(status_code=502, detail=f"OLT menolak konfigurasi: {deployment.get('message', 'unknown error')[:500]}")
    gpon_port_str = f"1/{req.slot}/{req.port}:{onu_idx}"
    olt_alias = olt.name

    # Simpan record ke PostgreSQL
    new_onu = OnuDevice(
        olt_name=olt_alias,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user,
        gpon_port=gpon_port_str,
        status="Offline",
        rx_olt=None,
        rx_onu=None,
        sn_mac=req.sn_onu.strip().upper(),
        actual_type=req.actual_type or "ZTE-GPON"
    )

    db.add(new_onu)
    db.add(audit_event(request, "Register", f"Registrasi ONU {req.sn_onu.strip().upper()} untuk {req.nama_pelanggan.strip().upper()} pada {olt_alias}"))
    db.commit()
    db.refresh(new_onu)

    return {
        "status": "success", 
        "message": "Konfigurasi berhasil dikirim ke OLT dan disimpan di Database", 
        "data": req.model_dump() if hasattr(req, "model_dump") else req.dict()
    }


# ==============================================================================
# 6. ROUTE HALAMAN ALL ONUS (DATABASE DINAMIS)
# ==============================================================================
@app.get("/all-onus", response_class=HTMLResponse)
def all_onus_page(request: Request, status: str = "ALL", db: Session = Depends(get_db)):
    # Ambil seluruh ONU dari PostgreSQL
    allowed_statuses = {"ALL", "Online", "DyingGasp", "LOS", "Offline"}
    selected_status = status if status in allowed_statuses else "ALL"
    onus = db.query(OnuDevice).order_by(OnuDevice.id.desc()).all()
    
    # Hitung metrik card persentase redaman secara dinamis
    total_onus = len(onus)
    good_count = sum(1 for onu in onus if onu.rx_onu is not None and onu.rx_onu >= -27.00)
    warning_count = sum(1 for onu in onus if onu.rx_onu is not None and -30.00 <= onu.rx_onu < -27.00)
    critical_count = sum(1 for onu in onus if onu.rx_onu is not None and onu.rx_onu < -30.00)
    other_count = total_onus - (good_count + warning_count + critical_count)

    stats = {
        "good_percentage": round((good_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "warning_percentage": round((warning_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "critical_percentage": round((critical_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "other_percentage": round((other_count / total_onus * 100), 1) if total_onus > 0 else 0.0,
        "good_count": good_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "other_count": other_count
    }

    return templates.TemplateResponse(
        request=request, 
        name="all_onus.html",
        context={"onus": onus, "stats": stats, "selected_status": selected_status}
    )
