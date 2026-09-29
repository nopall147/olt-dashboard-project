import os
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import engine, Base, get_db
from app.models import OnuDevice

# Buat tabel otomatis jika belum ada di database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="OLT Monitoring & Provisioning System")

# Path yang benar: naik 2 tingkat dari backend/app ke root project, lalu masuk ke frontend/templates
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) # folder backend/app
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..")) # folder root olt-dashboard
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "frontend", "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

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

# ==============================================================================
# ROUTE WEB TAMPILAN
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request):
    dashboard_data = {
        "summary": {
            "total_olts": 2,
            "total_onus": 290,
            "online_onus": 279,
            "online_percentage": 96.21,
            "dying_gasp_onus": 6,
            "dying_gasp_percentage": 2.07,
            "los_onus": 1,
            "los_percentage": 0.34,
            "offline_onus": 4,
            "offline_percentage": 1.38,
        },
        "olts": [
            {
                "id": 1,
                "name": "OLT-C320 Anggraeni",
                "model": "ZTE-C300-M",
                "ip": "10.10.10.5",
                "status": "Online",
                "uptime": "8 days 0 hours 42 minutes",
                "temperature": 40,
                "total_fan": 0,
                "total_onu": 278,
                "online": 267,
                "los": 1,
                "dying_gasp": 6,
                "offline": 4,
                "other": 0,
                "fans": []
            },
            {
                "id": 2,
                "name": "OLT-C300 Tajur",
                "model": "ZTE-C300",
                "ip": "192.168.100.20",
                "status": "Online",
                "uptime": "1 days 2 hours 34 minutes",
                "temperature": 51,
                "total_fan": 3,
                "total_onu": 12,
                "online": 12,
                "los": 0,
                "dying_gasp": 0,
                "offline": 0,
                "other": 0,
                "fans": [
                    {"name": "Fan 1", "status": "Online", "rpm": 3100, "level": "Super (4)"},
                    {"name": "Fan 2", "status": "Online", "rpm": 3100, "level": "Super (4)"},
                    {"name": "Fan 3", "status": "Online", "rpm": 3100, "level": "Super (4)"}
                ]
            }
        ]
    }
    return templates.TemplateResponse(
        request=request, 
        name="dashboard.html",
        context={"data": dashboard_data}
    )

@app.get("/add-onu", response_class=HTMLResponse)
def add_onu_page(request: Request):
    return templates.TemplateResponse(request=request, name="add_onu.html")

@app.get("/all-onus", response_class=HTMLResponse)
def all_onus_page(request: Request, db: Session = Depends(get_db)):
    onus = db.query(OnuDevice).order_by(OnuDevice.id.desc()).all()
    
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
        context={"onus": onus, "stats": stats}
    )

# ==============================================================================
# API ENDPOINT (HANYA SATU SAJA)
# ==============================================================================
@app.post("/api/v1/register-onu")
def register_onu(req: ONURequest, db: Session = Depends(get_db)):
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Serial Number {req.sn_onu} sudah terdaftar!")

    onu_idx = req.onu_id if req.onu_id else 1
    gpon_port_str = f"1/{req.slot}/{req.port}:{onu_idx}"
    olt_alias = "OLT-C300 Tajur" if "192.168.100" in req.olt_ip else "OLT-C320 Anggraeni"

    new_onu = OnuDevice(
        olt_name=olt_alias,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user,
        gpon_port=gpon_port_str,
        status="Online",
        rx_olt=-22.45,
        rx_onu=-21.15,
        sn_mac=req.sn_onu.strip().upper(),
        actual_type=req.actual_type
    )

    db.add(new_onu)
    db.commit()
    db.refresh(new_onu)

    return {
        "status": "success",
        "message": "Data berhasil diproses ke OLT dan disimpan di Database",
        "data": req.model_dump() if hasattr(req, "model_dump") else req.dict()
    }