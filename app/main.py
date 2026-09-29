import os
import urllib.parse
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.sql import func

# ==============================================================================
# 1. KONFIGURASI DATABASE POSTGRESQL (SQLALCHEMY)
# ==============================================================================
DB_USER = "postgres"
DB_PASS = urllib.parse.quote_plus("project!@#")  # Meng-encode karakter !, @, dan #
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "olt_db"

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Model Tabel ONU di PostgreSQL
class OnuDevice(Base):
    __tablename__ = "onu_devices"

    id = Column(Integer, primary_key=True, index=True)
    olt_name = Column(String(100), nullable=False)
    customer_name = Column(String(150), nullable=False)
    description = Column(String(255), nullable=True)
    pppoe_user = Column(String(100), nullable=True)
    gpon_port = Column(String(50), nullable=False)       # Contoh: 1/2/1:8
    status = Column(String(50), default="Online")        # Online, DyingGasp, LOS, Offline
    rx_olt = Column(Float, nullable=True)                # Nilai Rx OLT (dBm)
    rx_onu = Column(Float, nullable=True)                # Nilai Rx ONU (dBm)
    sn_mac = Column(String(50), unique=True, index=True) # Serial Number ONU
    actual_type = Column(String(50), default="GPON")     # Model ONU (misal: F660 / HG6145D2)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# Buat tabel otomatis jika belum ada di database
Base.metadata.create_all(bind=engine)

# Dependency untuk inject Session DB ke FastAPI Routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==============================================================================
# 2. INISIALISASI FASTAPI & TEMPLATES
# ==============================================================================
app = FastAPI(title="OLT Monitoring & Provisioning System")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

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

@app.post("/api/v1/register-onu")
def register_onu(req: ONURequest, db: Session = Depends(get_db)):
    # Validasi apakah SN sudah pernah terdaftar
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Serial Number {req.sn_onu} sudah terdaftar!")

    # Format GPON Port: 1/Slot/Port:ONU_ID
    onu_idx = req.onu_id if req.onu_id else 1
    gpon_port_str = f"1/{req.slot}/{req.port}:{onu_idx}"
    olt_alias = "OLT-C300 Tajur" if "192.168.100" in req.olt_ip else "OLT-C320 Anggraeni"

    new_onu = OnuDevice(
        olt_name=olt_alias,
        customer_name=req.nama_pelanggan.strip().upper(),
        description=req.description or f"VLAN {req.vlan_id}",
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


# ==============================================================================
# 3. ROUTE HALAMAN UTAMA (DASHBOARD)
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


# ==============================================================================
# 4. ROUTE HALAMAN FORM (ADD ONU)
# ==============================================================================
@app.get("/add-onu", response_class=HTMLResponse)
def add_onu_page(request: Request):
    return templates.TemplateResponse(request=request, name="add_onu.html")


# ==============================================================================
# 5. ENDPOINT API PROVISIONING & SIMPAN KE DATABASE
# ==============================================================================
@app.post("/api/v1/register-onu")
def register_onu(req: ONURequest, db: Session = Depends(get_db)):
    # Validasi apakah SN sudah pernah terdaftar
    existing = db.query(OnuDevice).filter(OnuDevice.sn_mac == req.sn_onu.strip().upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Serial Number {req.sn_onu} sudah terdaftar!")

    # Format penomoran PON (Rack 1 / Shelf 1 / Slot / Port : ONU ID)
    onu_idx = req.onu_id if req.onu_id else 1
    gpon_port_str = f"1/{req.slot}/{req.port}:{onu_idx}"
    olt_alias = "OLT-C300 Tajur" if "192.168.100" in req.olt_ip else "OLT-C320 Anggraeni"

    # Simpan record ke PostgreSQL
    new_onu = OnuDevice(
        olt_name=olt_alias,
        customer_name=req.nama_pelanggan,
        description=f"VLAN: {req.vlan_id} | Profile: {req.profil_paket}",
        pppoe_user=req.pppoe_user,
        gpon_port=gpon_port_str,
        status="Online",
        rx_olt=-22.45,  # Nilai default awal (dapat diupdate sinkronisasi OLT berkala)
        rx_onu=-21.15,
        sn_mac=req.sn_onu.strip().upper(),
        actual_type="ZTE-GPON"
    )

    db.add(new_onu)
    db.commit()
    db.refresh(new_onu)

    return {
        "status": "success", 
        "message": "Data berhasil diproses ke OLT dan disimpan di Database", 
        "data": req
    }


# ==============================================================================
# 6. ROUTE HALAMAN ALL ONUS (DATABASE DINAMIS)
# ==============================================================================
@app.get("/all-onus", response_class=HTMLResponse)
def all_onus_page(request: Request, db: Session = Depends(get_db)):
    # Ambil seluruh ONU dari PostgreSQL
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
        context={"onus": onus, "stats": stats}
    )