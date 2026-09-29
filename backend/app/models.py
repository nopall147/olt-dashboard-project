from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from app.database import Base

class OnuDevice(Base):
    __tablename__ = "onu_devices"

    id = Column(Integer, primary_key=True, index=True)
    olt_name = Column(String(100), nullable=False)        # Misal: OLT-C300 Tajur
    customer_name = Column(String(150), nullable=False)   # Misal: FITRIANA
    description = Column(String(255), nullable=True)     # Alamat/Keterangan
    pppoe_user = Column(String(100), nullable=True)      # Username PPPoE
    gpon_port = Column(String(50), nullable=False)       # Format: 1/2/1:8
    status = Column(String(50), default="Offline")       # Online, LOS, DyingGasp, Offline
    rx_olt = Column(Float, nullable=True)                # Nilai dBm RX OLT
    rx_onu = Column(Float, nullable=True)                # Nilai dBm RX ONU
    sn_mac = Column(String(50), unique=True, index=True) # FHTTC27552A0
    actual_type = Column(String(50), default="GPON")     # HG6145D2 / F660
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    