"""SQLAlchemy models shared by the FastAPI routes and database layer."""
from sqlalchemy import BigInteger, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


class OnuDevice(Base):
    __tablename__ = "onu_devices"

    id = Column(Integer, primary_key=True, index=True)
    olt_name = Column(String(100), nullable=False)
    customer_name = Column(String(150), nullable=False)
    description = Column(String(255), nullable=True)
    pppoe_user = Column(String(100), nullable=True)
    gpon_port = Column(String(50), nullable=False)
    status = Column(String(50), default="Offline")
    rx_olt = Column(Float, nullable=True)
    rx_onu = Column(Float, nullable=True)
    sn_mac = Column(String(50), unique=True, index=True)
    actual_type = Column(String(50), default="GPON")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ActivityEvent(Base):
    __tablename__ = "activity_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(40), nullable=False, index=True)
    username = Column(String(100), nullable=False, default="system")
    information = Column(Text, nullable=False)
    client_ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class OLTConfig(Base):
    __tablename__ = "olt_configs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    ip_address = Column(String(64), nullable=False, unique=True)
    model = Column(String(80), nullable=False, default="ZTE C300/C320")
    snmp_version = Column(String(10), nullable=False, default="2c")
    snmp_port = Column(Integer, nullable=False, default=161)
    snmp_community_encrypted = Column(Text, nullable=True)
    telnet_username = Column(String(100), nullable=False, default="admin")
    telnet_password_encrypted = Column(Text, nullable=True)
    telnet_port = Column(Integer, nullable=False, default=23)
    snmp_status = Column(String(40), nullable=True)
    telnet_status = Column(String(40), nullable=True)
    last_connection_test = Column(DateTime(timezone=True), nullable=True)
    system_description = Column(Text, nullable=True)
    uptime_ticks = Column(BigInteger, nullable=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)


class TrafficSample(Base):
    __tablename__ = "traffic_samples"

    id = Column(Integer, primary_key=True, index=True)
    onu_id = Column(Integer, ForeignKey("onu_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    download_bps = Column(Float, nullable=False)
    upload_bps = Column(Float, nullable=False)
    sampled_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class OLTSettingEntry(Base):
    __tablename__ = "olt_setting_entries"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(40), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    data_json = Column(Text, nullable=False, default="{}")
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class OLTConfigBackup(Base):
    __tablename__ = "olt_config_backups"

    id = Column(Integer, primary_key=True, index=True)
    olt_id = Column(Integer, ForeignKey("olt_configs.id", ondelete="CASCADE"), nullable=True, index=True)
    filename = Column(String(180), nullable=False)
    backup_type = Column(String(20), nullable=False, index=True)
    content_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
