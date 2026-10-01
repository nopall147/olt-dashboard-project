"""Database engine, declarative base, and request-scoped session dependency."""
import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


def _load_local_environment():
    # Menemukan root direktori project secara dinamis
    current_dir = Path(__file__).resolve().parent
    env_path = None
    for parent in [current_dir] + list(current_dir.parents):
        candidate = parent / ".env"
        if candidate.is_file():
            env_path = candidate
            break

    if not env_path or not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_local_environment()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL tidak ditemukan. Pastikan sudah mengisi file .env dengan URL Neon!")

# Pastikan driver menggunakan postgresql+psycopg2 jika memakai format URL postgresql://
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# Konfigurasi engine dengan pre-ping dan recycle untuk mencegah koneksi serverless Neon drop
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=5,
    max_overflow=10,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()