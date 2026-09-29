import urllib.parse
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DB_USER = "postgres"
DB_PASS = urllib.parse.quote_plus("project!@#")
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "olt_db"

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Jika di laptop belum ada Postgres dan mau tes SQLite dulu, cukup ganti ke:
# DATABASE_URL = "sqlite:///./olt_database.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()