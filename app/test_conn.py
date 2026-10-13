import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

print("Mencoba menghubungkan ke:", DATABASE_URL)
engine = create_engine(DATABASE_URL)

try:
    with engine.connect() as connection:
        result = connection.execute(text("SELECT version();"))
        for row in result:
            print("\nSUKSES TERHUBUNG KE NEON! Versi Postgres:", row[0])
except Exception as e:
    print("\nGAGAL TERHUBUNG:", e)