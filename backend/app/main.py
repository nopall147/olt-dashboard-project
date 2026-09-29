"""Compatibility launcher for the canonical application in the project root.

Use ``uvicorn main:app --reload`` from this directory or, preferably,
``uvicorn app.main:app --reload`` from the project root.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app  # noqa: E402,F401
