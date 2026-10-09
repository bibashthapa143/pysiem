"""Configuration management for PySIEM."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present in the current working directory or project root
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

DB_PATH = os.getenv("PYSIEM_DB_PATH", "pysiem.db")
SECRET_KEY = os.getenv("PYSIEM_SECRET_KEY", "insecure-default-key-change-me")
INGEST_API_KEY = os.getenv("PYSIEM_INGEST_API_KEY", "pysiem-ingest-secret-key-12345")
ADMIN_USER = os.getenv("PYSIEM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("PYSIEM_ADMIN_PASSWORD", "adminpassword123")
RULES_DIR = os.getenv("PYSIEM_RULES_DIR", str(Path(__file__).resolve().parent / "rules"))
HOST = os.getenv("PYSIEM_HOST", "127.0.0.1")
PORT = int(os.getenv("PYSIEM_PORT", "8000"))
