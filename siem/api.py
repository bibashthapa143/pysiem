"""FastAPI application for PySIEM.

Provides authenticated log ingestion endpoints, query APIs for events
and alerts, rule inspection, and dashboard metrics.
"""

import hmac
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from siem import auth, storage
from siem.config import DB_PATH, INGEST_API_KEY, RULES_DIR
from siem.ingest import ingest_raw_lines, ingest_structured_events
from siem.models import (
    AlertStatusUpdate,
    AuthTokenResponse,
    IngestLogsRequest,
    UserCredentials,
)
from siem.rules import load_rules

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure database and administrator user exist upon application startup."""
    storage.init_db(DB_PATH)
    auth.init_default_admin(DB_PATH)
    yield


app = FastAPI(
    title="PySIEM",
    description="Lightweight Security Information and Event Management System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"


def verify_ingest_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> bool:
    """Validate API key provided via X-API-Key or Bearer header."""
    provided_key = x_api_key
    if not provided_key and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            provided_key = parts[1]

    if not provided_key or not hmac.compare_digest(provided_key, INGEST_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing ingestion API key",
        )
    return True


def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    """Validate session token for protected SIEM routes."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must follow 'Bearer <token>' format",
        )
    username = auth.verify_token(parts[1])
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token is invalid or has expired",
        )
    return username


# ---------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------
@app.post("/api/v1/auth/login", response_model=AuthTokenResponse)
def login(creds: UserCredentials):
    """Authenticate with username and password, returns signed bearer token."""
    user = storage.get_user(creds.username, db_path=DB_PATH)
    if not user or not auth.verify_password(creds.password, user["password_hash"], user["salt"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = auth.create_token(creds.username)
    return AuthTokenResponse(access_token=token, username=creds.username)


# ---------------------------------------------------------
# Log Ingestion Routes
# ---------------------------------------------------------
@app.post("/api/v1/ingest")
def ingest_logs(
    payload: IngestLogsRequest,
    _authorized: bool = Depends(verify_ingest_key),
):
    """
    Ingest log records via HTTP.
    Accepts raw syslog lines or structured event dictionaries.
    """
    if payload.lines:
        res = ingest_raw_lines(payload.lines, db_path=DB_PATH, rules_dir=RULES_DIR)
        return {"status": "success", "type": "raw_lines", **res}
    elif payload.events:
        res = ingest_structured_events(payload.events, db_path=DB_PATH, rules_dir=RULES_DIR)
        return {"status": "success", "type": "structured_events", **res}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must include either 'lines' or 'events' array",
        )


# ---------------------------------------------------------
# Event Query Routes
# ---------------------------------------------------------
@app.get("/api/v1/events")
def list_events(
    src_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    activity: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Free text search query"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: str = Depends(get_current_user),
):
    """Search and paginate normalized SIEM events."""
    events, total = storage.query_events(
        db_path=DB_PATH,
        src_ip=src_ip,
        username=username,
        outcome=outcome,
        activity=activity,
        start_time=start_time,
        end_time=end_time,
        search_query=q,
        limit=limit,
        offset=offset,
    )
    return {"events": events, "total": total, "limit": limit, "offset": offset}


# ---------------------------------------------------------
# Alert Routes
# ---------------------------------------------------------
@app.get("/api/v1/alerts")
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _user: str = Depends(get_current_user),
):
    """Retrieve security detection alerts with pagination."""
    alerts, total = storage.query_alerts(
        db_path=DB_PATH,
        status=status_filter,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {"alerts": alerts, "total": total, "limit": limit, "offset": offset}


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: int, _user: str = Depends(get_current_user)):
    """Fetch details of a single alert by ID."""
    alert = storage.get_alert_by_id(alert_id, db_path=DB_PATH)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.patch("/api/v1/alerts/{alert_id}/status")
def update_alert(
    alert_id: int,
    body: AlertStatusUpdate,
    _user: str = Depends(get_current_user),
):
    """Update status of an alert (new, acknowledged, closed)."""
    updated = storage.update_alert_status(alert_id, body.status, db_path=DB_PATH)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "success", "alert_id": alert_id, "new_status": body.status}


# ---------------------------------------------------------
# Statistics & Rules Routes
# ---------------------------------------------------------
@app.get("/api/v1/stats")
def get_stats(_user: str = Depends(get_current_user)):
    """Aggregate statistics for SIEM dashboard overview."""
    return storage.get_dashboard_stats(db_path=DB_PATH)


@app.get("/api/v1/rules")
def get_rules(_user: str = Depends(get_current_user)):
    """List loaded detection rules and metadata."""
    rules = load_rules(RULES_DIR)
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "mitre_attack": r.mitre_attack,
                "type": r.type,
                "window_seconds": r.window_seconds,
                "threshold": r.threshold,
                "group_by": r.group_by,
            }
            for r in rules
        ]
    }


# ---------------------------------------------------------
# Frontend Dashboard Routes
# ---------------------------------------------------------
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def index_page():
    """Serve the PySIEM web dashboard."""
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return HTMLResponse("<h1>PySIEM Dashboard template not found</h1>", status_code=404)
