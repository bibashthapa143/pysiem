"""Data models and schemas for PySIEM."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class Event(BaseModel):
    """Normalized security event schema."""
    id: Optional[int] = None
    timestamp: str = Field(..., description="UTC ISO 8601 timestamp string")
    received_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host: str = Field(default="unknown")
    program: str = Field(default="unknown")
    pid: Optional[int] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    method: Optional[str] = None
    activity: str = Field(default="authentication")
    outcome: str = Field(..., description="'success', 'failure', or 'unknown'")
    invalid_user: bool = False
    raw_message: str = Field(default="")

    @field_validator("outcome")
    @classmethod
    def validate_outcome(cls, v: str) -> str:
        v_lower = v.lower()
        if v_lower not in {"success", "failure", "unknown"}:
            raise ValueError("outcome must be 'success', 'failure', or 'unknown'")
        return v_lower


class Alert(BaseModel):
    """Detection alert representation."""
    id: Optional[int] = None
    rule_id: str
    rule_name: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    description: str = ""
    mitre_tag: Optional[str] = None
    fingerprint: str
    status: Literal["new", "acknowledged", "closed"] = "new"
    event_count: int = 1
    first_seen: str
    last_seen: str
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AlertStatusUpdate(BaseModel):
    status: Literal["new", "acknowledged", "closed"]


class IngestLogsRequest(BaseModel):
    """HTTP log ingestion payload."""
    lines: Optional[List[str]] = None
    events: Optional[List[Dict[str, Any]]] = None


class UserCredentials(BaseModel):
    username: str
    password: str


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
