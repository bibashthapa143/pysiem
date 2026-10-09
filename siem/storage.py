"""SQLite database storage layer for PySIEM.

All queries are strictly parameterized using SQLite '?' placeholders.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL,
    host TEXT,
    program TEXT,
    pid INTEGER,
    username TEXT,
    src_ip TEXT,
    src_port INTEGER,
    method TEXT,
    activity TEXT NOT NULL,
    outcome TEXT NOT NULL,
    invalid_user INTEGER NOT NULL DEFAULT 0,
    raw_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip_ts ON events(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(username, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_outcome ON events(outcome);
CREATE INDEX IF NOT EXISTS idx_events_activity ON events(activity);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    mitre_tag TEXT,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    event_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint_status ON alerts(fingerprint, status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
"""


from contextlib import contextmanager


@contextmanager
def get_connection(db_path: str = "pysiem.db"):
    """Yield a configured SQLite connection and ensure it is properly closed."""
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: str = "pysiem.db") -> None:
    """Initialize SQLite database tables and indexes."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)


def insert_event(event: Dict[str, Any], db_path: str = "pysiem.db") -> int:
    """Insert a single normalized event using parameterized SQL."""
    sql = """
        INSERT INTO events (
            timestamp, received_at, host, program, pid,
            username, src_ip, src_port, method, activity,
            outcome, invalid_user, raw_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    received_at = event.get("received_at") or datetime.now(timezone.utc).isoformat()
    params = (
        event["timestamp"],
        received_at,
        event.get("host"),
        event.get("program"),
        event.get("pid"),
        event.get("username"),
        event.get("src_ip"),
        event.get("src_port"),
        event.get("method"),
        event.get("activity", "authentication"),
        event["outcome"],
        1 if event.get("invalid_user") else 0,
        event.get("raw_message", ""),
    )
    with get_connection(db_path) as conn:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.lastrowid  # type: ignore


def insert_events(events: List[Dict[str, Any]], db_path: str = "pysiem.db") -> List[int]:
    """Insert multiple events within a single transaction using parameterized SQL."""
    if not events:
        return []

    sql = """
        INSERT INTO events (
            timestamp, received_at, host, program, pid,
            username, src_ip, src_port, method, activity,
            outcome, invalid_user, raw_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    inserted_ids = []

    with get_connection(db_path) as conn:
        for event in events:
            received_at = event.get("received_at") or now_iso
            params = (
                event["timestamp"],
                received_at,
                event.get("host"),
                event.get("program"),
                event.get("pid"),
                event.get("username"),
                event.get("src_ip"),
                event.get("src_port"),
                event.get("method"),
                event.get("activity", "authentication"),
                event["outcome"],
                1 if event.get("invalid_user") else 0,
                event.get("raw_message", ""),
            )
            cursor = conn.execute(sql, params)
            inserted_ids.append(cursor.lastrowid)
        conn.commit()
    return inserted_ids


def query_events(
    db_path: str = "pysiem.db",
    src_ip: Optional[str] = None,
    username: Optional[str] = None,
    outcome: Optional[str] = None,
    activity: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    search_query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Query events with parameterized filtering and pagination."""
    conditions = []
    params: List[Any] = []

    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)
    if username:
        conditions.append("username = ?")
        params.append(username)
    if outcome:
        conditions.append("outcome = ?")
        params.append(outcome)
    if activity:
        conditions.append("activity = ?")
        params.append(activity)
    if start_time:
        conditions.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        conditions.append("timestamp <= ?")
        params.append(end_time)
    if search_query:
        # Parameterized search across text fields
        search_like = f"%{search_query}%"
        conditions.append("(raw_message LIKE ? OR username LIKE ? OR src_ip LIKE ? OR host LIKE ?)")
        params.extend([search_like, search_like, search_like, search_like])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    count_sql = f"SELECT COUNT(*) FROM events {where_clause}"
    select_sql = f"""
        SELECT * FROM events {where_clause}
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
    """

    with get_connection(db_path) as conn:
        count_cursor = conn.execute(count_sql, tuple(params))
        total = count_cursor.fetchone()[0]

        select_params = list(params) + [limit, offset]
        rows = conn.execute(select_sql, tuple(select_params)).fetchall()
        events = [dict(row) for row in rows]
        for e in events:
            e["invalid_user"] = bool(e.get("invalid_user"))
        return events, total


def query_events_window(
    db_path: str,
    start_time: str,
    end_time: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch events between start_time and optional end_time for detection analysis."""
    if end_time:
        sql = "SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC, id ASC"
        params = (start_time, end_time)
    else:
        sql = "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC, id ASC"
        params = (start_time,)

    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        events = [dict(r) for r in rows]
        for e in events:
            e["invalid_user"] = bool(e.get("invalid_user"))
        return events


def insert_or_update_alert(
    alert: Dict[str, Any],
    dedup_window_seconds: int = 3600,
    db_path: str = "pysiem.db",
) -> Tuple[Dict[str, Any], bool]:
    """
    Insert a new alert or aggregate into an existing open/acknowledged alert
    with matching fingerprint within the deduplication time window.
    Returns (alert_record, is_new).
    """
    fingerprint = alert["fingerprint"]
    details_str = json.dumps(alert.get("details", {}))
    last_seen = alert.get("last_seen", alert.get("first_seen", datetime.now(timezone.utc).isoformat()))
    first_seen = alert.get("first_seen", last_seen)

    with get_connection(db_path) as conn:
        # Check for existing alert with same fingerprint that is not closed
        sql_check = """
            SELECT * FROM alerts
            WHERE fingerprint = ? AND status != 'closed'
            ORDER BY id DESC LIMIT 1
        """
        existing = conn.execute(sql_check, (fingerprint,)).fetchone()

        if existing:
            existing_dict = dict(existing)
            # Update event_count and last_seen
            new_count = existing_dict["event_count"] + alert.get("event_count", 1)
            sql_update = """
                UPDATE alerts
                SET event_count = ?, last_seen = ?, details = ?
                WHERE id = ?
            """
            conn.execute(sql_update, (new_count, last_seen, details_str, existing_dict["id"]))
            conn.commit()
            existing_dict["event_count"] = new_count
            existing_dict["last_seen"] = last_seen
            existing_dict["details"] = json.loads(details_str)
            return existing_dict, False
        else:
            created_at = alert.get("created_at") or datetime.now(timezone.utc).isoformat()
            sql_insert = """
                INSERT INTO alerts (
                    rule_id, rule_name, severity, title, description,
                    mitre_tag, fingerprint, status, event_count,
                    first_seen, last_seen, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                alert["rule_id"],
                alert["rule_name"],
                alert["severity"],
                alert["title"],
                alert.get("description", ""),
                alert.get("mitre_tag", ""),
                fingerprint,
                alert.get("status", "new"),
                alert.get("event_count", 1),
                first_seen,
                last_seen,
                details_str,
                created_at,
            )
            cursor = conn.execute(sql_insert, params)
            conn.commit()
            alert_copy = dict(alert)
            alert_copy["id"] = cursor.lastrowid
            return alert_copy, True


def query_alerts(
    db_path: str = "pysiem.db",
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Query alerts with parameterized filtering and pagination."""
    conditions = []
    params: List[Any] = []

    if status:
        conditions.append("status = ?")
        params.append(status)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    count_sql = f"SELECT COUNT(*) FROM alerts {where_clause}"
    select_sql = f"""
        SELECT * FROM alerts {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """

    with get_connection(db_path) as conn:
        total = conn.execute(count_sql, tuple(params)).fetchone()[0]
        rows = conn.execute(select_sql, tuple(params + [limit, offset])).fetchall()
        alerts = []
        for r in rows:
            d = dict(r)
            if d.get("details"):
                try:
                    d["details"] = json.loads(d["details"])
                except Exception:
                    pass
            alerts.append(d)
        return alerts, total


def get_alert_by_id(alert_id: int, db_path: str = "pysiem.db") -> Optional[Dict[str, Any]]:
    """Retrieve an alert by ID."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        return d


def update_alert_status(alert_id: int, status: str, db_path: str = "pysiem.db") -> bool:
    """Update status of an alert (new, acknowledged, closed)."""
    if status not in {"new", "acknowledged", "closed"}:
        raise ValueError("Invalid alert status")

    with get_connection(db_path) as conn:
        cursor = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        conn.commit()
        return cursor.rowcount > 0


def get_dashboard_stats(db_path: str = "pysiem.db") -> Dict[str, Any]:
    """Aggregate statistics for SIEM dashboard overview."""
    with get_connection(db_path) as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status != 'closed'").fetchone()[0]

        # Severity breakdown
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity
        """).fetchall()
        severity_counts = {r["severity"]: r["cnt"] for r in sev_rows}

        # Outcome breakdown
        outcome_rows = conn.execute("""
            SELECT outcome, COUNT(*) as cnt FROM events GROUP BY outcome
        """).fetchall()
        outcome_counts = {r["outcome"]: r["cnt"] for r in outcome_rows}

        # Top 5 source IPs
        ip_rows = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt FROM events
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
        """).fetchall()
        top_ips = [{"ip": r["src_ip"], "count": r["cnt"]} for r in ip_rows]

        # Top targeted usernames
        user_rows = conn.execute("""
            SELECT username, COUNT(*) as cnt FROM events
            WHERE username IS NOT NULL AND username != ''
            GROUP BY username ORDER BY cnt DESC LIMIT 5
        """).fetchall()
        top_users = [{"username": r["username"], "count": r["cnt"]} for r in user_rows]

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "severity_counts": severity_counts,
            "outcome_counts": outcome_counts,
            "top_ips": top_ips,
            "top_users": top_users,
        }


def create_user(
    username: str,
    password_hash: str,
    salt: str,
    db_path: str = "pysiem.db",
) -> int:
    """Store user credentials securely."""
    now_iso = datetime.now(timezone.utc).isoformat()
    sql = "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)"
    with get_connection(db_path) as conn:
        cursor = conn.execute(sql, (username, password_hash, salt, now_iso))
        conn.commit()
        return cursor.lastrowid  # type: ignore


def get_user(username: str, db_path: str = "pysiem.db") -> Optional[Dict[str, Any]]:
    """Retrieve user record by username."""
    sql = "SELECT * FROM users WHERE username = ?"
    with get_connection(db_path) as conn:
        row = conn.execute(sql, (username,)).fetchone()
        return dict(row) if row else None
