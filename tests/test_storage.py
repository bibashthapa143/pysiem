import os
import tempfile
import pytest
from siem import auth, storage


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage.init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_insert_and_query_event(temp_db):
    event = {
        "timestamp": "2026-10-09T04:20:00Z",
        "host": "metasploitable",
        "program": "sshd",
        "pid": 5452,
        "username": "root",
        "src_ip": "10.0.2.4",
        "src_port": 35643,
        "method": "password",
        "activity": "authentication",
        "outcome": "failure",
        "invalid_user": False,
        "raw_message": "Failed password for root",
    }
    event_id = storage.insert_event(event, db_path=temp_db)
    assert event_id > 0

    events, total = storage.query_events(db_path=temp_db, src_ip="10.0.2.4")
    assert total == 1
    assert len(events) == 1
    assert events[0]["username"] == "root"
    assert events[0]["outcome"] == "failure"
    assert events[0]["pid"] == 5452


def test_alert_deduplication(temp_db):
    alert_1 = {
        "rule_id": "rule_ssh_brute",
        "rule_name": "SSH Brute Force",
        "severity": "high",
        "title": "SSH Brute Force from 10.0.2.4",
        "description": "5 failures",
        "mitre_tag": "T1110.001",
        "fingerprint": "rule_ssh_brute_10.0.2.4",
        "status": "new",
        "event_count": 5,
        "first_seen": "2026-10-09T04:00:00Z",
        "last_seen": "2026-10-09T04:05:00Z",
        "details": {"src_ip": "10.0.2.4"},
    }
    rec1, is_new1 = storage.insert_or_update_alert(alert_1, db_path=temp_db)
    assert is_new1 is True
    assert rec1["event_count"] == 5

    # Second trigger with same fingerprint should aggregate, not duplicate
    alert_2 = {
        "rule_id": "rule_ssh_brute",
        "rule_name": "SSH Brute Force",
        "severity": "high",
        "title": "SSH Brute Force from 10.0.2.4",
        "description": "3 more failures",
        "mitre_tag": "T1110.001",
        "fingerprint": "rule_ssh_brute_10.0.2.4",
        "event_count": 3,
        "last_seen": "2026-10-09T04:08:00Z",
    }
    rec2, is_new2 = storage.insert_or_update_alert(alert_2, db_path=temp_db)
    assert is_new2 is False
    assert rec2["event_count"] == 8

    alerts, total = storage.query_alerts(db_path=temp_db)
    assert total == 1
    assert alerts[0]["event_count"] == 8

    # Update status
    updated = storage.update_alert_status(rec1["id"], "acknowledged", db_path=temp_db)
    assert updated is True
    fetched = storage.get_alert_by_id(rec1["id"], db_path=temp_db)
    assert fetched["status"] == "acknowledged"


def test_auth_hashing_and_tokens(temp_db):
    auth.init_default_admin(db_path=temp_db)
    user = storage.get_user("admin", db_path=temp_db)
    assert user is not None
    assert auth.verify_password("adminpassword123", user["password_hash"], user["salt"])
    assert not auth.verify_password("wrongpassword", user["password_hash"], user["salt"])

    # Test token signing and validation
    token = auth.create_token("admin", expires_in_seconds=60)
    assert auth.verify_token(token) == "admin"
    assert auth.verify_token(token + "tampered") is None
