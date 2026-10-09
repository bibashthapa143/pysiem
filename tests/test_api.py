import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from siem import auth, config, storage
from siem.api import app


@pytest.fixture
def test_client_and_db(monkeypatch):
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    monkeypatch.setattr(config, "DB_PATH", db_path)
    monkeypatch.setattr("siem.api.DB_PATH", db_path)
    monkeypatch.setattr("siem.auth.DB_PATH", db_path)

    storage.init_db(db_path)
    auth.init_default_admin(db_path)

    client = TestClient(app)
    yield client, db_path

    if os.path.exists(db_path):
        os.remove(db_path)


def test_login_success_and_failure(test_client_and_db):
    client, _ = test_client_and_db

    # Valid credentials
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword123"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["username"] == "admin"

    # Invalid credentials
    res_bad = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert res_bad.status_code == 401


def test_ingest_with_and_without_api_key(test_client_and_db):
    client, _ = test_client_and_db

    lines = [
        "Oct  5 03:29:46 metasploitable sshd[5331]: Accepted password for msfadmin from 192.168.18.176 port 60056 ssh2",
        "Oct  5 03:37:50 metasploitable sshd[5345]: Failed password for invalid user fakeuser from 192.168.18.176 port 54524 ssh2",
    ]

    # Without API key -> 401
    res_no_auth = client.post("/api/v1/ingest", json={"lines": lines})
    assert res_no_auth.status_code == 401

    # With invalid key -> 401
    res_bad_key = client.post(
        "/api/v1/ingest",
        json={"lines": lines},
        headers={"X-API-Key": "wrong-key"},
    )
    assert res_bad_key.status_code == 401

    # With valid API key -> 200
    res_ok = client.post(
        "/api/v1/ingest",
        json={"lines": lines},
        headers={"X-API-Key": config.INGEST_API_KEY},
    )
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "success"
    assert data["events_stored"] == 2


def test_event_search_and_xss_safety(test_client_and_db):
    client, db_path = test_client_and_db

    # Login to get bearer token
    login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Ingest log line containing potential XSS and SQL injection payloads in username
    malicious_line = (
        "Sep 28 04:27:18 metasploitable sshd[5452]: "
        "Failed password for <script>alert(1)</script>'OR'1'='1 from 10.0.2.4 port 35643 ssh2"
    )
    client.post(
        "/api/v1/ingest",
        json={"lines": [malicious_line]},
        headers={"X-API-Key": config.INGEST_API_KEY},
    )

    # Search for events
    res = client.get("/api/v1/events", headers=headers)
    assert res.status_code == 200
    events_data = res.json()
    assert events_data["total"] == 1
    stored_event = events_data["events"][0]
    # Parameterized SQL safely kept the exact text without executing injection
    assert "<script>alert(1)</script>'OR'1'='1" in stored_event["username"]


def test_alert_lifecycle_and_status_update(test_client_and_db):
    client, _ = test_client_and_db

    # Login
    login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Trigger brute force by ingesting 6 failures from same IP
    brute_lines = [
        f"Oct 09 04:0{i}:00 metasploitable sshd[500{i}]: Failed password for root from 192.168.1.99 port 4000{i} ssh2"
        for i in range(6)
    ]
    ingest_res = client.post(
        "/api/v1/ingest",
        json={"lines": brute_lines},
        headers={"X-API-Key": config.INGEST_API_KEY},
    )
    assert ingest_res.status_code == 200

    # Query alerts
    alerts_res = client.get("/api/v1/alerts", headers=headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()["alerts"]
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]
    assert alerts[0]["status"] == "new"

    # Update status to acknowledged
    patch_res = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "acknowledged"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "acknowledged"

    # Query alert by ID
    get_single = client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert get_single.status_code == 200
    assert get_single.json()["status"] == "acknowledged"


def test_stats_and_rules_endpoints(test_client_and_db):
    client, _ = test_client_and_db

    login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    stats_res = client.get("/api/v1/stats", headers=headers)
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_events" in stats
    assert "total_alerts" in stats

    rules_res = client.get("/api/v1/rules", headers=headers)
    assert rules_res.status_code == 200
    rules = rules_res.json()["rules"]
    assert len(rules) >= 4
