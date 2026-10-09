import os
import tempfile
import pytest
from siem import storage
from siem.engine import DetectionEngine
from siem.rules import load_rules


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage.init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_load_yaml_rules():
    rules = load_rules("siem/rules")
    rule_ids = {r.id for r in rules}
    assert "ssh_brute_force" in rule_ids
    assert "ssh_password_spraying" in rule_ids
    assert "ssh_invalid_user_guessing" in rule_ids
    assert "ssh_failure_then_success" in rule_ids


def test_ssh_brute_force_detection():
    rules = load_rules("siem/rules")
    engine = DetectionEngine(rules=[r for r in rules if r.id == "ssh_brute_force"])

    events = [
        {
            "timestamp": f"2026-10-09T04:0{i}:00Z",
            "host": "srv1",
            "program": "sshd",
            "username": "root",
            "src_ip": "192.168.1.100",
            "src_port": 40000 + i,
            "activity": "authentication",
            "outcome": "failure",
            "invalid_user": False,
        }
        for i in range(5)
    ]

    alerts = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ssh_brute_force"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["mitre_tag"] == "T1110.001"
    assert alerts[0]["event_count"] == 5


def test_password_spraying_detection():
    rules = load_rules("siem/rules")
    engine = DetectionEngine(rules=[r for r in rules if r.id == "ssh_password_spraying"])

    # 3 distinct usernames from same IP
    targets = ["alice", "bob", "charlie"]
    events = [
        {
            "timestamp": f"2026-10-09T04:0{i}:00Z",
            "host": "srv1",
            "program": "sshd",
            "username": u,
            "src_ip": "192.168.1.200",
            "src_port": 50000 + i,
            "activity": "authentication",
            "outcome": "failure",
            "invalid_user": False,
        }
        for i, u in enumerate(targets)
    ]

    alerts = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ssh_password_spraying"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["mitre_tag"] == "T1110.003"
    assert set(alerts[0]["details"]["distinct_values"]) == {"alice", "bob", "charlie"}


def test_invalid_user_guessing_detection():
    rules = load_rules("siem/rules")
    engine = DetectionEngine(rules=[r for r in rules if r.id == "ssh_invalid_user_guessing"])

    events = [
        {
            "timestamp": f"2026-10-09T04:0{i}:00Z",
            "host": "srv1",
            "program": "sshd",
            "username": f"fake_{i}",
            "src_ip": "192.168.1.250",
            "src_port": 30000 + i,
            "activity": "authentication",
            "outcome": "failure",
            "invalid_user": True,
        }
        for i in range(3)
    ]

    alerts = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ssh_invalid_user_guessing"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["mitre_tag"] == "T1087.001"


def test_failure_then_success_detection():
    rules = load_rules("siem/rules")
    engine = DetectionEngine(rules=[r for r in rules if r.id == "ssh_failure_then_success"])

    events = [
        # 3 failures for root from 10.0.0.50
        {
            "timestamp": f"2026-10-09T05:0{i}:00Z",
            "host": "srv1",
            "program": "sshd",
            "username": "root",
            "src_ip": "10.0.0.50",
            "src_port": 41000 + i,
            "activity": "authentication",
            "outcome": "failure",
            "invalid_user": False,
        }
        for i in range(3)
    ]
    # Followed by 1 success for root from 10.0.0.50
    events.append({
        "timestamp": "2026-10-09T05:04:00Z",
        "host": "srv1",
        "program": "sshd",
        "username": "root",
        "src_ip": "10.0.0.50",
        "src_port": 41004,
        "activity": "authentication",
        "outcome": "success",
        "invalid_user": False,
    })

    alerts = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ssh_failure_then_success"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["mitre_tag"] == "T1110"


def test_process_and_store_end_to_end(temp_db):
    engine = DetectionEngine(rules_dir="siem/rules")
    events = [
        {
            "timestamp": f"2026-10-09T06:0{i}:00Z",
            "host": "metasploitable",
            "program": "sshd",
            "username": "admin",
            "src_ip": "172.16.1.5",
            "src_port": 45000 + i,
            "activity": "authentication",
            "outcome": "failure",
            "invalid_user": False,
            "raw_message": f"Failed password for admin attempt {i}",
        }
        for i in range(6)
    ]

    event_ids, alerts = engine.process_and_store(events, db_path=temp_db)
    assert len(event_ids) == 6
    assert len(alerts) >= 1

    stored_alerts, total_alerts = storage.query_alerts(db_path=temp_db)
    assert total_alerts >= 1
    assert stored_alerts[0]["severity"] == "high"
