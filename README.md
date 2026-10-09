# PySIEM (Security Information & Event Management System)

![Status](https://img.shields.io/badge/Status-Complete-emerald)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.143%2B-009688)
![Tests](https://img.shields.io/badge/Tests-26%20Passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

PySIEM is a lightweight, open-source Security Information and Event Management (SIEM) system built in Python. It provides high-performance log parsing, event normalization, parameterized SQLite storage, YAML-driven correlation and detection engines (mapped to MITRE ATT&CK), real-time alert deduplication, and a responsive web dashboard with defense metrics.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Sources (auth.log, etc.)   |
                      +--------------+--------------+
                                     |
              +----------------------+----------------------+
              |                                             |
    [Local Log Ingestor]                          [HTTP Ingest Endpoint]
    (siem/cli.py ingest)                          (POST /api/v1/ingest)
              |                                             |
              +----------------------+----------------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Parser & Normalization    |
                      |       (siem/parser.py)      |
                      |  - UTC ISO 8601 Timestamps  |
                      |  - Common SIEM Event Schema |
                      +--------------+--------------+
                                     |
                                     v
              +----------------------+----------------------+
              |                                             |
              v                                             v
+---------------------------+                 +---------------------------+
|    SQLite Event Store     |                 |     Detection Engine      |
|    (siem/storage.py)      |                 |     (siem/engine.py)      |
|  - Parameterized queries  |                 |  - YAML Correlation Rules |
|  - Compound B-tree indexes|                 |  - MITRE ATT&CK Mappings  |
+---------------------------+                 +-------------+-------------+
                                                            |
                                                            v
                                              +---------------------------+
                                              |    Alerting & Dedup       |
                                              |  - Fingerprint hashing    |
                                              |  - Status lifecycle       |
                                              +-------------+-------------+
                                                            |
                                                            v
                                              +---------------------------+
                                              |   FastAPI & SOC Web UI    |
                                              |     (http://127.0.0.1)    |
                                              |  - XSS-safe Event Search  |
                                              |  - Triage & Incident Mgmt |
                                              +---------------------------+
```

### Common Event Schema
Every ingested log entry is normalized into a standard SIEM schema:
- `timestamp`: UTC ISO 8601 string (e.g. `2026-10-09T04:27:18Z`)
- `received_at`: Ingestion timestamp (UTC ISO 8601)
- `host`: Hostname reported in syslog header
- `program`: Service daemon (e.g. `sshd`)
- `pid`: Process identifier (integer)
- `username`: Target account name (untrusted attacker input)
- `src_ip`: Attacker / client IP address
- `src_port`: Client ephemeral port (integer)
- `method`: Authentication method (`password` or `publickey`)
- `activity`: Category of activity (`authentication`)
- `outcome`: Result (`success` or `failure`)
- `invalid_user`: Boolean flag indicating if username does not exist on host
- `raw_message`: Full verbatim syslog string

---

## Security Architecture

1. **Untrusted Input Handling**: Attacker-controlled usernames, IP headers, and log messages are treated as completely untrusted. Regex patterns are anchored with `^` and tokenized to avoid ReDoS (Regex Denial of Service).
2. **Parameterized SQL Everywhere**: Every database query uses SQLite `?` placeholders with bound tuples. No dynamic SQL concatenation is used.
3. **Strict XSS Defense**: All user-controlled fields displayed in the web dashboard are sanitized via HTML entity encoding (`escapeHtml`) before being rendered into the DOM.
4. **Strong Password Hashing**: Analysts' passwords use **PBKDF2-HMAC-SHA256** with 100,000 iterations and cryptographically random 16-byte salts (`secrets.token_hex(16)`). Verification uses constant-time string comparison (`hmac.compare_digest`).
5. **HMAC Session Tokens & API Keys**: Dashboard sessions use signed HMAC-SHA256 bearer tokens. HTTP ingestion requires an ingestion API key (`X-API-Key`).
6. **Zero Secrets in Repo**: Configuration is loaded from `.env` using `python-dotenv`.

---

## Detection Rules & MITRE ATT&CK Mapping

Rules are defined in declarative YAML files located in [`siem/rules/`](file:///d:/pysiem/siem/rules):

| Rule ID | Rule Name | Type | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ssh_brute_force` | SSH Brute Force Detection | Threshold | **T1110.001** | Triggers when $\ge 5$ failed logins occur from the same `src_ip` within 300s. |
| `ssh_password_spraying` | SSH Password Spraying | Distinct Threshold | **T1110.003** | Triggers when $\ge 3$ distinct usernames fail from the same `src_ip` within 600s. |
| `ssh_invalid_user_guessing` | Invalid User Account Guessing | Threshold | **T1087.001** | Triggers when $\ge 3$ non-existent user attempts are made from the same `src_ip` within 300s. |
| `ssh_failure_then_success` | Failure Followed by Success | Sequence | **T1110** | Triggers when $\ge 3$ failures are immediately followed by a successful login for the same account/IP within 600s. |

---

## Installation & Setup

### 1. Clone & Set Up Virtual Environment

```bash
# Activate existing venv or create a new one
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```bash
pip install fastapi "uvicorn[standard]" pyyaml python-dotenv httpx pytest
```

### 3. Environment Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Default credentials in `.env`:
- **Admin Username**: `admin`
- **Admin Password**: `adminpassword123`
- **Ingestion API Key**: `pysiem-ingest-secret-key-12345`
- **Database File**: `pysiem.db`

---

## Usage

### 1. Start the PySIEM Web Dashboard

```bash
python -m siem.cli serve --host 127.0.0.1 --port 8000
```
Open your browser to: **`http://127.0.0.1:8000`**

Sign in with:
- **Username**: `admin`
- **Password**: `adminpassword123`

### 2. Ingest Logs via CLI

Ingest any local `auth.log` file:
```bash
python -m siem.cli ingest sample_logs/auth_sample.log
```

### 3. Validate Detection Rules

Inspect active YAML rules and parameters:
```bash
python -m siem.cli check-rules
```

### 4. Ingest Logs via HTTP API

Send logs programmatically from syslog forwarders (rsyslog, Fluent Bit, Vector):

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: pysiem-ingest-secret-key-12345" \
  -d '{
    "lines": [
      "Oct  5 03:29:46 metasploitable sshd[5331]: Accepted password for msfadmin from 192.168.18.176 port 60056 ssh2",
      "Oct  5 03:37:50 metasploitable sshd[5345]: Failed password for invalid user fakeuser from 192.168.18.176 port 54524 ssh2"
    ]
  }'
```

---

## Kali / Metasploitable Lab Testing Guide

This walkthrough demonstrates how to simulate an SSH brute-force attack from a Kali Linux machine against a Metasploitable2 VM and detect it in PySIEM.

### Lab Topology
- **Attacker**: Kali Linux (`192.168.18.205`)
- **Target**: Metasploitable 2 (`192.168.18.176`) running OpenSSH
- **SIEM Server**: PySIEM host (`192.168.18.1` / `127.0.0.1`)

---

### Step 1: Execute SSH Brute Force with Hydra on Kali

On your Kali Linux machine, launch Hydra against the target SSH port using a common wordlist:

```bash
# Brute force a single target account (root)
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 4 ssh://192.168.18.176

# Or password spray multiple usernames:
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -p Password123 -t 4 ssh://192.168.18.176
```

---

### Step 2: Retrieve the Authentication Logs from the Target

SSH into the Metasploitable VM or pull `/var/log/auth.log`:

```bash
# On Metasploitable / Ubuntu target:
sudo tail -n 50 /var/log/auth.log > hydra_attack.log
```

Lines generated by the attack will look like:
```syslog
Oct 09 10:15:01 metasploitable sshd[7101]: Failed password for root from 192.168.18.205 port 42100 ssh2
Oct 09 10:15:02 metasploitable sshd[7102]: Failed password for root from 192.168.18.205 port 42102 ssh2
Oct 09 10:15:03 metasploitable sshd[7103]: Failed password for root from 192.168.18.205 port 42104 ssh2
Oct 09 10:15:04 metasploitable sshd[7104]: Failed password for root from 192.168.18.205 port 42106 ssh2
Oct 09 10:15:05 metasploitable sshd[7105]: Failed password for root from 192.168.18.205 port 42108 ssh2
Oct 09 10:15:06 metasploitable sshd[7106]: Accepted password for root from 192.168.18.205 port 42110 ssh2
```

---

### Step 3: Ingest into PySIEM

**Option A — Via CLI**:
```bash
python -m siem.cli ingest hydra_attack.log
```

**Option B — Via Web Dashboard Ingestion Lab**:
1. Open the dashboard at `http://127.0.0.1:8000`.
2. Navigate to **Ingestion & Lab**.
3. Paste the raw log lines or click **"Load Hydra SSH Attack Sample"**.
4. Click **"Ingest & Run Detection Engine"**.

---

### Step 4: Analyst Triage on the Dashboard

1. Navigate to the **Dashboard**:
   - The **Ingested Events** counter increments.
   - The **Critical & High Incidents** counter triggers.
   - **Security Alerts by Severity** reflects new high/critical events.
   - Attacker IP `192.168.18.205` appears under **Top Source IP Addresses**.
2. Navigate to the **Alerts** view:
   - Alert **"SSH Brute Force Detection"** (`T1110.001`) is displayed with severity **HIGH**.
   - If the password was cracked, **"SSH Failures Followed by Successful Login"** (`T1110`) appears with severity **CRITICAL**.
3. Change alert status from `new` $\rightarrow$ `acknowledged` $\rightarrow$ `closed` using the inline status selector.

---

## Automated Test Suite

Run all unit and integration tests with pytest:

```bash
python -m pytest -v
```

Current test suite coverage (26 tests):
- [`tests/test_parser.py`](file:///d:/pysiem/tests/test_parser.py): Original parser tests, publickey support, ISO 8601 normalization, and file processing.
- [`tests/test_storage.py`](file:///d:/pysiem/tests/test_storage.py): Parameterized SQLite schema, index validation, deduplication windowing, and PBKDF2 hashing.
- [`tests/test_engine.py`](file:///d:/pysiem/tests/test_engine.py): YAML rule loading, brute force thresholding, password spraying, invalid user guessing, and failure-then-success correlation.
- [`tests/test_api.py`](file:///d:/pysiem/tests/test_api.py): FastAPI endpoints, API key authentication, bearer token verification, alert lifecycles, and XSS payload resistance.
