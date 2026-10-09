"""Authentication, password hashing, and session management for PySIEM.

Implements PBKDF2-HMAC-SHA256 with random salts and constant-time comparisons
to prevent timing attacks and rainbow table lookups.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional, Tuple

from siem.config import ADMIN_PASSWORD, ADMIN_USER, DB_PATH, SECRET_KEY
from siem import storage

ITERATIONS = 100_000


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    Returns (hex_digest, salt).
    """
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        ITERATIONS,
    )
    return key.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored hash using constant-time comparison."""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


def create_token(username: str, expires_in_seconds: int = 86400) -> str:
    """
    Create a signed session token.
    Token structure: base64(payload).signature
    """
    payload = {
        "sub": username,
        "exp": int(time.time()) + expires_in_seconds,
        "nonce": secrets.token_hex(8),
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("utf-8")
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def verify_token(token: str) -> Optional[str]:
    """
    Verify a signed token and return the username if valid and not expired.
    """
    if not token or "." not in token:
        return None
    try:
        payload_b64, signature = token.split(".", 1)
        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None

        # Decode payload safely
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload.get("sub")
    except Exception:
        return None


def init_default_admin(db_path: str = DB_PATH) -> None:
    """Ensure the initial administrator account exists."""
    storage.init_db(db_path)
    existing = storage.get_user(ADMIN_USER, db_path=db_path)
    if not existing:
        p_hash, salt = hash_password(ADMIN_PASSWORD)
        storage.create_user(ADMIN_USER, p_hash, salt, db_path=db_path)
