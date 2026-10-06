import base64
import hashlib
import hmac
import json
import secrets
from typing import Any


def secure_token_urlsafe(length: int = 48) -> str:
    """Generate a high-entropy URL-safe token."""
    return secrets.token_urlsafe(length)


def sha256_hex(value: Any) -> str:
    """Return SHA-256 hex digest for string/bytes/json-serializable value."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def token_hash(token: str) -> str:
    """Hash token before storing it in DB."""
    return sha256_hex(token)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")


def hmac_sha256_hex(secret: str, payload: Any) -> str:
    if not isinstance(payload, bytes):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        else:
            payload = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def b64encode_bytes(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
