import json
import frappe
from frappe.utils import now_datetime
from .crypto import sha256_hex
from .transaction import lock_audit_chain


def get_request_ip() -> str:
    headers = getattr(frappe.local, "request", None)
    if not headers:
        return "system"
    request = frappe.local.request
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_user_agent() -> str:
    request = getattr(frappe.local, "request", None)
    if not request:
        return "system"
    return request.headers.get("User-Agent", "unknown")


def add_audit(
    envelope: str,
    event_type: str,
    actor_type: str = "System",
    actor_user: str | None = None,
    actor_email: str | None = None,
    details: dict | None = None,
    request_id: str | None = None,
):
    """Append-only audit log with hash chain."""
    details = details or {}

    # The envelope row is the per-chain mutex. Every audit append must hold it
    # until the surrounding transaction commits or rolls back.
    lock_audit_chain(envelope)

    previous = frappe.get_all(
        "E-Sign Audit Log",
        filters={"envelope": envelope},
        fields=["current_hash"],
        order_by="creation desc",
        limit=1,
    )

    previous_hash = previous[0].current_hash if previous else ""

    timestamp = now_datetime()

    payload = {
        "envelope": envelope,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_user": actor_user,
        "actor_email": actor_email,
        "timestamp_utc": str(timestamp),
        "ip_address": get_request_ip(),
        "user_agent": get_user_agent(),
        "request_id": request_id,
        "details_json": details,
        "previous_hash": previous_hash,
    }

    current_hash = sha256_hex(payload)

    doc = frappe.get_doc({
        "doctype": "E-Sign Audit Log",
        "envelope": envelope,
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_user": actor_user,
        "actor_email": actor_email,
        "timestamp_utc": timestamp,
        "ip_address": payload["ip_address"],
        "user_agent": payload["user_agent"],
        "request_id": request_id,
        "details_json": json.dumps(details, ensure_ascii=False, sort_keys=True, default=str),
        "previous_hash": previous_hash,
        "current_hash": current_hash,
    })

    doc.insert(ignore_permissions=True)
    return doc.name


def verify_audit_chain(envelope: str) -> dict:
    logs = frappe.get_all(
        "E-Sign Audit Log",
        filters={"envelope": envelope},
        fields=[
            "name",
            "event_type",
            "actor_type",
            "actor_user",
            "actor_email",
            "timestamp_utc",
            "ip_address",
            "user_agent",
            "request_id",
            "details_json",
            "previous_hash",
            "current_hash",
        ],
        order_by="creation asc",
    )

    expected_previous = ""
    broken_at = None

    for row in logs:
        details = {}
        if row.details_json:
            try:
                details = json.loads(row.details_json)
            except Exception:
                details = {"_raw": row.details_json}

        payload = {
            "envelope": envelope,
            "event_type": row.event_type,
            "actor_type": row.actor_type,
            "actor_user": row.actor_user,
            "actor_email": row.actor_email,
            "timestamp_utc": str(row.timestamp_utc),
            "ip_address": row.ip_address,
            "user_agent": row.user_agent,
            "request_id": row.request_id,
            "details_json": details,
            "previous_hash": row.previous_hash or "",
        }

        recalculated = sha256_hex(payload)

        if (row.previous_hash or "") != expected_previous or recalculated != row.current_hash:
            broken_at = row.name
            break

        expected_previous = row.current_hash

    return {
        "valid": broken_at is None,
        "total_logs": len(logs),
        "broken_at": broken_at,
        "latest_hash": expected_previous if not broken_at else None,
    }
