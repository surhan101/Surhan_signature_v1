import json
import frappe
from frappe.utils import now_datetime
from surhan_signature.signing.audit import get_request_ip, get_user_agent


def add_security_event(
    event_type: str,
    severity: str = "Low",
    envelope: str | None = None,
    recipient_row: str | None = None,
    recipient_email: str | None = None,
    token_hash_prefix: str | None = None,
    rate_key: str | None = None,
    details: dict | None = None,
):
    details = details or {}

    try:
        if not frappe.db.exists("DocType", "E-Sign Security Event"):
            return None

        doc = frappe.get_doc({
            "doctype": "E-Sign Security Event",
            "event_type": event_type,
            "severity": severity,
            "envelope": envelope,
            "recipient_row": recipient_row,
            "recipient_email": recipient_email,
            "token_hash_prefix": token_hash_prefix,
            "timestamp_utc": now_datetime(),
            "ip_address": get_request_ip(),
            "user_agent": get_user_agent(),
            "rate_key": rate_key,
            "details_json": json.dumps(details, ensure_ascii=False, sort_keys=True, default=str),
        })

        doc.insert(ignore_permissions=True)
        return doc.name

    except Exception:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Security Event Failed")
        return None
