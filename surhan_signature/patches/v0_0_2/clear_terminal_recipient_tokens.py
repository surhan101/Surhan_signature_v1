"""Revoke bearer tokens retained by historical terminal recipients."""

import frappe
from frappe.utils import now_datetime

from surhan_signature.signing.lifecycle import TERMINAL_RECIPIENT_STATUSES


def execute():
    names = frappe.get_all(
        "E-Sign Recipient",
        filters={
            "status": ["in", sorted(TERMINAL_RECIPIENT_STATUSES)],
            "token_hash": ["!=", ""],
        },
        pluck="name",
    )
    now = now_datetime()
    for name in names:
        frappe.db.set_value(
            "E-Sign Recipient",
            name,
            {"token_hash": "", "token_expires_at": now},
            update_modified=False,
        )
