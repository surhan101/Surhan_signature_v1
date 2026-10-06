"""Concurrency controls for the critical signing transaction."""

from __future__ import annotations

import frappe
from frappe import _


def assert_signable_state(recipient: dict, envelope: dict) -> None:
    if not recipient:
        raise ValueError("Signing recipient was not found.")
    if str(recipient.get("status") or "") == "Signed" or recipient.get("signed_at"):
        raise ValueError("This recipient has already signed.")
    if not recipient.get("token_hash"):
        raise ValueError("The signing link is no longer active.")
    if not int(recipient.get("otp_verified") or 0):
        raise ValueError("A verified OTP session is required.")
    if not envelope:
        raise ValueError("Signing envelope was not found.")
    if int(envelope.get("locked") or 0) or str(envelope.get("status") or "") == "Signed":
        raise ValueError("This envelope is already completed and locked.")


def lock_lifecycle_scope(recipient_name: str, envelope_name: str) -> tuple[dict, dict]:
    """Lock an envelope and recipient in a stable order without changing state."""
    envelopes = frappe.db.sql(
        """
        SELECT name, status, locked
        FROM `tabE-Sign Envelope`
        WHERE name = %s
        FOR UPDATE
        """,
        (envelope_name,),
        as_dict=True,
    )
    recipients = frappe.db.sql(
        """
        SELECT name, parent, status, signed_at, token_hash,
               otp_verified, otp_verified_at, otp_expires_at, otp_token_hash
        FROM `tabE-Sign Recipient`
        WHERE name = %s AND parent = %s
        FOR UPDATE
        """,
        (recipient_name, envelope_name),
        as_dict=True,
    )
    envelope = envelopes[0] if envelopes else None
    recipient = recipients[0] if recipients else None
    if not envelope:
        frappe.throw(_("Signing envelope was not found."), exc=frappe.DoesNotExistError)
    if not recipient:
        frappe.throw(_("Signing recipient was not found."), exc=frappe.DoesNotExistError)
    return recipient, envelope


def lock_signing_scope(recipient_name: str, envelope_name: str) -> tuple[dict, dict]:
    """Lock in a stable order and then validate freshly-read database state."""
    recipient, envelope = lock_lifecycle_scope(recipient_name, envelope_name)
    try:
        assert_signable_state(recipient, envelope)
    except ValueError as exc:
        frappe.throw(_(str(exc)), exc=frappe.ValidationError)
    return recipient, envelope


def lock_audit_chain(envelope_name: str) -> None:
    """Serialize audit appends per envelope to prevent hash-chain forks."""
    rows = frappe.db.sql(
        "SELECT name FROM `tabE-Sign Envelope` WHERE name=%s FOR UPDATE",
        (envelope_name,),
    )
    if not rows:
        frappe.throw(_("Signing envelope was not found."), exc=frappe.DoesNotExistError)
