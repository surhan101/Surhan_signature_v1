"""Hardened OTP and signing endpoints.

This module is wired through Frappe's override_whitelisted_methods hook so the
public API remains backward compatible while the legacy monolith is refactored.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.utils import now_datetime

from surhan_signature import api as legacy
from surhan_signature.signing.otp import (
    invalidate_recipient_otp,
    recipient_has_valid_otp_session,
    set_otp_for_recipient,
    verify_recipient_otp,
)
from surhan_signature.signing.transaction import lock_signing_scope


def _developer_otp_is_allowed() -> bool:
    return bool(frappe.conf.get("developer_mode")) and bool(
        legacy._phase15_bool_setting("expose_dev_otp", 0)
    )


def phase1_health():
    hooks = frappe.get_hooks("override_whitelisted_methods") or {}

    def targets(method):
        value = hooks.get(method, [])
        return [value] if isinstance(value, str) else list(value or [])

    expected = {
        "surhan_signature.api.request_otp": "surhan_signature.secure_otp_api.request_otp",
        "surhan_signature.api.verify_otp": "surhan_signature.secure_otp_api.verify_otp",
        "surhan_signature.api.sign_typed": "surhan_signature.secure_otp_api.sign_typed",
        "surhan_signature.api.sign_drawn": "surhan_signature.secure_otp_api.sign_drawn",
        "surhan_signature.api.sign_uploaded": "surhan_signature.secure_otp_api.sign_uploaded",
    }
    override_status = {
        method: target in targets(method) for method, target in expected.items()
    }

    return {
        "ok": bool(
            frappe.conf.get("encryption_key")
            and frappe.db.has_column("E-Sign Recipient", "otp_token_hash")
            and all(override_status.values())
        ),
        "encryption_key_configured": bool(frappe.conf.get("encryption_key")),
        "otp_token_hash_column": frappe.db.has_column(
            "E-Sign Recipient", "otp_token_hash"
        ),
        "overrides": override_status,
        "legacy_verified_sessions": frappe.db.count(
            "E-Sign Recipient", {"otp_verified": 1}
        ),
    }


def assert_phase1_health():
    result = phase1_health()
    if not result["ok"]:
        raise RuntimeError(f"OTP hardening health check failed: {result}")
    return result


def _recipient_for_active_token(token: str):
    row = legacy._get_recipient_by_token(token)
    legacy._ensure_token_active(row)
    return row


def _require_valid_otp_session(token: str):
    row = _recipient_for_active_token(token)
    if not recipient_has_valid_otp_session(row.name, lock=True):
        legacy.add_security_event(
            event_type="signing.blocked_invalid_otp_session",
            severity="High",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=legacy._phase10_token_prefix(token),
        )
        frappe.throw(_("A current OTP verification is required before signing."))
    return row


@frappe.whitelist(allow_guest=True)
def request_otp(token: str):
    legacy._phase10_rate(
        scope="request_otp_v2",
        token=token,
        limit=3,
        window_seconds=600,
        severity="High",
    )

    row = legacy._get_recipient_by_token(token)
    if not row:
        legacy.add_security_event(
            event_type="otp.invalid_token",
            severity="Medium",
            token_hash_prefix=legacy._phase10_token_prefix(token),
            details={"operation": "request_otp_v2"},
        )
        frappe.throw(_("Invalid signing link"))

    legacy._ensure_token_active(row)
    env = frappe.get_doc("E-Sign Envelope", row.parent)
    can_sign, reason = legacy._recipient_can_sign(env, row.name)
    if not can_sign:
        legacy.add_security_event(
            event_type="otp.request_blocked_not_current_signer",
            severity="Medium",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=legacy._phase10_token_prefix(token),
            details={"reason": reason},
        )
        frappe.throw(_(reason))

    settings = legacy._settings()
    expiry_minutes = int(getattr(settings, "otp_expiry_minutes", 5) or 5)
    expiry_minutes = max(1, min(expiry_minutes, 15))

    otp = set_otp_for_recipient(row.name, expiry_minutes=expiry_minutes)
    frappe.db.set_value(
        "E-Sign Recipient",
        row.name,
        "status",
        "OTP Requested",
        update_modified=False,
    )
    delivery = legacy._send_otp_email(row, otp)
    developer_delivery = _developer_otp_is_allowed()

    legacy.add_audit(
        envelope=row.parent,
        event_type="recipient.otp_requested",
        actor_type="External Signer",
        actor_email=row.signer_email,
        details={
            "recipient": row.name,
            "expiry_minutes": expiry_minutes,
            "email_result": delivery,
            "otp_version": 2,
        },
    )
    legacy.add_security_event(
        event_type="otp.requested",
        severity="Low" if delivery.get("sent") else "Medium",
        envelope=row.parent,
        recipient_row=row.name,
        recipient_email=row.signer_email,
        token_hash_prefix=legacy._phase10_token_prefix(token),
        details={
            "delivery": delivery,
            "expiry_minutes": expiry_minutes,
            "otp_version": 2,
        },
    )

    if not delivery.get("sent") and not developer_delivery:
        invalidate_recipient_otp(row.name)
        frappe.db.set_value(
            "E-Sign Recipient",
            row.name,
            "status",
            "Viewed",
            update_modified=False,
        )
        frappe.db.commit()
        return {
            "ok": False,
            "message": _("The verification code could not be delivered. Please try again later."),
            "delivery": {"sent": False},
        }

    frappe.db.commit()
    response = {
        "ok": True,
        "message": _("Verification code sent."),
        "delivery": delivery,
        "expires_in_minutes": expiry_minutes,
    }
    if developer_delivery:
        response["dev_otp"] = otp
        response["warning"] = "Development-only OTP output is enabled."
    return response


@frappe.whitelist(allow_guest=True)
def verify_otp(token: str, otp: str):
    row = legacy._get_recipient_by_token(token)
    if not row:
        legacy._phase10_rate(
            scope="otp_verify_invalid_token_v2",
            token=token,
            limit=5,
            window_seconds=600,
            severity="High",
        )
        legacy.add_security_event(
            event_type="otp.invalid_token_verify",
            severity="High",
            token_hash_prefix=legacy._phase10_token_prefix(token),
        )
        frappe.throw(_("Invalid signing link"))

    legacy._phase10_rate(
        scope="otp_verify_v2",
        token=token,
        email=row.signer_email,
        limit=10,
        window_seconds=600,
        envelope=row.parent,
        recipient_row=row.name,
        severity="High",
    )
    legacy._ensure_token_active(row)

    settings = legacy._settings()
    max_attempts = int(getattr(settings, "max_otp_attempts", 5) or 5)
    max_attempts = max(1, min(max_attempts, 10))
    verified = verify_recipient_otp(row.name, otp, max_attempts=max_attempts)

    state = frappe.db.get_value(
        "E-Sign Recipient",
        row.name,
        ["otp_attempts", "otp_verified"],
        as_dict=True,
    ) or {}
    attempts = int(state.get("otp_attempts") or 0)
    locked = bool(not verified and attempts >= max_attempts)

    if verified:
        frappe.db.set_value(
            "E-Sign Recipient",
            row.name,
            "status",
            "OTP Verified",
            update_modified=False,
        )
    elif locked:
        invalidate_recipient_otp(row.name)
        frappe.db.set_value(
            "E-Sign Recipient",
            row.name,
            {
                "status": "Failed",
                "token_hash": "",
                "token_expires_at": now_datetime(),
            },
            update_modified=False,
        )

    legacy.add_audit(
        envelope=row.parent,
        event_type=(
            "recipient.otp_locked"
            if locked
            else "recipient.otp_verified"
            if verified
            else "recipient.otp_failed"
        ),
        actor_type="External Signer" if not locked else "System",
        actor_email=row.signer_email,
        details={
            "recipient": row.name,
            "ok": verified,
            "attempts": attempts,
            "max_attempts": max_attempts,
            "token_revoked": locked,
            "otp_version": 2,
        },
    )
    legacy.add_security_event(
        event_type=("otp.locked_token_revoked" if locked else "otp.verified" if verified else "otp.failed"),
        severity="High" if locked else "Low" if verified else "Medium",
        envelope=row.parent,
        recipient_row=row.name,
        recipient_email=row.signer_email,
        token_hash_prefix=legacy._phase10_token_prefix(token),
        details={"attempts": attempts, "max_attempts": max_attempts, "otp_version": 2},
    )
    frappe.db.commit()
    return {
        "ok": verified,
        "verified": verified,
        "attempts": attempts,
        "max_attempts": max_attempts,
        "locked": locked,
    }


def _finish_signing(token: str, operation, **kwargs):
    # Resolve without locking, then acquire the envelope and recipient locks in
    # one consistent order. This avoids certificate/audit races and deadlocks.
    row = _recipient_for_active_token(token)
    lock_signing_scope(row.name, row.parent)
    if not recipient_has_valid_otp_session(row.name, lock=False):
        legacy.add_security_event(
            event_type="signing.blocked_invalid_otp_session",
            severity="High",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=legacy._phase10_token_prefix(token),
        )
        frappe.throw(_("A current OTP verification is required before signing."))
    result = operation(token=token, **kwargs)
    invalidate_recipient_otp(row.name)
    frappe.db.commit()
    return result


@frappe.whitelist(allow_guest=True)
def sign_typed(token: str, signature_text: str, consent_accepted: int = 0):
    return _finish_signing(
        token,
        legacy.sign_typed,
        signature_text=signature_text,
        consent_accepted=consent_accepted,
    )


@frappe.whitelist(allow_guest=True)
def sign_drawn(token: str, signature_data_url: str, consent_accepted: int = 0):
    return _finish_signing(
        token,
        legacy.sign_drawn,
        signature_data_url=signature_data_url,
        consent_accepted=consent_accepted,
    )


@frappe.whitelist(allow_guest=True)
def sign_uploaded(
    token: str,
    file_name: str,
    file_base64: str,
    consent_accepted: int = 0,
):
    return _finish_signing(
        token,
        legacy.sign_uploaded,
        file_name=file_name,
        file_base64=file_base64,
        consent_accepted=consent_accepted,
    )
