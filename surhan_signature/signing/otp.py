import hashlib
import hmac
import secrets
import string

import frappe
from frappe import _
from frappe.utils import add_to_date, get_datetime, now_datetime


OTP_LENGTH = 6
MIN_EXPIRY_MINUTES = 1
MAX_EXPIRY_MINUTES = 15
MAX_ALLOWED_ATTEMPTS = 10


def generate_numeric_otp(length: int = OTP_LENGTH) -> str:
    length = int(length)
    if length < OTP_LENGTH or length > 10:
        raise ValueError("OTP length must be between 6 and 10 digits")

    return "".join(secrets.choice(string.digits) for _ in range(length))


def _site_otp_pepper() -> str:
    pepper = frappe.conf.get("encryption_key")
    if not pepper:
        frappe.throw(
            _("Site encryption key is required for OTP security."),
            exc=frappe.ValidationError,
        )
    return str(pepper)


def hash_otp(
    otp: str,
    salt: str,
    token_digest: str,
    *,
    pepper: str | None = None,
) -> str:
    """Bind an OTP to the current signing token and a site-held secret."""
    secret = str(pepper) if pepper is not None else _site_otp_pepper()
    message = f"v2:{salt}:{token_digest}:{otp}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def is_expired(dt) -> bool:
    if not dt:
        return True
    return now_datetime() > get_datetime(dt)


def _bounded_expiry_minutes(expiry_minutes: int) -> int:
    try:
        value = int(expiry_minutes)
    except (TypeError, ValueError):
        value = 5
    return max(MIN_EXPIRY_MINUTES, min(value, MAX_EXPIRY_MINUTES))


def _bounded_max_attempts(max_attempts: int) -> int:
    try:
        value = int(max_attempts)
    except (TypeError, ValueError):
        value = 5
    return max(1, min(value, MAX_ALLOWED_ATTEMPTS))


def _locked_recipient(recipient_row_name: str):
    rows = frappe.db.sql(
        """
        SELECT
            name,
            token_hash,
            otp_token_hash,
            otp_salt,
            otp_hash,
            otp_expires_at,
            otp_attempts,
            otp_verified,
            otp_verified_at
        FROM `tabE-Sign Recipient`
        WHERE name = %s
        FOR UPDATE
        """,
        (recipient_row_name,),
        as_dict=True,
    )
    return rows[0] if rows else None


def reset_otp_state_on_row(recipient) -> None:
    """Reset OTP state on a loaded E-Sign Recipient child row."""
    recipient.otp_salt = None
    recipient.otp_hash = None
    recipient.otp_token_hash = None
    recipient.otp_expires_at = None
    recipient.otp_attempts = 0
    recipient.otp_verified = 0
    recipient.otp_verified_at = None


def invalidate_recipient_otp(recipient_row_name: str) -> None:
    frappe.db.set_value(
        "E-Sign Recipient",
        recipient_row_name,
        {
            "otp_salt": None,
            "otp_hash": None,
            "otp_token_hash": None,
            "otp_expires_at": None,
            "otp_attempts": 0,
            "otp_verified": 0,
            "otp_verified_at": None,
        },
        update_modified=False,
    )


def set_otp_for_recipient(recipient_row_name: str, expiry_minutes: int = 5) -> str:
    row = _locked_recipient(recipient_row_name)
    if not row:
        frappe.throw(_("Signing recipient was not found."), exc=frappe.DoesNotExistError)
    if not row.token_hash:
        frappe.throw(_("The signing link is not active."), exc=frappe.ValidationError)

    otp = generate_numeric_otp()
    salt = secrets.token_urlsafe(24)
    otp_digest = hash_otp(otp, salt, row.token_hash)
    expiry_minutes = _bounded_expiry_minutes(expiry_minutes)

    frappe.db.set_value(
        "E-Sign Recipient",
        recipient_row_name,
        {
            "otp_salt": salt,
            "otp_hash": otp_digest,
            "otp_token_hash": row.token_hash,
            "otp_expires_at": add_to_date(now_datetime(), minutes=expiry_minutes),
            "otp_attempts": 0,
            "otp_verified": 0,
            "otp_verified_at": None,
        },
        update_modified=False,
    )
    return otp


def verify_recipient_otp(recipient_row_name: str, otp: str, max_attempts: int = 5) -> bool:
    row = _locked_recipient(recipient_row_name)
    if not row:
        return False

    max_attempts = _bounded_max_attempts(max_attempts)

    if (
        row.otp_verified
        and row.otp_verified_at
        and row.token_hash
        and row.otp_token_hash
        and hmac.compare_digest(row.token_hash, row.otp_token_hash)
        and not is_expired(row.otp_expires_at)
    ):
        return True

    attempts = int(row.otp_attempts or 0)
    if attempts >= max_attempts:
        return False

    next_attempt = attempts + 1
    supplied_otp = str(otp or "").strip()
    format_valid = len(supplied_otp) == OTP_LENGTH and supplied_otp.isdigit()
    challenge_active = bool(
        row.token_hash
        and row.otp_token_hash
        and hmac.compare_digest(row.token_hash, row.otp_token_hash)
        and row.otp_salt
        and row.otp_hash
        and not is_expired(row.otp_expires_at)
    )

    candidate = hash_otp(supplied_otp, row.otp_salt or "", row.token_hash or "")
    verified = bool(
        format_valid
        and challenge_active
        and hmac.compare_digest(candidate, row.otp_hash or "")
    )

    values = {
        "otp_attempts": next_attempt,
        "otp_verified": 1 if verified else 0,
        "otp_verified_at": now_datetime() if verified else None,
    }

    if verified:
        # The challenge itself is single-use. otp_expires_at becomes the
        # deadline for completing the signing action.
        values.update({"otp_salt": None, "otp_hash": None})
    elif next_attempt >= max_attempts:
        values.update(
            {
                "otp_salt": None,
                "otp_hash": None,
                "otp_token_hash": None,
                "otp_expires_at": None,
            }
        )

    frappe.db.set_value(
        "E-Sign Recipient",
        recipient_row_name,
        values,
        update_modified=False,
    )
    return verified


def recipient_has_valid_otp_session(recipient_row_name: str, *, lock: bool = False) -> bool:
    if lock:
        row = _locked_recipient(recipient_row_name)
    else:
        row = frappe.db.get_value(
            "E-Sign Recipient",
            recipient_row_name,
            [
                "token_hash",
                "otp_token_hash",
                "otp_verified",
                "otp_verified_at",
                "otp_expires_at",
            ],
            as_dict=True,
        )

    return bool(
        row
        and row.token_hash
        and row.otp_token_hash
        and hmac.compare_digest(row.token_hash, row.otp_token_hash)
        and row.otp_verified
        and row.otp_verified_at
        and not is_expired(row.otp_expires_at)
    )
