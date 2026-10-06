"""Shared envelope lifecycle policy and validation helpers."""

from __future__ import annotations

import re
from datetime import datetime

TERMINAL_ENVELOPE_STATUSES = frozenset({"Signed", "Voided", "Expired", "Archived", "Declined"})
TERMINAL_RECIPIENT_STATUSES = frozenset({"Signed", "Declined", "Expired", "Failed"})
MAX_LIFECYCLE_REASON_LENGTH = 1000
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_lifecycle_reason(reason, default: str) -> str:
    value = _CONTROL_CHARACTERS.sub("", str(reason or "")).strip() or default
    if len(value) > MAX_LIFECYCLE_REASON_LENGTH:
        raise ValueError(
            f"Lifecycle reason must not exceed {MAX_LIFECYCLE_REASON_LENGTH} characters."
        )
    return value


def envelope_is_expired(expires_on, *, current_time=None) -> bool:
    if not expires_on:
        return False
    if isinstance(expires_on, datetime) and isinstance(current_time, datetime):
        return expires_on <= current_time
    from frappe.utils import get_datetime, now_datetime

    return get_datetime(expires_on) <= get_datetime(current_time or now_datetime())
