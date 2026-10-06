"""Validation primitives for irreversible decline operations."""

from __future__ import annotations

import re


MAX_DECLINE_REASON_LENGTH = 1000
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_decline_reason(reason) -> str:
    value = _CONTROL_CHARACTERS.sub("", str(reason or "")).strip()
    if not value:
        return "No reason provided."
    if len(value) > MAX_DECLINE_REASON_LENGTH:
        raise ValueError(
            f"Decline reason must not exceed {MAX_DECLINE_REASON_LENGTH} characters."
        )
    return value
