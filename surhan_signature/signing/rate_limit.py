import hashlib

import frappe
from frappe import _


_ATOMIC_COUNTER_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return current
"""


def _cache():
    return frappe.cache()


def safe_identity(value: str) -> str:
    raw = str(value or "anonymous").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def rate_limit_key(scope: str, identity: str) -> str:
    return f"surhan_signature:rate:{scope}:{safe_identity(identity)}"


def hit_rate_limit(scope: str, identity: str, limit: int, window_seconds: int) -> dict:
    limit = max(1, int(limit))
    window_seconds = max(1, int(window_seconds))
    key = rate_limit_key(scope, identity)

    try:
        current = int(_cache().eval(_ATOMIC_COUNTER_SCRIPT, 1, key, window_seconds))
    except Exception:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Rate Limiter Failure")
        frappe.throw(
            _("The security service is temporarily unavailable. Please try again later."),
            title=_("Security service unavailable"),
        )

    return {
        "allowed": current <= limit,
        "key": key,
        "scope": scope,
        "count": current,
        "limit": limit,
        "window_seconds": window_seconds,
    }


def enforce_rate_limit(scope: str, identity: str, limit: int, window_seconds: int) -> dict:
    result = hit_rate_limit(scope, identity, limit, window_seconds)
    if not result["allowed"]:
        frappe.throw(
            _("Too many attempts. Please wait before trying again."),
            title=_("Rate limit exceeded"),
        )
    return result
