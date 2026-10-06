from frappe.model.naming import getseries
from frappe.utils import nowdate


def current_year() -> str:
    return nowdate().split("-")[0]


def next_series(prefix: str, digits: int = 5) -> str:
    return f"{prefix}{getseries(prefix, digits)}"


def next_envelope_name() -> str:
    return next_series(f"ESIGN-ENV-{current_year()}-", 5)


def next_audit_log_name() -> str:
    return next_series(f"ESIGN-AUD-{current_year()}-", 5)


def next_certificate_no(prefix: str = "ESIGN-CERT") -> str:
    clean_prefix = (prefix or "ESIGN-CERT").strip().rstrip("-")
    return next_series(f"{clean_prefix}-{current_year()}-", 5)

def next_security_event_name() -> str:
    return next_series(f"ESIGN-SEC-{current_year()}-", 5)

def next_webhook_endpoint_name() -> str:
    return next_series(f"ESIGN-WHE-{current_year()}-", 5)

def next_webhook_delivery_name() -> str:
    return next_series(f"ESIGN-WHD-{current_year()}-", 5)

def next_test_run_name() -> str:
    return next_series(f"ESIGN-TEST-{current_year()}-", 5)

def next_risk_assessment_name() -> str:
    return next_series(f"ESIGN-RISK-{current_year()}-", 5)

