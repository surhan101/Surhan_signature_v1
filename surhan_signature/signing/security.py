import re
import html


DANGEROUS_TAGS = [
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "link",
    "meta",
    "base",
    "form",
    "input",
    "button",
    "textarea",
    "select",
]


def safe_document_html(value: str | None) -> str:
    """
    Conservative HTML sanitizer for signing preview.
    This is not a full legal document renderer yet.
    Phase 10 will move final rendering to controlled PDF generation.
    """
    if not value:
        return ""

    text = str(value)

    # Prefer Frappe sanitizer if available.
    try:
        from frappe.utils.html_utils import sanitize_html
        return sanitize_html(text)
    except Exception:
        pass

    # Fallback sanitizer.
    for tag in DANGEROUS_TAGS:
        text = re.sub(rf"<\s*{tag}[^>]*>.*?<\s*/\s*{tag}\s*>", "", text, flags=re.I | re.S)
        text = re.sub(rf"<\s*{tag}[^>]*/?\s*>", "", text, flags=re.I | re.S)

    # Remove inline event handlers.
    text = re.sub(r"\s+on[a-zA-Z]+\s*=\s*\"[^\"]*\"", "", text)
    text = re.sub(r"\s+on[a-zA-Z]+\s*=\s*'[^']*'", "", text)
    text = re.sub(r"\s+on[a-zA-Z]+\s*=\s*[^\s>]+", "", text)

    # Remove javascript: and data:text/html payloads.
    text = re.sub(r"javascript\s*:", "", text, flags=re.I)
    text = re.sub(r"data\s*:\s*text/html", "", text, flags=re.I)

    return text


def mask_email(email_addr: str | None) -> str:
    if not email_addr or "@" not in email_addr:
        return email_addr or ""
    local, domain = email_addr.split("@", 1)
    if len(local) <= 2:
        masked = local[:1] + "*"
    else:
        masked = local[:2] + "*" * max(2, len(local) - 2)
    return f"{masked}@{domain}"


def production_safe_dev_value(value):
    """
    Return sensitive development helper only when developer_mode is enabled.
    """
    try:
        import frappe
        if int(frappe.conf.get("developer_mode") or 0):
            return value
    except Exception:
        pass
    return None
