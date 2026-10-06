import frappe

from surhan_signature.security.content import MAX_HTML_BYTES, MAX_SIGNATURE_BYTES
from surhan_signature.security.outbound import UnsafeOutboundURL, validate_outbound_url


@frappe.whitelist()
def health():
    blocked = []
    for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/"):
        try:
            validate_outbound_url(url)
        except UnsafeOutboundURL:
            blocked.append(url)
    return {
        "ok": len(blocked) == 3,
        "ssrf_fail_closed": len(blocked) == 3,
        "redirects_allowed": False,
        "max_response_bytes": 65_536,
        "max_signature_bytes": MAX_SIGNATURE_BYTES,
        "max_document_html_bytes": MAX_HTML_BYTES,
        "hmac_replay_window_seconds": 600,
    }
