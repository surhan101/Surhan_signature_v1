# -*- coding: utf-8 -*-
"""
Surhan Signature - RESTful API Gateway for External Systems
Enterprise-grade HMAC-SHA256 authenticated signature gateway.
"""

import json
import time
import hashlib
import hmac
import traceback
import frappe
from frappe import _


def _safe_json_dumps(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _authenticate_external_request():
    """
    Authenticate incoming request using either:
    1. X-API-Key + X-Signature-Timestamp + X-Signature-HMAC
    2. Bearer API Key in Authorization header
    """
    api_key = frappe.get_request_header("X-API-Key")
    if not api_key:
        auth_header = frappe.get_request_header("Authorization") or ""
        if auth_header.startswith("Bearer "):
            api_key = auth_header.replace("Bearer ", "").strip()
            
    if not api_key:
        frappe.throw(_("Authentication Failed: Missing X-API-Key or Authorization Bearer header."), frappe.AuthenticationError)

    dt_system = "Internal Signature External System"
    if not frappe.db.exists("DocType", dt_system):
        frappe.throw(_("External System integration not initialized."), frappe.ConfigurationError)

    system_names = frappe.get_all(dt_system, filters={"api_key": api_key, "enabled": 1}, fields=["name", "system_name", "ip_whitelist", "allowed_doctypes"])
    if not system_names:
        frappe.throw(_("Authentication Failed: Invalid or disabled API Key."), frappe.AuthenticationError)

    system = frappe.get_doc(dt_system, system_names[0].name)

    # Validate IP Whitelist if configured
    if system.ip_whitelist:
        client_ip = frappe.local.request_ip or frappe.get_request_header("X-Forwarded-For") or ""
        client_ip = client_ip.split(",")[0].strip()
        allowed_ips = [ip.strip() for ip in system.ip_whitelist.split(",") if ip.strip()]
        if allowed_ips and client_ip not in allowed_ips:
            frappe.throw(_(f"Security Rejection: IP {client_ip} is not in the authorized whitelist."), frappe.PermissionError)

    # Optional HMAC Verification if HMAC headers are present
    hmac_header = frappe.get_request_header("X-Signature-HMAC")
    timestamp_header = frappe.get_request_header("X-Signature-Timestamp")
    secret_key = getattr(system, "secret_key", None)

    if hmac_header and secret_key:
        if not timestamp_header:
            frappe.throw(_("Missing X-Signature-Timestamp header for HMAC validation."), frappe.AuthenticationError)
        
        # Check timestamp drift (5 minutes)
        try:
            req_time = int(timestamp_header)
            current_time = int(time.time())
            if abs(current_time - req_time) > 300:
                frappe.throw(_("Request expired: Timestamp drift exceeds 300 seconds."), frappe.AuthenticationError)
        except Exception:
            frappe.throw(_("Invalid timestamp format."), frappe.AuthenticationError)

        # Recompute HMAC
        raw_body = frappe.request.get_data(as_text=True) if frappe.request else ""
        expected_sig = hmac.new(
            secret_key.encode("utf-8"),
            f"{timestamp_header}.{raw_body}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, hmac_header):
            frappe.throw(_("HMAC Signature Mismatch: Payload integrity check failed."), frappe.AuthenticationError)

    return system


@frappe.whitelist(allow_guest=True)
def create_signature_request():
    """
    External API: Creates a signature request from an external system.
    Payload: {
        "external_reference": "EXT-001",
        "reference_doctype": "Sales Invoice",
        "reference_name": "ACC-SINV-2026-00001",
        "title": "Document Title",
        "signers": [
            {"user": "manager@company.com", "action": "Sign", "sequence": 1}
        ],
        "callback_url": "https://external-system.com/webhook"
    }
    """
    system = _authenticate_external_request()

    try:
        data = json.loads(frappe.request.get_data(as_text=True) or "{}")
    except Exception:
        data = frappe.form_dict or {}

    external_ref = data.get("external_reference")
    reference_doctype = data.get("reference_doctype")
    reference_name = data.get("reference_name")
    signers = data.get("signers", [])
    callback_url = data.get("callback_url") or system.callback_url

    if not external_ref or not reference_doctype:
        frappe.throw(_("Missing required fields: external_reference and reference_doctype are mandatory."))

    # Validate Allowed DocTypes
    if system.allowed_doctypes:
        allowed = [d.strip() for d in system.allowed_doctypes.split(",") if d.strip()]
        if allowed and reference_doctype not in allowed:
            frappe.throw(_(f"DocType '{reference_doctype}' is not authorized for system '{system.system_name}'."))

    # Forward to core external gateway implementation in api.py
    from surhan_signature.api import external_signature_gateway_create_request
    
    res = external_signature_gateway_create_request(
        system_id=system.name,
        external_reference=external_ref,
        reference_doctype=reference_doctype,
        reference_name=reference_name,
        signers=signers,
        callback_url=callback_url
    )
    
    frappe.response["http_status_code"] = 200
    return res


@frappe.whitelist(allow_guest=True)
def get_signature_status(external_reference=None, gateway_request=None):
    """
    External API: Returns status of a signature request.
    Query params: external_reference or gateway_request
    """
    system = _authenticate_external_request()
    
    if not external_reference and not gateway_request:
        external_reference = frappe.form_dict.get("external_reference")
        gateway_request = frappe.form_dict.get("gateway_request")
        
    from surhan_signature.api import external_signature_gateway_status
    res = external_signature_gateway_status(
        system_id=system.name,
        external_reference=external_reference,
        gateway_request=gateway_request
    )
    return res


@frappe.whitelist(allow_guest=True)
def verify_signature_hash(document_hash=None, certificate_no=None):
    """
    External API: Validates a SHA-256 document hash or Certificate Number.
    Publicly accessible or authenticated.
    """
    if not document_hash and not certificate_no:
        document_hash = frappe.form_dict.get("document_hash")
        certificate_no = frappe.form_dict.get("certificate_no")
        
    filters = {}
    if certificate_no:
        filters["verification_code"] = certificate_no
    elif document_hash:
        filters["signed_pdf_sha256"] = document_hash
    else:
        frappe.throw(_("Either document_hash or certificate_no must be provided."))

    dt = "Internal Signature Certificate"
    if not frappe.db.exists("DocType", dt):
        return {"valid": False, "message": "Certificate registry not initialized"}

    fields = ["name", "reference_doctype", "reference_name", "verification_code", "signed_pdf_sha256", "signed_pdf", "verification_url", "creation"]
    existing = [f for f in fields if frappe.db.has_column(dt, f)]
    certs = frappe.get_all(dt, filters=filters, fields=existing)
    if not certs:
        return {
            "valid": False,
            "message": "Certificate or document hash not found in official registry."
        }

    cert = certs[0]
    return {
        "valid": True,
        "certificate_no": cert.get("verification_code") or cert.name,
        "reference_doctype": cert.get("reference_doctype"),
        "reference_name": cert.get("reference_name"),
        "sha256_hash": cert.get("signed_pdf_sha256"),
        "certificate_pdf": cert.get("signed_pdf"),
        "verification_url": cert.get("verification_url"),
        "issued_at": str(cert.get("creation")),
        "status": "OFFICIALLY_VERIFIED"
    }
