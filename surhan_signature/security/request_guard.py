"""Request-time role and object authorization checks."""

import frappe

from surhan_signature.security.policy import classify

ADMIN_ROLES = frozenset({"System Manager", "Internal Signature Administrator", "Internal Signature Manager"})
AUDITOR_ROLES = ADMIN_ROLES | {"Internal Signature Auditor"}
USER_ROLES = AUDITOR_ROLES | {"Internal Signature User"}

ENVELOPE_READ = frozenset({"envelope_progress", "check_audit_chain", "verify_artifacts", "envelope_compliance_report", "export_envelope_compliance_json", "calculate_envelope_risk", "export_envelope_risk_report_json"})
ENVELOPE_WRITE = frozenset({"issue_signing_token", "revoke_signing_token", "send_envelope_invites", "resend_invite", "finalize_artifacts"})
REFERENCE_READ = frozenset({"get_document_signature_state", "get_document_signature_form_context", "get_signed_document_print_context"})
REFERENCE_WRITE = frozenset({"sync_ac_footer_requests", "apply_first_pending_saved_signature_for_document", "reject_first_pending_signature_for_document"})
REQUEST_METHODS = frozenset({"get_document_signature_request_action_context", "apply_saved_signature_request", "apply_direction_signature_request", "reject_document_signature_request", "phase26n_get_classic_signature_context", "phase26n_accept_signature_request", "phase26n_refuse_signature_request", "phase26n_linear_guidance_signature_request"})


def _method():
    form = getattr(frappe.local, "form_dict", None) or {}
    return str(form.get("cmd") or "").strip()


def _params():
    return getattr(frappe.local, "form_dict", None) or {}


def _roles():
    return set(frappe.get_roles(frappe.session.user) or [])


def _is_admin():
    return frappe.session.user == "Administrator" or bool(_roles() & ADMIN_ROLES)


def _deny(message="You are not permitted to access this signature operation."):
    frappe.throw(message, frappe.PermissionError)


def _require_login():
    if not frappe.session.user or frappe.session.user == "Guest":
        _deny("Authentication is required.")


def _require_roles(allowed):
    _require_login()
    if frappe.session.user != "Administrator" and not (_roles() & allowed):
        _deny()


def _require_doc_permission(doctype, name, ptype):
    if not doctype or not name or not frappe.db.exists(doctype, name):
        _deny("The requested document is unavailable.")
    doc = frappe.get_doc(doctype, name)
    if not frappe.has_permission(doctype, ptype=ptype, doc=doc, user=frappe.session.user):
        _deny("You do not have permission for the requested document.")


def _object_guard(method):
    short = method.rsplit(".", 1)[-1]
    params = _params()
    if short == "create_envelope":
        if not frappe.has_permission("E-Sign Envelope", ptype="create", user=frappe.session.user):
            _deny("You cannot create signature envelopes.")
    elif short in ENVELOPE_READ:
        _require_doc_permission("E-Sign Envelope", params.get("envelope"), "read")
    elif short in ENVELOPE_WRITE:
        _require_doc_permission("E-Sign Envelope", params.get("envelope"), "write")
    elif short in REFERENCE_READ:
        _require_doc_permission(params.get("reference_doctype"), params.get("reference_name"), "read")
    elif short in REFERENCE_WRITE:
        _require_doc_permission(params.get("reference_doctype"), params.get("reference_name"), "write")
    elif short in REQUEST_METHODS:
        request_name = params.get("request_name")
        if not request_name or not frappe.db.exists("Document Signature Request", request_name):
            _deny("The signature request is unavailable.")
        row = frappe.db.get_value("Document Signature Request", request_name, ["requested_user", "reference_doctype", "reference_name"], as_dict=True)
        if not _is_admin() and row.requested_user != frappe.session.user:
            _deny("This signature request is assigned to another user.")
        _require_doc_permission(row.reference_doctype, row.reference_name, "read")


def enforce():
    """Frappe before_request hook; unrelated applications are ignored."""
    method = _method()
    mode = classify(method)
    if mode in {"unrelated", "public"}:
        return
    if mode == "self":
        _require_login()
        return
    if mode == "signature_user":
        _require_roles(USER_ROLES)
        _object_guard(method)
        return
    if mode == "auditor":
        _require_roles(AUDITOR_ROLES)
        return
    _require_roles(ADMIN_ROLES)


@frappe.whitelist()
def health():
    _require_roles(ADMIN_ROLES)
    return {"ok": True, "fail_closed": True, "admin_roles": sorted(ADMIN_ROLES), "auditor_roles": sorted(AUDITOR_ROLES), "user_roles": sorted(USER_ROLES)}
