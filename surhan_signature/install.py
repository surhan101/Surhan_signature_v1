import frappe


MODULE_NAME = "Surhan Signature"


ROLES = [
    "Signature Administrator",
    "Signature Manager",
    "Signature Sender",
    "Signature Viewer",
    "Signature Auditor",
    "Signature Legal Reviewer",
    "Integration User",
]


def after_install():
    create_all()


def create_all():
    create_module()
    create_roles()
    create_doctypes()
    create_settings()
    frappe.db.commit()


def create_module():
    if not frappe.db.exists("Module Def", MODULE_NAME):
        frappe.get_doc({
            "doctype": "Module Def",
            "module_name": MODULE_NAME,
            "app_name": "surhan_signature",
        }).insert(ignore_permissions=True)


def create_roles():
    for role in ROLES:
        if not frappe.db.exists("Role", role):
            frappe.get_doc({
                "doctype": "Role",
                "role_name": role,
                "desk_access": 1,
            }).insert(ignore_permissions=True)


def f(fieldname, label, fieldtype, **kwargs):
    row = {
        "fieldname": fieldname,
        "label": label,
        "fieldtype": fieldtype,
    }
    row.update(kwargs)
    return row


def base_permissions():
    return [
        {
            "role": "System Manager",
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 1,
            "submit": 0,
            "cancel": 0,
            "amend": 0,
            "report": 1,
            "export": 1,
            "share": 1,
            "print": 1,
            "email": 1,
        },
        {
            "role": "Signature Administrator",
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 0,
            "report": 1,
            "export": 1,
            "share": 1,
            "print": 1,
            "email": 1,
        },
        {
            "role": "Signature Manager",
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 0,
            "report": 1,
            "export": 1,
            "print": 1,
            "email": 1,
        },
        {
            "role": "Signature Sender",
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 0,
            "report": 1,
            "print": 1,
            "email": 1,
        },
        {
            "role": "Signature Viewer",
            "read": 1,
            "write": 0,
            "create": 0,
            "delete": 0,
            "report": 1,
            "print": 1,
        },
        {
            "role": "Signature Auditor",
            "read": 1,
            "write": 0,
            "create": 0,
            "delete": 0,
            "report": 1,
            "export": 1,
            "print": 1,
        },
    ]


def admin_only_permissions():
    return [
        {
            "role": "System Manager",
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 1,
            "report": 1,
            "export": 1,
            "print": 1,
        },
        {
            "role": "Signature Administrator",
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 0,
            "report": 1,
            "export": 1,
            "print": 1,
        },
        {
            "role": "Signature Auditor",
            "read": 1,
            "write": 0,
            "create": 0,
            "delete": 0,
            "report": 1,
            "export": 1,
            "print": 1,
        },
    ]


def ensure_doctype(name, fields, permissions=None, istable=0, issingle=0, autoname=None, title_field=None):
    if frappe.db.exists("DocType", name):
        print(f"Exists: {name}")
        return

    doc = {
        "doctype": "DocType",
        "name": name,
        "module": MODULE_NAME,
        "custom": 0,
        "istable": istable,
        "issingle": issingle,
        "editable_grid": 1 if istable else 0,
        "track_changes": 1,
        "fields": fields,
        "permissions": [] if istable else (permissions or base_permissions()),
        "sort_field": "modified",
        "sort_order": "DESC",
    }

    if autoname:
        doc["autoname"] = autoname

    if title_field:
        doc["title_field"] = title_field

    frappe.get_doc(doc).insert(ignore_permissions=True)
    print(f"Created: {name}")


def create_doctypes():
    create_recipient_doctype()
    create_signature_field_doctype()
    create_envelope_doctype()
    create_audit_log_doctype()
    create_certificate_doctype()
    create_settings_doctype()


def create_recipient_doctype():
    ensure_doctype(
        "E-Sign Recipient",
        [
            f("signer_name", "Signer Name", "Data", reqd=1, in_list_view=1),
            f("signer_email", "Signer Email", "Data", reqd=1, in_list_view=1),
            f("signer_phone", "Signer Phone", "Data"),
            f("signer_user", "Signer User", "Link", options="User"),
            f("role", "Role", "Select", options="Signer\nApprover\nViewer\nWitness", default="Signer", reqd=1),
            f("sign_order", "Sign Order", "Int", default=1),
            f("status", "Status", "Select", options="Pending\nInvited\nViewed\nOTP Requested\nOTP Verified\nSigned\nDeclined\nExpired\nFailed", default="Pending", in_list_view=1),
            f("security_section", "Security", "Section Break"),
            f("token_hash", "Token Hash", "Data", read_only=1),
            f("token_expires_at", "Token Expires At", "Datetime"),
            f("otp_salt", "OTP Salt", "Data", read_only=1),
            f("otp_hash", "OTP Hash", "Data", read_only=1),
            f("otp_expires_at", "OTP Expires At", "Datetime"),
            f("otp_attempts", "OTP Attempts", "Int", default=0),
            f("otp_verified", "OTP Verified", "Check", default=0),
            f("otp_verified_at", "OTP Verified At", "Datetime"),
            f("activity_section", "Activity", "Section Break"),
            f("viewed_at", "Viewed At", "Datetime"),
            f("signed_at", "Signed At", "Datetime"),
            f("declined_at", "Declined At", "Datetime"),
            f("decline_reason", "Decline Reason", "Small Text"),
            f("signature_section", "Signature Evidence", "Section Break"),
            f("signature_method", "Signature Method", "Select", options="Drawn\nTyped\nUploaded\nWebCrypto\nOTP\nKYC\nExternal Provider"),
            f("signature_text", "Signature Text", "Data"),
            f("signature_image", "Signature Image", "Attach"),
            f("selfie_file", "Selfie / KYC File", "Attach"),
            f("public_key_pem", "Public Key PEM", "Long Text"),
            f("signature_value", "Cryptographic Signature Value", "Long Text"),
            f("device_section", "Device Evidence", "Section Break"),
            f("ip_address", "IP Address", "Data"),
            f("user_agent", "User Agent", "Small Text"),
            f("consent_text_snapshot", "Consent Text Snapshot", "Small Text"),
        ],
        istable=1,
    )


def create_signature_field_doctype():
    ensure_doctype(
        "E-Sign Signature Field",
        [
            f("field_key", "Field Key", "Data", reqd=1, in_list_view=1),
            f("recipient_email", "Recipient Email", "Data", in_list_view=1),
            f("field_type", "Field Type", "Select", options="Signature\nInitial\nDate\nText\nCheckbox\nRadio\nStamp\nAttachment\nCompany Seal", default="Signature", reqd=1),
            f("required", "Required", "Check", default=1),
            f("page_no", "Page No", "Int", default=1),
            f("x", "X", "Float"),
            f("y", "Y", "Float"),
            f("width", "Width", "Float"),
            f("height", "Height", "Float"),
            f("value", "Value", "Small Text"),
        ],
        istable=1,
    )


def create_envelope_doctype():
    ensure_doctype(
        "E-Sign Envelope",
        [
            f("title", "Title", "Data", reqd=1, in_list_view=1),
            f("status", "Status", "Select", options="Draft\nPrepared\nSent\nViewed\nPartially Signed\nSigned\nDeclined\nExpired\nVoided\nFailed\nArchived", default="Draft", in_list_view=1),
            f("signing_level", "Signing Level", "Select", options="SES\nAES\nQES Provider Ready", default="SES", reqd=1),
            f("workflow_type", "Workflow Type", "Select", options="Sequential\nParallel\nMixed", default="Sequential", reqd=1),
            f("category", "Category", "Select", options="Legal\nHR\nFinance\nSales\nOperations\nOther", default="Legal"),
            f("source_section", "Source", "Section Break"),
            f("source_doctype", "Source DocType", "Link", options="DocType"),
            f("source_name", "Source Name", "Dynamic Link", options="source_doctype"),
            f("document_section", "Document", "Section Break"),
            f("original_file", "Original File", "Attach"),
            f("final_signed_pdf", "Final Signed PDF", "Attach", read_only=1),
            f("document_html", "Document HTML", "Text Editor"),
            f("hash_section", "Integrity Hashes", "Section Break"),
            f("canonical_sha256", "Canonical SHA-256", "Data", read_only=1),
            f("final_pdf_sha256", "Final PDF SHA-256", "Data", read_only=1),
            f("audit_root_hash", "Audit Root Hash", "Data", read_only=1),
            f("recipients_section", "Recipients", "Section Break"),
            f("recipients", "Recipients", "Table", options="E-Sign Recipient"),
            f("fields_section", "Signature Fields", "Section Break"),
            f("signature_fields", "Signature Fields", "Table", options="E-Sign Signature Field"),
            f("lifecycle_section", "Lifecycle", "Section Break"),
            f("expires_on", "Expires On", "Datetime"),
            f("sent_on", "Sent On", "Datetime"),
            f("completed_on", "Completed On", "Datetime"),
            f("locked", "Locked", "Check", default=0),
            f("certificate_no", "Certificate No", "Data", read_only=1),
            f("risk_section", "Risk / AI Review", "Section Break"),
            f("risk_score", "Risk Score", "Percent"),
            f("risk_level", "Risk Level", "Select", options="\nLow\nMedium\nHigh\nCritical"),
            f("risk_json", "Risk JSON", "Code", options="JSON"),
            f("notes", "Notes", "Small Text"),
        ],
        permissions=base_permissions(),
        autoname="format:ESIGN-ENV-.YYYY.-.#####",
        title_field="title",
    )


def create_audit_log_doctype():
    ensure_doctype(
        "E-Sign Audit Log",
        [
            f("envelope", "Envelope", "Link", options="E-Sign Envelope", reqd=1, in_list_view=1),
            f("event_type", "Event Type", "Data", reqd=1, in_list_view=1),
            f("actor_type", "Actor Type", "Select", options="System\nUser\nExternal Signer\nIntegration\nAdministrator", default="System"),
            f("actor_user", "Actor User", "Link", options="User"),
            f("actor_email", "Actor Email", "Data"),
            f("timestamp_utc", "Timestamp UTC", "Datetime", reqd=1, in_list_view=1),
            f("ip_address", "IP Address", "Data"),
            f("user_agent", "User Agent", "Small Text"),
            f("request_id", "Request ID", "Data"),
            f("details_json", "Details JSON", "Code", options="JSON"),
            f("previous_hash", "Previous Hash", "Data", read_only=1),
            f("current_hash", "Current Hash", "Data", read_only=1, in_list_view=1),
        ],
        permissions=admin_only_permissions(),
        autoname="format:ESIGN-AUD-.YYYY.-.#####",
        title_field="event_type",
    )


def create_certificate_doctype():
    ensure_doctype(
        "E-Sign Certificate",
        [
            f("envelope", "Envelope", "Link", options="E-Sign Envelope", reqd=1, in_list_view=1),
            f("certificate_no", "Certificate No", "Data", reqd=1, unique=1, in_list_view=1),
            f("completed_at", "Completed At", "Datetime", in_list_view=1),
            f("original_hash", "Original Hash", "Data"),
            f("final_hash", "Final Hash", "Data"),
            f("audit_root_hash", "Audit Root Hash", "Data"),
            f("signer_summary", "Signer Summary", "Code", options="JSON"),
            f("verification_url", "Verification URL", "Data"),
            f("qr_code", "QR Code", "Attach"),
            f("certificate_pdf", "Certificate PDF", "Attach"),
        ],
        permissions=admin_only_permissions(),
        autoname="field:certificate_no",
        title_field="certificate_no",
    )


def create_settings_doctype():
    ensure_doctype(
        "E-Sign Settings",
        [
            f("general_section", "General", "Section Break"),
            f("default_expiry_days", "Default Expiry Days", "Int", default=7),
            f("default_signing_level", "Default Signing Level", "Select", options="SES\nAES\nQES Provider Ready", default="SES"),
            f("certificate_prefix", "Certificate Prefix", "Data", default="ESIGN-CERT"),
            f("security_section", "Security", "Section Break"),
            f("otp_expiry_minutes", "OTP Expiry Minutes", "Int", default=5),
            f("max_otp_attempts", "Max OTP Attempts", "Int", default=5),
            f("allowed_file_types", "Allowed File Types", "Small Text", default="pdf,docx,png,jpg,jpeg"),
            f("max_file_size_mb", "Max File Size MB", "Int", default=25),
            f("integrations_section", "Integrations", "Section Break"),
            f("enable_email", "Enable Email", "Check", default=1),
            f("enable_sms", "Enable SMS", "Check", default=0),
            f("enable_whatsapp", "Enable WhatsApp", "Check", default=0),
            f("enable_ai_review", "Enable AI Review", "Check", default=0),
            f("webhook_secret", "Webhook Secret", "Password"),
        ],
        permissions=admin_only_permissions(),
        issingle=1,
    )


def create_settings():
    if not frappe.db.exists("E-Sign Settings", "E-Sign Settings"):
        try:
            doc = frappe.get_doc("E-Sign Settings")
            doc.default_expiry_days = 7
            doc.otp_expiry_minutes = 5
            doc.max_otp_attempts = 5
            doc.default_signing_level = "SES"
            doc.certificate_prefix = "ESIGN-CERT"
            doc.save(ignore_permissions=True)
        except Exception:
            pass
