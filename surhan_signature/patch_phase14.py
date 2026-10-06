import json
import frappe


SIGNATURE_ROLES = [
    "Signature Administrator",
    "Signature Manager",
    "Signature Sender",
    "Signature Auditor",
    "Signature Viewer",
]


def ensure_roles():
    created = []

    for role_name in SIGNATURE_ROLES:
        if not frappe.db.exists("Role", role_name):
            doc = frappe.get_doc({
                "doctype": "Role",
                "role_name": role_name,
                "desk_access": 1,
                "disabled": 0,
                "is_custom": 1,
            })
            doc.insert(ignore_permissions=True)
            created.append(role_name)

    frappe.db.commit()

    return created


def assign_role_to_user(user: str, role: str):
    if role not in SIGNATURE_ROLES:
        frappe.throw(f"Invalid Signature role: {role}")

    if not frappe.db.exists("User", user):
        frappe.throw(f"User not found: {user}")

    doc = frappe.get_doc("User", user)
    existing = {r.role for r in doc.roles}

    if role not in existing:
        doc.append("roles", {"role": role})
        doc.save(ignore_permissions=True)
        frappe.db.commit()
        return True

    return False


def ensure_workspace():
    """
    Create a simple Desk workspace for the app.
    This is intentionally conservative because Workspace fields differ between Frappe versions.
    """
    label = "Surhan Signature"
    name = frappe.db.exists("Workspace", {"label": label}) or frappe.db.exists("Workspace", label)

    if name:
        ws = frappe.get_doc("Workspace", name)
        created = False
    else:
        ws = frappe.new_doc("Workspace")
        created = True

    meta = frappe.get_meta("Workspace")

    def has(fieldname):
        return meta.has_field(fieldname)

    if has("label"):
        ws.label = label
    if has("title"):
        ws.title = label
    if has("module"):
        ws.module = "Surhan Signature"
    if has("public"):
        ws.public = 1
    if has("category"):
        ws.category = "Modules"
    if has("icon"):
        ws.icon = "signature"
    if has("indicator_color"):
        ws.indicator_color = "blue"
    if has("sequence_id"):
        ws.sequence_id = 20
    if has("is_hidden"):
        ws.is_hidden = 0

    content = [
        {
            "id": "surhan_signature_header",
            "type": "header",
            "data": {"text": "Surhan Signature"},
        },
        {
            "id": "surhan_signature_dashboard",
            "type": "shortcut",
            "data": {
                "shortcut_name": "Signature Dashboard",
                "link_to": "/signature-dashboard",
                "type": "URL",
            },
        },
        {
            "id": "surhan_signature_envelopes",
            "type": "shortcut",
            "data": {
                "shortcut_name": "E-Sign Envelopes",
                "link_to": "E-Sign Envelope",
                "type": "DocType",
            },
        },
        {
            "id": "surhan_signature_certificates",
            "type": "shortcut",
            "data": {
                "shortcut_name": "E-Sign Certificates",
                "link_to": "E-Sign Certificate",
                "type": "DocType",
            },
        },
        {
            "id": "surhan_signature_audit",
            "type": "shortcut",
            "data": {
                "shortcut_name": "Audit Logs",
                "link_to": "E-Sign Audit Log",
                "type": "DocType",
            },
        },
    ]

    if has("content"):
        ws.content = json.dumps(content, ensure_ascii=False)

    if has("roles"):
        existing_roles = {r.role for r in ws.roles}
        for role in SIGNATURE_ROLES:
            if role not in existing_roles:
                ws.append("roles", {"role": role})

    try:
        if created:
            ws.insert(ignore_permissions=True, ignore_mandatory=True)
        else:
            ws.save(ignore_permissions=True, ignore_mandatory=True)

        frappe.db.commit()

        return {
            "ok": True,
            "created": created,
            "workspace": ws.name,
            "label": label,
        }

    except Exception:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Workspace Creation Failed")
        return {
            "ok": False,
            "created": False,
            "workspace": None,
            "label": label,
            "error": "Workspace creation failed. Check Error Log.",
        }


def apply():
    created_roles = ensure_roles()

    assigned_admin = False
    if frappe.db.exists("User", "Administrator"):
        for role in ["Signature Administrator", "Signature Manager", "Signature Auditor"]:
            assigned_admin = assign_role_to_user("Administrator", role) or assigned_admin

    workspace = ensure_workspace()

    print({
        "created_roles": created_roles,
        "administrator_roles_assigned_or_existing": True,
        "workspace": workspace,
    })
