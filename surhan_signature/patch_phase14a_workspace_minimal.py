import json
import frappe


SHORTCUTS = [
    ("E-Sign Envelopes", "E-Sign Envelope", "Green"),
    ("E-Sign Certificates", "E-Sign Certificate", "Purple"),
    ("E-Sign Audit Logs", "E-Sign Audit Log", "Orange"),
    ("E-Sign Security Events", "E-Sign Security Event", "Red"),
    ("E-Sign Settings", "E-Sign Settings", "Grey"),
]


def _set_if_has(doc, meta, fieldname, value):
    if meta.has_field(fieldname):
        setattr(doc, fieldname, value)


def _set_row_if_has(row, meta, fieldname, value):
    if meta.has_field(fieldname):
        setattr(row, fieldname, value)


def _append_doctype_shortcut(ws, label, doctype_name, color):
    meta = frappe.get_meta("Workspace Shortcut")
    row = ws.append("shortcuts", {})

    # مهم: لا نستخدم URL هنا لأن Frappe عندك يفسره كـ DocType
    _set_row_if_has(row, meta, "shortcut_name", label)
    _set_row_if_has(row, meta, "label", label)
    _set_row_if_has(row, meta, "title", label)
    _set_row_if_has(row, meta, "type", "DocType")
    _set_row_if_has(row, meta, "link_to", doctype_name)
    _set_row_if_has(row, meta, "doc_view", "List")
    _set_row_if_has(row, meta, "color", color)

    return row


def apply():
    label = "Surhan Signature"

    name = frappe.db.exists("Workspace", {"label": label}) or frappe.db.exists("Workspace", label)

    if name:
        ws = frappe.get_doc("Workspace", name)
    else:
        ws = frappe.new_doc("Workspace")

    meta = frappe.get_meta("Workspace")

    _set_if_has(ws, meta, "label", label)
    _set_if_has(ws, meta, "title", label)
    _set_if_has(ws, meta, "module", "Surhan Signature")
    _set_if_has(ws, meta, "public", 1)
    _set_if_has(ws, meta, "is_hidden", 0)
    _set_if_has(ws, meta, "category", "Modules")
    _set_if_has(ws, meta, "indicator_color", "blue")
    _set_if_has(ws, meta, "icon", "signature")
    _set_if_has(ws, meta, "sequence_id", 20)

    # امسح أي rows قديمة فيها URL وتسبب DocType URL not found
    if meta.has_field("shortcuts"):
        ws.set("shortcuts", [])
        for label_, dt, color in SHORTCUTS:
            if frappe.db.exists("DocType", dt):
                _append_doctype_shortcut(ws, label_, dt, color)

    if meta.has_field("links"):
        ws.set("links", [])

    if meta.has_field("content"):
        content = [
            {
                "id": "surhan_signature_header",
                "type": "header",
                "data": {
                    "text": "Surhan Signature",
                    "col": 12,
                },
            },
            {
                "id": "surhan_signature_note",
                "type": "paragraph",
                "data": {
                    "text": "Electronic signature envelopes, certificates, audit logs, security events, and settings. Dashboard URL: /signature-dashboard",
                    "col": 12,
                },
            },
        ]

        for label_, dt, color in SHORTCUTS:
            content.append({
                "id": label_.lower().replace(" ", "_").replace("-", "_"),
                "type": "shortcut",
                "data": {
                    "shortcut_name": label_,
                    "col": 3,
                },
            })

        ws.content = json.dumps(content, ensure_ascii=False)

    if meta.has_field("roles"):
        existing_roles = {r.role for r in ws.roles}
        for role in [
            "System Manager",
            "Signature Administrator",
            "Signature Manager",
            "Signature Sender",
            "Signature Auditor",
            "Signature Viewer",
        ]:
            if frappe.db.exists("Role", role) and role not in existing_roles:
                ws.append("roles", {"role": role})

    ws.flags.ignore_mandatory = True

    if ws.is_new():
        ws.insert(ignore_permissions=True)
    else:
        ws.save(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache()

    print({
        "ok": True,
        "workspace": ws.name,
        "label": ws.label,
        "shortcuts_count": len(getattr(ws, "shortcuts", []) or []),
        "links_count": len(getattr(ws, "links", []) or []),
        "content_present": bool(getattr(ws, "content", None)),
        "dashboard_url": "/signature-dashboard",
    })


def verify():
    label = "Surhan Signature"
    name = frappe.db.exists("Workspace", {"label": label}) or frappe.db.exists("Workspace", label)

    if not name:
        print({"ok": False, "error": "Workspace not found"})
        return

    ws = frappe.get_doc("Workspace", name)

    shortcuts = []
    for r in getattr(ws, "shortcuts", []) or []:
        shortcuts.append({
            "shortcut_name": getattr(r, "shortcut_name", None) or getattr(r, "label", None) or getattr(r, "title", None),
            "type": getattr(r, "type", None),
            "link_to": getattr(r, "link_to", None),
        })

    print({
        "ok": True,
        "workspace": ws.name,
        "label": getattr(ws, "label", None),
        "title": getattr(ws, "title", None),
        "module": getattr(ws, "module", None),
        "public": getattr(ws, "public", None),
        "shortcuts_count": len(shortcuts),
        "shortcuts": shortcuts,
        "content_present": bool(getattr(ws, "content", None)),
        "dashboard_direct_url": "/signature-dashboard",
    })
