import json
import frappe


def _has(meta, fieldname):
    return meta.has_field(fieldname)


def _set_if_has(doc, meta, fieldname, value):
    if _has(meta, fieldname):
        setattr(doc, fieldname, value)


def _append_shortcut(ws, shortcut_name, link_type, link_to, url=None, color="Blue"):
    meta = frappe.get_meta("Workspace Shortcut")
    row = ws.append("shortcuts", {})

    values = {
        "shortcut_name": shortcut_name,
        "label": shortcut_name,
        "title": shortcut_name,
        "type": link_type,
        "link_to": link_to,
        "url": url or link_to,
        "color": color,
        "doc_view": "List",
    }

    for key, value in values.items():
        if meta.has_field(key):
            setattr(row, key, value)

    return row


def _append_link(ws, label, link_type, link_to, icon=None):
    meta = frappe.get_meta("Workspace Link")
    row = ws.append("links", {})

    values = {
        "label": label,
        "type": link_type,
        "link_type": link_type,
        "link_to": link_to,
        "url": link_to,
        "icon": icon or "list",
        "hidden": 0,
        "is_query_report": 0,
    }

    for key, value in values.items():
        if meta.has_field(key):
            setattr(row, key, value)

    return row


def apply():
    label = "Surhan Signature"

    name = frappe.db.exists("Workspace", {"label": label}) or frappe.db.exists("Workspace", label)

    if not name:
        ws = frappe.new_doc("Workspace")
    else:
        ws = frappe.get_doc("Workspace", name)

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

    shortcuts = [
        {
            "name": "Signature Dashboard",
            "type": "URL",
            "link_to": "/signature-dashboard",
            "url": "/signature-dashboard",
            "color": "Blue",
        },
        {
            "name": "E-Sign Envelopes",
            "type": "DocType",
            "link_to": "E-Sign Envelope",
            "color": "Green",
        },
        {
            "name": "E-Sign Certificates",
            "type": "DocType",
            "link_to": "E-Sign Certificate",
            "color": "Purple",
        },
        {
            "name": "E-Sign Audit Logs",
            "type": "DocType",
            "link_to": "E-Sign Audit Log",
            "color": "Orange",
        },
        {
            "name": "E-Sign Security Events",
            "type": "DocType",
            "link_to": "E-Sign Security Event",
            "color": "Red",
        },
        {
            "name": "E-Sign Settings",
            "type": "DocType",
            "link_to": "E-Sign Settings",
            "color": "Grey",
        },
    ]

    if meta.has_field("shortcuts"):
        ws.set("shortcuts", [])
        for s in shortcuts:
            _append_shortcut(
                ws,
                shortcut_name=s["name"],
                link_type=s["type"],
                link_to=s["link_to"],
                url=s.get("url"),
                color=s.get("color", "Blue"),
            )

    if meta.has_field("links"):
        ws.set("links", [])
        _append_link(ws, "Signature Dashboard", "URL", "/signature-dashboard", "dashboard")
        _append_link(ws, "E-Sign Envelope", "DocType", "E-Sign Envelope", "signature")
        _append_link(ws, "E-Sign Certificate", "DocType", "E-Sign Certificate", "file")
        _append_link(ws, "E-Sign Audit Log", "DocType", "E-Sign Audit Log", "list")
        _append_link(ws, "E-Sign Security Event", "DocType", "E-Sign Security Event", "shield")
        _append_link(ws, "E-Sign Settings", "DocType", "E-Sign Settings", "settings")

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
                "id": "surhan_signature_subheader",
                "type": "paragraph",
                "data": {
                    "text": "Manage electronic signature envelopes, certificates, audit logs, security events, and verification.",
                    "col": 12,
                },
            },
        ]

        for s in shortcuts:
            content.append({
                "id": s["name"].lower().replace(" ", "_").replace("-", "_"),
                "type": "shortcut",
                "data": {
                    "shortcut_name": s["name"],
                    "col": 3,
                },
            })

        ws.content = json.dumps(content, ensure_ascii=False)

    # Workspace roles
    if meta.has_field("roles"):
        existing_roles = {r.role for r in ws.roles}
        for role in [
            "Signature Administrator",
            "Signature Manager",
            "Signature Sender",
            "Signature Auditor",
            "Signature Viewer",
            "System Manager",
        ]:
            if frappe.db.exists("Role", role) and role not in existing_roles:
                ws.append("roles", {"role": role})

    ws.flags.ignore_mandatory = True

    if ws.is_new():
        ws.insert(ignore_permissions=True)
    else:
        ws.save(ignore_permissions=True)

    frappe.db.commit()

    print({
        "ok": True,
        "workspace": ws.name,
        "label": ws.label,
        "shortcuts_count": len(getattr(ws, "shortcuts", []) or []),
        "links_count": len(getattr(ws, "links", []) or []),
        "has_content": bool(getattr(ws, "content", None)),
    })
