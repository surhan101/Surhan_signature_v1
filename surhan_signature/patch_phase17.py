import json
import frappe


MODULE = "Surhan Signature"


def perm(role, read=0, write=0, create=0, delete=0, report=0, export=0, print_=0, email=0, share=0):
    return {
        "role": role,
        "read": int(read),
        "write": int(write),
        "create": int(create),
        "delete": int(delete),
        "submit": 0,
        "cancel": 0,
        "amend": 0,
        "report": int(report),
        "export": int(export),
        "import": 0,
        "share": int(share),
        "print": int(print_),
        "email": int(email),
        "if_owner": 0,
        "select": 1,
    }


def ensure_doctype(name, fields, permissions):
    if frappe.db.exists("DocType", name):
        doc = frappe.get_doc("DocType", name)
        existing = {f.fieldname for f in doc.fields}

        for f in fields:
            if f["fieldname"] not in existing:
                doc.append("fields", f)

        doc.permissions = []
        for p in permissions:
            doc.append("permissions", p)

        doc.save(ignore_permissions=True)
        frappe.db.commit()
        print(f"Updated DocType: {name}")
        return

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": name,
        "module": MODULE,
        "custom": 0,
        "istable": 0,
        "issingle": 0,
        "editable_grid": 1,
        "track_changes": 1,
        "fields": fields,
        "permissions": permissions,
    })
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    print(f"Created DocType: {name}")


def update_workspace():
    label = "Surhan Signature"
    name = frappe.db.exists("Workspace", {"label": label}) or frappe.db.exists("Workspace", label)

    if not name:
        return {"ok": False, "reason": "Workspace not found"}

    ws = frappe.get_doc("Workspace", name)
    meta = frappe.get_meta("Workspace")

    extra = [
        ("Webhook Endpoints", "E-Sign Webhook Endpoint", "Blue"),
        ("Webhook Deliveries", "E-Sign Webhook Delivery", "Grey"),
    ]

    if meta.has_field("shortcuts"):
        shortcut_meta = frappe.get_meta("Workspace Shortcut")
        existing = {
            getattr(r, "link_to", None)
            for r in getattr(ws, "shortcuts", []) or []
        }

        for label_, dt, color in extra:
            if dt in existing:
                continue

            row = ws.append("shortcuts", {})

            for key, value in {
                "shortcut_name": label_,
                "label": label_,
                "title": label_,
                "type": "DocType",
                "link_to": dt,
                "doc_view": "List",
                "color": color,
            }.items():
                if shortcut_meta.has_field(key):
                    setattr(row, key, value)

    if meta.has_field("content"):
        try:
            content = json.loads(ws.content or "[]")
        except Exception:
            content = []

        ids = {c.get("id") for c in content if isinstance(c, dict)}

        for label_, dt, color in extra:
            cid = label_.lower().replace(" ", "_")
            if cid not in ids:
                content.append({
                    "id": cid,
                    "type": "shortcut",
                    "data": {
                        "shortcut_name": label_,
                        "col": 3,
                    },
                })

        ws.content = json.dumps(content, ensure_ascii=False)

    ws.flags.ignore_mandatory = True
    ws.save(ignore_permissions=True)
    frappe.db.commit()

    return {"ok": True, "workspace": ws.name}


def apply():
    endpoint_fields = [
        {"fieldname": "enabled", "label": "Enabled", "fieldtype": "Check", "default": 1, "in_list_view": 1},
        {"fieldname": "dry_run", "label": "Dry Run", "fieldtype": "Check", "default": 0, "in_list_view": 1},
        {"fieldname": "title", "label": "Title", "fieldtype": "Data", "reqd": 1, "in_list_view": 1},
        {"fieldname": "target_url", "label": "Target URL", "fieldtype": "Data", "reqd": 1, "in_list_view": 1},
        {"fieldname": "secret", "label": "Secret", "fieldtype": "Password"},
        {"fieldname": "events", "label": "Events", "fieldtype": "Code", "options": "JSON", "description": "JSON array. Use [\"*\"] for all events."},
        {"fieldname": "timeout_seconds", "label": "Timeout Seconds", "fieldtype": "Int", "default": 10},
        {"fieldname": "max_attempts", "label": "Max Attempts", "fieldtype": "Int", "default": 3},
        {"fieldname": "last_status", "label": "Last Status", "fieldtype": "Select", "options": "\nPending\nDelivered\nFailed\nSkipped", "read_only": 1, "in_list_view": 1},
        {"fieldname": "last_delivery_at", "label": "Last Delivery At", "fieldtype": "Datetime", "read_only": 1},
    ]

    delivery_fields = [
        {"fieldname": "endpoint", "label": "Endpoint", "fieldtype": "Link", "options": "E-Sign Webhook Endpoint", "in_list_view": 1},
        {"fieldname": "event_type", "label": "Event Type", "fieldtype": "Data", "in_list_view": 1},
        {"fieldname": "status", "label": "Status", "fieldtype": "Select", "options": "Pending\nDelivered\nFailed\nSkipped", "default": "Pending", "in_list_view": 1},
        {"fieldname": "envelope", "label": "Envelope", "fieldtype": "Link", "options": "E-Sign Envelope", "in_list_view": 1},
        {"fieldname": "certificate_no", "label": "Certificate No", "fieldtype": "Link", "options": "E-Sign Certificate"},
        {"fieldname": "target_url", "label": "Target URL", "fieldtype": "Data"},
        {"fieldname": "attempt_count", "label": "Attempt Count", "fieldtype": "Int", "default": 0, "in_list_view": 1},
        {"fieldname": "http_status", "label": "HTTP Status", "fieldtype": "Int", "read_only": 1},
        {"fieldname": "request_sha256", "label": "Request SHA256", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "payload_json", "label": "Payload JSON", "fieldtype": "Code", "options": "JSON"},
        {"fieldname": "headers_json", "label": "Headers JSON", "fieldtype": "Code", "options": "JSON"},
        {"fieldname": "response_text", "label": "Response Text", "fieldtype": "Small Text", "read_only": 1},
        {"fieldname": "error", "label": "Error", "fieldtype": "Small Text", "read_only": 1},
        {"fieldname": "delivered_at", "label": "Delivered At", "fieldtype": "Datetime", "read_only": 1},
        {"fieldname": "next_retry_at", "label": "Next Retry At", "fieldtype": "Datetime", "read_only": 1},
    ]

    endpoint_perms = [
        perm("System Manager", 1, 1, 1, 1, 1, 1, 1, 1, 1),
        perm("Signature Administrator", 1, 1, 1, 1, 1, 1, 1, 1, 1),
        perm("Signature Manager", 1, 1, 1, 0, 1, 1, 1, 1, 0),
        perm("Signature Auditor", 1, 0, 0, 0, 1, 1, 1, 0, 0),
        perm("Signature Viewer", 1, 0, 0, 0, 0, 0, 1, 0, 0),
    ]

    delivery_perms = [
        perm("System Manager", 1, 0, 0, 0, 1, 1, 1, 1, 0),
        perm("Signature Administrator", 1, 0, 0, 0, 1, 1, 1, 1, 0),
        perm("Signature Manager", 1, 0, 0, 0, 1, 1, 1, 1, 0),
        perm("Signature Auditor", 1, 0, 0, 0, 1, 1, 1, 0, 0),
        perm("Signature Viewer", 1, 0, 0, 0, 0, 0, 1, 0, 0),
    ]

    ensure_doctype("E-Sign Webhook Endpoint", endpoint_fields, endpoint_perms)
    ensure_doctype("E-Sign Webhook Delivery", delivery_fields, delivery_perms)

    ws = update_workspace()

    print({
        "ok": True,
        "workspace": ws,
    })
