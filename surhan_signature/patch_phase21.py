import frappe


MODULE = "Surhan Signature"


def perm(role, read=0, write=0, create=0, delete=0, report=0, export=0, print_=0, email=0):
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
        "share": 0,
        "print": int(print_),
        "email": int(email),
        "if_owner": 0,
        "select": 1,
    }


def ensure_test_run_doctype():
    name = "E-Sign Test Run"

    fields = [
        {"fieldname": "suite", "label": "Suite", "fieldtype": "Data", "default": "signature_system", "in_list_view": 1},
        {"fieldname": "mode", "label": "Mode", "fieldtype": "Select", "options": "safe\nfull", "default": "safe", "in_list_view": 1},
        {"fieldname": "status", "label": "Status", "fieldtype": "Select", "options": "Passed\nFailed\nWarning", "in_list_view": 1},
        {"fieldname": "started_at", "label": "Started At", "fieldtype": "Datetime"},
        {"fieldname": "finished_at", "label": "Finished At", "fieldtype": "Datetime", "in_list_view": 1},
        {"fieldname": "total_tests", "label": "Total Tests", "fieldtype": "Int", "in_list_view": 1},
        {"fieldname": "passed_tests", "label": "Passed Tests", "fieldtype": "Int", "in_list_view": 1},
        {"fieldname": "failed_tests", "label": "Failed Tests", "fieldtype": "Int", "in_list_view": 1},
        {"fieldname": "warning_tests", "label": "Warning Tests", "fieldtype": "Int"},
        {"fieldname": "release_ready", "label": "Release Ready", "fieldtype": "Check"},
        {"fieldname": "production_ready", "label": "Production Ready", "fieldtype": "Check"},
        {"fieldname": "result_sha256", "label": "Result SHA256", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "result_json", "label": "Result JSON", "fieldtype": "Code", "options": "JSON"},
    ]

    permissions = [
        perm("System Manager", 1, 0, 0, 0, 1, 1, 1, 1),
        perm("Signature Administrator", 1, 0, 0, 0, 1, 1, 1, 1),
        perm("Signature Manager", 1, 0, 0, 0, 1, 1, 1, 1),
        perm("Signature Auditor", 1, 0, 0, 0, 1, 1, 1, 0),
        perm("Signature Viewer", 1, 0, 0, 0, 0, 0, 1, 0),
    ]

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
        return

    ws = frappe.get_doc("Workspace", name)
    meta = frappe.get_meta("Workspace")

    if meta.has_field("shortcuts"):
        shortcut_meta = frappe.get_meta("Workspace Shortcut")
        existing = {getattr(r, "link_to", None) for r in getattr(ws, "shortcuts", []) or []}

        if "E-Sign Test Run" not in existing:
            row = ws.append("shortcuts", {})

            for key, value in {
                "shortcut_name": "Automated Test Runs",
                "label": "Automated Test Runs",
                "title": "Automated Test Runs",
                "type": "DocType",
                "link_to": "E-Sign Test Run",
                "doc_view": "List",
                "color": "Cyan",
            }.items():
                if shortcut_meta.has_field(key):
                    setattr(row, key, value)

    ws.flags.ignore_mandatory = True
    ws.save(ignore_permissions=True)
    frappe.db.commit()


def apply():
    ensure_test_run_doctype()
    update_workspace()
    print({"ok": True, "phase": "21"})
