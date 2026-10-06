import frappe


MODULE_NAME = "Surhan Signature"


def f(fieldname, label, fieldtype, **kwargs):
    row = {
        "fieldname": fieldname,
        "label": label,
        "fieldtype": fieldtype,
    }
    row.update(kwargs)
    return row


def apply():
    if frappe.db.exists("DocType", "E-Sign Security Event"):
        print("E-Sign Security Event already exists.")
        return

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": "E-Sign Security Event",
        "module": MODULE_NAME,
        "custom": 0,
        "track_changes": 1,
        "autoname": "format:ESIGN-SEC-.YYYY.-.#####",
        "title_field": "event_type",
        "sort_field": "creation",
        "sort_order": "DESC",
        "fields": [
            f("event_type", "Event Type", "Data", reqd=1, in_list_view=1),
            f("severity", "Severity", "Select", options="Low\nMedium\nHigh\nCritical", default="Low", in_list_view=1),
            f("envelope", "Envelope", "Link", options="E-Sign Envelope", in_list_view=1),
            f("recipient_row", "Recipient Row", "Data"),
            f("recipient_email", "Recipient Email", "Data"),
            f("token_hash_prefix", "Token Hash Prefix", "Data"),
            f("timestamp_utc", "Timestamp UTC", "Datetime", reqd=1, in_list_view=1),
            f("ip_address", "IP Address", "Data", in_list_view=1),
            f("user_agent", "User Agent", "Small Text"),
            f("rate_key", "Rate Key", "Data"),
            f("details_json", "Details JSON", "Code", options="JSON"),
        ],
        "permissions": [
            {
                "role": "System Manager",
                "read": 1,
                "write": 0,
                "create": 0,
                "delete": 0,
                "report": 1,
                "export": 1,
                "print": 1,
            },
            {
                "role": "Signature Administrator",
                "read": 1,
                "write": 0,
                "create": 0,
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
        ],
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    print("Created: E-Sign Security Event")
