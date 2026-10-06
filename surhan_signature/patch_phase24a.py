import frappe


def add_field(doc, existing, field):
    if field["fieldname"] not in existing:
        doc.append("fields", field)
        existing.add(field["fieldname"])


def apply():
    doctype = "E-Sign Certificate"

    doc = frappe.get_doc("DocType", doctype)
    existing = {f.fieldname for f in doc.fields}

    fields = [
        {
            "fieldname": "qr_section",
            "label": "QR Verification",
            "fieldtype": "Section Break",
            "collapsible": 1,
        },
        {
            "fieldname": "verification_url",
            "label": "Verification URL",
            "fieldtype": "Data",
            "read_only": 1,
            "in_list_view": 0,
        },
        {
            "fieldname": "verification_qr_svg",
            "label": "Verification QR SVG",
            "fieldtype": "Code",
            "options": "HTML",
            "read_only": 1,
        },
        {
            "fieldname": "verification_qr_pdf",
            "label": "Verification QR PDF",
            "fieldtype": "Attach",
            "read_only": 1,
        },
        {
            "fieldname": "verification_qr_pdf_sha256",
            "label": "Verification QR PDF SHA256",
            "fieldtype": "Data",
            "read_only": 1,
        },
        {
            "fieldname": "verification_qr_generated_at",
            "label": "Verification QR Generated At",
            "fieldtype": "Datetime",
            "read_only": 1,
        },
    ]

    for field in fields:
        add_field(doc, existing, field)

    doc.save(ignore_permissions=True)
    frappe.db.commit()

    print({"ok": True, "phase": "24A", "doctype": doctype})
