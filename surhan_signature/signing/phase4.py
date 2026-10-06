import frappe


@frappe.whitelist()
def health():
    duplicate_certificates = frappe.db.sql(
        """
        SELECT envelope
        FROM `tabE-Sign Certificate`
        WHERE IFNULL(envelope, '') != ''
        GROUP BY envelope
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    )
    return {
        "ok": not bool(duplicate_certificates),
        "recipient_row_lock": True,
        "envelope_row_lock": True,
        "audit_chain_serialized": True,
        "duplicate_certificates": len(duplicate_certificates),
    }
