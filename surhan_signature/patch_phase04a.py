import frappe


BAD_ENVELOPE = "ESIGN-ENV-.YYYY.-.#####"
BAD_AUDIT = "ESIGN-AUD-.YYYY.-.#####"
BAD_CERT = "ESIGN-CERT-.YYYY.-.#####"


def apply():
    # Remove bad test artifacts created before naming controller fix.
    if frappe.db.exists("E-Sign Envelope", BAD_ENVELOPE):
        for name in frappe.get_all("E-Sign Audit Log", filters={"envelope": BAD_ENVELOPE}, pluck="name"):
            frappe.delete_doc("E-Sign Audit Log", name, force=True, ignore_permissions=True)

        for name in frappe.get_all("E-Sign Certificate", filters={"envelope": BAD_ENVELOPE}, pluck="name"):
            frappe.delete_doc("E-Sign Certificate", name, force=True, ignore_permissions=True)

        frappe.delete_doc("E-Sign Envelope", BAD_ENVELOPE, force=True, ignore_permissions=True)
        print(f"Deleted bad envelope: {BAD_ENVELOPE}")

    for dt, bad_name in [
        ("E-Sign Audit Log", BAD_AUDIT),
        ("E-Sign Certificate", BAD_CERT),
    ]:
        if frappe.db.exists(dt, bad_name):
            frappe.delete_doc(dt, bad_name, force=True, ignore_permissions=True)
            print(f"Deleted bad record: {dt} {bad_name}")

    frappe.db.commit()
    print("Phase 04A cleanup completed.")
