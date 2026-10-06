import frappe
from surhan_signature.signing.naming import next_security_event_name


def apply():
    bad = "ESIGN-SEC-.YYYY.-.#####"

    if frappe.db.exists("E-Sign Security Event", bad):
        new_name = next_security_event_name()

        frappe.flags.in_signature_system_update = True
        try:
            frappe.rename_doc(
                "E-Sign Security Event",
                bad,
                new_name,
                force=True,
            )
        finally:
            frappe.flags.in_signature_system_update = False

        frappe.db.commit()
        print(f"Renamed bad Security Event: {bad} -> {new_name}")
    else:
        print("No bad Security Event name found.")

    print("Phase 10A cleanup completed.")
