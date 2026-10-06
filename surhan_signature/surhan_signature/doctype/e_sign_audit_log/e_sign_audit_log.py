import frappe
from frappe.model.document import Document
from surhan_signature.signing.naming import next_audit_log_name


PROTECTED_FIELDS = [
    "envelope",
    "event_type",
    "actor_type",
    "actor_user",
    "actor_email",
    "timestamp_utc",
    "ip_address",
    "user_agent",
    "request_id",
    "details_json",
    "previous_hash",
    "current_hash",
]


class ESignAuditLog(Document):
    def autoname(self):
        if not self.name:
            self.name = next_audit_log_name()

    def validate(self):
        if self.is_new():
            return

        if frappe.flags.in_signature_system_update:
            return

        old = frappe.get_doc(self.doctype, self.name)

        for field in PROTECTED_FIELDS:
            if str(old.get(field) or "") != str(self.get(field) or ""):
                frappe.throw(
                    f"E-Sign Audit Log is immutable. Field '{field}' cannot be modified."
                )

    def on_trash(self):
        if not frappe.flags.in_signature_system_update:
            frappe.throw("E-Sign Audit Log is immutable and cannot be deleted.")
