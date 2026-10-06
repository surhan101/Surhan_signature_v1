import frappe
from frappe.model.document import Document
from surhan_signature.signing.naming import next_security_event_name


class ESignSecurityEvent(Document):
    def autoname(self):
        if not self.name:
            self.name = next_security_event_name()

    def validate(self):
        if self.is_new():
            return

        if frappe.flags.in_signature_system_update:
            return

        frappe.throw("E-Sign Security Event is immutable and cannot be modified.")

    def on_trash(self):
        if not frappe.flags.in_signature_system_update:
            frappe.throw("E-Sign Security Event is immutable and cannot be deleted.")
