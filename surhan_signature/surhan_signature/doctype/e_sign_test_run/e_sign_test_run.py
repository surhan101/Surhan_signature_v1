import frappe
from frappe.model.document import Document
from surhan_signature.signing.naming import next_test_run_name


class ESignTestRun(Document):
    def autoname(self):
        if not self.name:
            self.name = next_test_run_name()

    def validate(self):
        if self.is_new():
            return

        if frappe.flags.in_signature_system_update:
            return

        frappe.throw("E-Sign Test Run is system-managed and cannot be modified manually.")

    def on_trash(self):
        if not frappe.flags.in_signature_system_update:
            frappe.throw("E-Sign Test Run cannot be deleted manually.")
