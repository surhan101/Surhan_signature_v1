import frappe
from frappe.model.document import Document
from surhan_signature.signing.naming import next_webhook_endpoint_name


class ESignWebhookEndpoint(Document):
    def autoname(self):
        if not self.name:
            self.name = next_webhook_endpoint_name()
