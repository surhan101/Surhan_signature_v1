import frappe
from frappe.model.document import Document
from surhan_signature.signing.naming import next_envelope_name


ALLOWED_LOCKED_UPDATE_FIELDS = {
    "final_signed_pdf",
    "final_pdf_sha256",
    "audit_root_hash",
    "artifacts_version",
    "artifacts_locked",
    "evidence_package",
    "evidence_package_sha256",
    "certificate_no",
    "completed_on",
    "modified",
    "modified_by",
    "_user_tags",
    "_comments",
    "_assign",
    "_liked_by",
}


class ESignEnvelope(Document):
    def autoname(self):
        if not self.name:
            self.name = next_envelope_name()

    def validate(self):
        if self.is_new():
            return

        old = frappe.get_doc(self.doctype, self.name)

        locked_state = bool(old.locked) or old.status in (
            "Signed",
            "Voided",
            "Expired",
            "Archived",
        )

        if not locked_state:
            return

        if frappe.flags.in_signature_system_update:
            return

        changed = []

        for df in self.meta.fields:
            fieldname = df.fieldname
            if not fieldname or fieldname in ALLOWED_LOCKED_UPDATE_FIELDS:
                continue

            if str(old.get(fieldname) or "") != str(self.get(fieldname) or ""):
                changed.append(fieldname)

        if changed:
            frappe.throw(
                "Signed/locked envelopes are immutable. Blocked changed fields: "
                + ", ".join(changed)
            )
