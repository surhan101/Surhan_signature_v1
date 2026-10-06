import frappe
from frappe.model.document import Document


ALLOWED_CERT_UPDATE_FIELDS = {
    "certificate_pdf",
    "certificate_pdf_sha256",
    "final_hash",
    "original_hash",
    "audit_root_hash",
    "verification_url",
    "artifact_version",
    "artifacts_locked",
    "evidence_package",
    "evidence_package_sha256",
    "last_file_integrity_status",
    "last_verified_at",
    "modified",
    "modified_by",
    "_user_tags",
    "_comments",
    "_assign",
    "_liked_by",
}


class ESignCertificate(Document):
    def validate(self):
        if self.is_new():
            return

        if frappe.flags.in_signature_system_update:
            return

        old = frappe.get_doc(self.doctype, self.name)

        locked_state = bool(getattr(old, "artifacts_locked", 0))

        if not locked_state:
            return

        changed = []

        for df in self.meta.fields:
            fieldname = df.fieldname
            if not fieldname or fieldname in ALLOWED_CERT_UPDATE_FIELDS:
                continue

            if str(old.get(fieldname) or "") != str(self.get(fieldname) or ""):
                changed.append(fieldname)

        if changed:
            frappe.throw(
                "Locked E-Sign Certificates cannot be modified. Blocked fields: "
                + ", ".join(changed)
            )

    def on_trash(self):
        if not frappe.flags.in_signature_system_update:
            frappe.throw("E-Sign Certificate cannot be deleted after creation.")
