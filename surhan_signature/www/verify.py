import frappe


def get_context(context):
    context.no_cache = 1
    context.title = "Verify Certificate"
    context.certificate_no = frappe.form_dict.get("certificate_no") or ""
