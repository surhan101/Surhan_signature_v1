import frappe


def get_context(context):
    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/signature-api-security-matrix"
        raise frappe.Redirect

    if frappe.session.user != "Administrator":
        user_roles = set(frappe.get_roles() or [])
        allowed_roles = {
            "System Manager",
            "Internal Signature Administrator",
            "Internal Signature Manager",
            "Internal Signature Auditor",
        }

        if not user_roles.intersection(allowed_roles):
            frappe.local.flags.redirect_location = "/app"
            raise frappe.PermissionError("You are not allowed to access Signature API Security Matrix.")

    context.no_cache = 1
    context.title = "Signature API Security Matrix"

    try:
        context.csrf_token = frappe.sessions.get_csrf_token()
    except Exception:
        context.csrf_token = ""
