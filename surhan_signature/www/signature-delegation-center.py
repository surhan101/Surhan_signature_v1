import frappe


def get_context(context):

    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/signature-delegation-center"
        raise frappe.Redirect

    if frappe.session.user != "Administrator":
        user_roles = set(frappe.get_roles() or [])
        allowed_roles = set(["System Manager", "Internal Signature Administrator", "Internal Signature Manager"])
        if not user_roles.intersection(allowed_roles):
            frappe.local.flags.redirect_location = "/app"
            raise frappe.PermissionError("You are not allowed to access Delegation Center.")

    context.no_cache = 1
    context.title = "Delegation Center"

    try:
        context.csrf_token = frappe.sessions.get_csrf_token()
    except Exception:
        context.csrf_token = ""

    context.allowed_roles = ["System Manager", "Internal Signature Administrator", "Internal Signature Manager"]
    context.access_mode = "admin"
