import frappe


def get_context(context):

    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/signature-inbox"
        raise frappe.Redirect

    context.no_cache = 1
    context.title = "Signature Inbox"

    try:
        context.csrf_token = frappe.sessions.get_csrf_token()
    except Exception:
        context.csrf_token = ""

    context.allowed_roles = ["All authenticated users"]
    context.access_mode = "authenticated"
