import frappe


no_cache = 1


def get_context(context):
    context.no_cache = 1
    context.show_sidebar = False
    context.title = "Surhan Signature Dashboard"

    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/signature-dashboard"
        raise frappe.Redirect

    return context
