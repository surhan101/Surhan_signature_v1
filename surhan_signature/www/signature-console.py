import frappe


def _get_csrf_token():
    token = None

    try:
        import frappe.sessions
        token = frappe.sessions.get_csrf_token()
    except Exception:
        token = None

    if not token:
        try:
            token = frappe.local.session.data.get("csrf_token")
        except Exception:
            token = None

    if not token:
        token = frappe.generate_hash()
        try:
            frappe.local.session.data["csrf_token"] = token
        except Exception:
            pass

    return token


def get_context(context):
    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login"
        raise frappe.Redirect

    roles = set(frappe.get_roles() or [])
    allowed = {
        "System Manager",
        "Signature Administrator",
        "Signature Manager",
        "Signature Sender",
        "Signature Auditor",
        "Signature Viewer",
    }

    if not roles.intersection(allowed):
        frappe.throw("You do not have access to Surhan Signature Console.")

    context.no_cache = 1
    context.title = "Surhan Signature Console"
    context.csrf_token = _get_csrf_token()
