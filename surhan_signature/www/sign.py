import frappe


no_cache = 1


def get_context(context):
    context.no_cache = 1
    context.show_sidebar = False
    context.title = "Surhan Signature"

    token = frappe.form_dict.get("token")
    context.token = token or ""
    context.portal_error = None
    context.portal_data = {}

    if not token:
        context.portal_error = "Missing signing token."
        return context

    try:
        data = frappe.get_attr("surhan_signature.api.signing_link_info")(token=token)
        context.portal_data = data
        for key, value in data.items():
            setattr(context, key, value)
    except Exception:
        messages = frappe.get_message_log()
        context.portal_error = messages[-1].get("message") if messages else "Unable to open signing link."

    return context
