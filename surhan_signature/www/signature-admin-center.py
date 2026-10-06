# -*- coding: utf-8 -*-
"""
Surhan Signature - Unified Admin Control Center Page Controller
Zero-Trust Access Enforcement: Strictly restricted to System Manager & Administrator.
"""

import frappe
from frappe import _


def get_context(context):
    user = frappe.session.user
    if not user or user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/signature-admin-center"
        raise frappe.Redirect

    roles = frappe.get_roles(user)
    if "System Manager" not in roles and user != "Administrator":
        frappe.throw(
            _("⛔ وصول محظور: لوحة التحكم الإدارية المركزية مخصصة حصرياً لمسؤولي النظام (System Managers)."),
            frappe.PermissionError
        )

    context.no_cache = 1
    context.title = _("Surhan Signature | لوحة التحكم الإدارية الموحدة")
    context.user_full_name = frappe.utils.get_fullname(user)
    context.user_email = user
    context.csrf_token = frappe.sessions.get_csrf_token()
    context.system_version = "v2.0 Enterprise"
    context.base_url = frappe.utils.get_url()

    return context
