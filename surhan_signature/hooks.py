app_name = "surhan_signature"
app_title = "Surhan Signature"
app_publisher = "Surhan"
app_description = " Enterprise-grade electronic signature platform for Farabi/Frappe"
app_email = "as@ysmo.org"
app_license = "mit"

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "surhan_signature",
# 		"logo": "/assets/surhan_signature/logo.png",
# 		"title": "Surhan Signature",
# 		"route": "/surhan_signature",
# 		"has_permission": "surhan_signature.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/surhan_signature/css/surhan_signature.css"
# app_include_js = "/assets/surhan_signature/js/surhan_signature.js"

# include js, css files in header of web template
# web_include_css = "/assets/surhan_signature/css/surhan_signature.css"
# web_include_js = "/assets/surhan_signature/js/surhan_signature.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "surhan_signature/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "surhan_signature/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# automatically load and sync documents of this doctype from downstream apps
# importable_doctypes = [doctype_1]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "surhan_signature.utils.jinja_methods",
# 	"filters": "surhan_signature.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "surhan_signature.install.before_install"
# after_install = "surhan_signature.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "surhan_signature.uninstall.before_uninstall"
# after_uninstall = "surhan_signature.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "surhan_signature.utils.before_app_install"
# after_app_install = "surhan_signature.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "surhan_signature.utils.before_app_uninstall"
# after_app_uninstall = "surhan_signature.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "surhan_signature.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"surhan_signature.tasks.all"
# 	],
# 	"daily": [
# 		"surhan_signature.tasks.daily"
# 	],
# 	"hourly": [
# 		"surhan_signature.tasks.hourly"
# 	],
# 	"weekly": [
# 		"surhan_signature.tasks.weekly"
# 	],
# 	"monthly": [
# 		"surhan_signature.tasks.monthly"
# 	],
# }

# Testing
# -------

# before_tests = "surhan_signature.install.before_tests"

# Extend DocType Class
# ------------------------------
#
# Specify custom mixins to extend the standard doctype controller.
# extend_doctype_class = {
# 	"Task": "surhan_signature.custom.task.CustomTaskMixin"
# }

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "surhan_signature.event.get_events"
# }

# Security-critical compatibility layer. Public method paths remain unchanged,
# while requests are routed to the hardened OTP/session implementation.
override_whitelisted_methods = {
	"surhan_signature.api.request_otp": "surhan_signature.secure_otp_api.request_otp",
	"surhan_signature.api.verify_otp": "surhan_signature.secure_otp_api.verify_otp",
	"surhan_signature.api.sign_typed": "surhan_signature.secure_otp_api.sign_typed",
	"surhan_signature.api.sign_drawn": "surhan_signature.secure_otp_api.sign_drawn",
	"surhan_signature.api.sign_uploaded": "surhan_signature.secure_otp_api.sign_uploaded",
}

# Central API authorization guard (Phase 2).
before_request = ["surhan_signature.security.request_guard.enforce"]
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "surhan_signature.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["surhan_signature.utils.before_request"]
# after_request = ["surhan_signature.utils.after_request"]

# Job Events
# ----------
# before_job = ["surhan_signature.utils.before_job"]
# after_job = ["surhan_signature.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"surhan_signature.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }

# Translation
# ------------
# List of apps whose translatable strings should be excluded from this app's translations.
# ignore_translatable_strings_from = []


# Surhan Signature Phase 11 scheduler.
try:
    scheduler_events
except NameError:
    scheduler_events = {}

scheduler_events.setdefault("hourly", [])
if "surhan_signature.api.expire_envelopes" not in scheduler_events["hourly"]:
    scheduler_events["hourly"].append("surhan_signature.api.expire_envelopes")

# Phase 26C: Ac Footer internal signature watcher.
doc_events = globals().get("doc_events", {})
if not isinstance(doc_events, dict):
    doc_events = {}

doc_events.setdefault("*", {})
if not isinstance(doc_events["*"], dict):
    doc_events["*"] = {}

doc_events["*"]["after_insert"] = "surhan_signature.api.phase26c_on_document_update"
doc_events["*"]["on_update"] = "surhan_signature.api.phase26c_on_document_update"

# Phase 26E: Desk form buttons for internal document signatures.
_app_include_js = "/assets/surhan_signature/js/internal_document_signature.js"

try:
    app_include_js
except NameError:
    app_include_js = []

if isinstance(app_include_js, str):
    app_include_js = [app_include_js]

if _app_include_js not in app_include_js:
    app_include_js.append(_app_include_js)



# Phase 27H: automatic signature ToDo notifications.
try:
    doc_events
except NameError:
    doc_events = {}

doc_events.setdefault("Document Signature Request", {})
doc_events["Document Signature Request"].setdefault("after_insert", [])
doc_events["Document Signature Request"].setdefault("on_update", [])

if "surhan_signature.api.phase27h_on_signature_request_update" not in doc_events["Document Signature Request"]["after_insert"]:
    doc_events["Document Signature Request"]["after_insert"].append("surhan_signature.api.phase27h_on_signature_request_update")

if "surhan_signature.api.phase27h_on_signature_request_update" not in doc_events["Document Signature Request"]["on_update"]:
    doc_events["Document Signature Request"]["on_update"].append("surhan_signature.api.phase27h_on_signature_request_update")


try:
    scheduler_events
except NameError:
    scheduler_events = {}

scheduler_events.setdefault("hourly", [])

if "surhan_signature.api.phase27h_scheduled_signature_notifications" not in scheduler_events["hourly"]:
    scheduler_events["hourly"].append("surhan_signature.api.phase27h_scheduled_signature_notifications")


# Phase 27I: automatic signature delegation scheduler.
try:
    scheduler_events
except NameError:
    scheduler_events = {}

scheduler_events.setdefault("hourly", [])

if "surhan_signature.api.phase27i_scheduled_apply_delegations" not in scheduler_events["hourly"]:
    scheduler_events["hourly"].append("surhan_signature.api.phase27i_scheduled_apply_delegations")

web_include_js = [
    "/assets/surhan_signature/frontend/signature-center/assets/index-D42meroR.js"
]

web_include_css = [
    "/assets/surhan_signature/frontend/signature-center/assets/index-CsUDhMuy.css"
]