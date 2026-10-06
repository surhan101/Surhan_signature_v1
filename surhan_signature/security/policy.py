"""Fail-closed access policy for Surhan Signature API methods."""

APP_PREFIX = "surhan_signature."

PUBLIC_METHODS = frozenset({
    "surhan_signature.api.signing_link_info",
    "surhan_signature.api.request_otp",
    "surhan_signature.api.verify_otp",
    "surhan_signature.api.sign_typed",
    "surhan_signature.api.sign_drawn",
    "surhan_signature.api.sign_uploaded",
    "surhan_signature.api.decline_signing",
    "surhan_signature.api.verify_certificate",
    "surhan_signature.api.public_verify_certificate_bundle",
    "surhan_signature.api.public_verify_page_health",
    "surhan_signature.api.verify_internal_signature_certificate",
    "surhan_signature.api.external_signature_gateway_create_request",
    "surhan_signature.api.external_signature_gateway_status",
})

SELF_SERVICE_METHODS = frozenset({
    "surhan_signature.api.get_my_signature_profile",
    "surhan_signature.api.save_my_signature_profile",
    "surhan_signature.api.revoke_my_signature_profile",
    "surhan_signature.api.get_my_internal_signature_capabilities",
    "surhan_signature.api.get_my_pending_document_signature_requests",
    "surhan_signature.api.phase27g_signature_inbox_data",
    "surhan_signature.api.phase27g_signature_badge_count",
    "surhan_signature.api.phase27g_sync_signature_todos",
    "surhan_signature.api.phase27g_export_signature_inbox_snapshot_json",
})

SIGNATURE_USER_METHODS = frozenset({
    "surhan_signature.api.create_envelope",
    "surhan_signature.api.issue_signing_token",
    "surhan_signature.api.revoke_signing_token",
    "surhan_signature.api.envelope_progress",
    "surhan_signature.api.send_envelope_invites",
    "surhan_signature.api.resend_invite",
    "surhan_signature.api.check_audit_chain",
    "surhan_signature.api.finalize_artifacts",
    "surhan_signature.api.verify_artifacts",
    "surhan_signature.api.envelope_compliance_report",
    "surhan_signature.api.export_envelope_compliance_json",
    "surhan_signature.api.calculate_envelope_risk",
    "surhan_signature.api.export_envelope_risk_report_json",
    "surhan_signature.api.get_document_signature_state",
    "surhan_signature.api.get_document_signature_form_context",
    "surhan_signature.api.get_signed_document_print_context",
    "surhan_signature.api.sync_ac_footer_requests",
    "surhan_signature.api.apply_first_pending_saved_signature_for_document",
    "surhan_signature.api.reject_first_pending_signature_for_document",
    "surhan_signature.api.get_document_signature_request_action_context",
    "surhan_signature.api.apply_saved_signature_request",
    "surhan_signature.api.apply_direction_signature_request",
    "surhan_signature.api.reject_document_signature_request",
    "surhan_signature.api.phase26n_get_classic_signature_context",
    "surhan_signature.api.phase26n_accept_signature_request",
    "surhan_signature.api.phase26n_refuse_signature_request",
    "surhan_signature.api.phase26n_linear_guidance_signature_request",
})

AUDITOR_METHODS = frozenset({
    "surhan_signature.api.debug_security_events",
    "surhan_signature.api.signature_dashboard_summary",
    "surhan_signature.api.signature_dashboard_details",
    "surhan_signature.api.webhook_delivery_summary",
    "surhan_signature.api.signature_system_health",
    "surhan_signature.api.backup_restore_monitoring_status",
    "surhan_signature.api.latest_signature_test_runs",
    "surhan_signature.api.risk_dashboard_summary",
    "surhan_signature.api.risk_current_snapshot",
    "surhan_signature.api.certificate_qr_status",
    "surhan_signature.api.admin_verify_certificate_bundle",
    "surhan_signature.api.phase26j_external_gateway_summary",
    "surhan_signature.api.phase26j_external_gateway_requests",
    "surhan_signature.api.phase26j_external_gateway_request_detail",
    "surhan_signature.api.phase27e_operations_summary",
    "surhan_signature.api.phase27e_pending_requests",
    "surhan_signature.api.phase27e_recent_requests",
    "surhan_signature.api.phase27e_certificate_overview",
    "surhan_signature.api.phase27e_external_gateway_overview",
    "surhan_signature.api.phase27f_admin_audit_logs",
    "surhan_signature.api.phase27f_verify_admin_audit_hash_chain",
    "surhan_signature.api.phase27h_notifications_center_data",
})


def classify(method: str | None) -> str:
    method = (method or "").strip()
    if not method.startswith(APP_PREFIX):
        return "unrelated"
    if method in PUBLIC_METHODS:
        return "public"
    if method in SELF_SERVICE_METHODS:
        return "self"
    if method in SIGNATURE_USER_METHODS:
        return "signature_user"
    if method in AUDITOR_METHODS:
        return "auditor"
    return "admin"
