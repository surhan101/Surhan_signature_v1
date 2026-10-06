import json
import base64
import re
import frappe
from frappe import _
from frappe.utils import add_to_date, now_datetime, get_url
from frappe.utils.file_manager import save_file
from surhan_signature.signing.crypto import sha256_hex, secure_token_urlsafe, token_hash
from surhan_signature.signing.audit import add_audit, verify_audit_chain
from surhan_signature.signing.otp import set_otp_for_recipient, verify_recipient_otp
from surhan_signature.signing.naming import next_certificate_no
from surhan_signature.signing.security import safe_document_html, mask_email, production_safe_dev_value
from surhan_signature.security.content import decode_signature_image, sanitize_document_html
from surhan_signature.security.outbound import safe_post, validate_outbound_url


def _parse_json(value, default=None):
    if default is None:
        default = []
    if not value:
        return default
    if isinstance(value, str):
        return frappe.parse_json(value)
    return value


def _settings():
    try:
        return frappe.get_single("E-Sign Settings")
    except Exception:
        return None


def _recipient_public_status(row) -> dict:
    return {
        "name": row.get("name"),
        "signer_name": row.get("signer_name"),
        "signer_email_masked": mask_email(row.get("signer_email")),
        "role": row.get("role"),
        "status": row.get("status"),
        "sign_order": row.get("sign_order"),
    }


def _get_recipient_by_token(raw_token: str):
    if not raw_token:
        return None

    digest = token_hash(raw_token)

    rows = frappe.get_all(
        "E-Sign Recipient",
        filters={"token_hash": digest},
        fields=[
            "name",
            "parent",
            "signer_email",
            "signer_name",
            "status",
            "token_expires_at",
            "role",
            "sign_order",
            "otp_verified",
        ],
        limit=1,
    )

    if not rows:
        return None

    return rows[0]




def _get_child_recipient(env, recipient_row_name: str):
    for r in env.recipients:
        if r.name == recipient_row_name:
            return r
    return None


def _recipient_can_sign(env, recipient_row_name: str) -> tuple[bool, str]:
    """
    Enforce signing order.
    Parallel: every active signer can sign.
    Sequential/Mixed: only the lowest pending sign_order can sign.
    """
    target = _get_child_recipient(env, recipient_row_name)
    if not target:
        return False, "Recipient is not part of this envelope."

    if target.status == "Signed":
        return False, "This recipient has already signed."

    if target.status in ("Declined", "Expired"):
        return False, "This recipient is no longer allowed to sign."

    if env.status in ("Signed", "Voided", "Expired", "Archived"):
        return False, f"Envelope is {env.status}."

    if env.workflow_type == "Parallel":
        return True, "Recipient can sign."

    active_roles = ("Signer", "Approver", "Witness")
    pending_orders = []

    for r in env.recipients:
        if r.role in active_roles and r.status != "Signed":
            pending_orders.append(int(r.sign_order or 1))

    if not pending_orders:
        return False, "No pending signing step."

    current_order = min(pending_orders)
    target_order = int(target.sign_order or 1)

    if target_order != current_order:
        return False, f"Waiting for signing order {current_order} before this recipient can sign."

    return True, "Recipient can sign."




def _decode_data_url(data_url: str) -> tuple[str, bytes]:
    """
    Decode a browser data URL such as:
    data:image/png;base64,....
    """
    if not data_url or not isinstance(data_url, str):
        frappe.throw(_("Signature image data is required"))

    match = re.match(r"^data:(image/(png|jpeg|jpg));base64,(.+)$", data_url, re.I | re.S)
    if not match:
        frappe.throw(_("Only PNG/JPEG signature images are allowed"))

    mime_type = match.group(1).lower()
    ext = "jpg" if mime_type in ("image/jpeg", "image/jpg") else "png"
    raw = base64.b64decode(match.group(3), validate=True)

    if len(raw) > 2 * 1024 * 1024:
        frappe.throw(_("Signature image is too large. Maximum allowed size is 2MB."))

    return ext, raw


def _save_private_signature_file(env_name: str, recipient_name: str, raw: bytes, ext: str, method: str) -> str:
    digest = sha256_hex(raw)
    file_name = f"{env_name}-{recipient_name}-{method}-{digest[:12]}.{ext}"

    saved = save_file(
        fname=file_name,
        content=raw,
        dt="E-Sign Envelope",
        dn=env_name,
        folder=None,
        is_private=1,
    )

    return saved.file_url


def _complete_signature(
    token: str,
    signature_method: str,
    consent_accepted: int,
    signature_text: str | None = None,
    signature_image: str | None = None,
    evidence_hash: str | None = None,
):
    row = _get_recipient_by_token(token)
    _ensure_token_active(row)

    if not int(consent_accepted):
        frappe.throw(_("Consent must be accepted before signing"))

    env = frappe.get_doc("E-Sign Envelope", row.parent)
    can_sign, can_sign_reason = _recipient_can_sign(env, row.name)

    if not can_sign:
        frappe.throw(_(can_sign_reason))

    latest = frappe.db.get_value(
        "E-Sign Recipient",
        row.name,
        ["otp_verified", "status"],
        as_dict=True,
    )

    if not latest or not latest.otp_verified:
        frappe.throw(_("OTP verification is required before signing"))

    if signature_method == "Typed" and not signature_text:
        frappe.throw(_("Signature text is required"))

    if signature_method in ("Drawn", "Uploaded") and not signature_image:
        frappe.throw(_("Signature image is required"))

    now = now_datetime()

    update_values = {
        "status": "Signed",
        "signed_at": now,
        "signature_method": signature_method,
        "consent_text_snapshot": "I agree to sign this document electronically and understand that my electronic signature is legally binding where applicable.",
    }

    if signature_text:
        update_values["signature_text"] = signature_text

    if signature_image:
        update_values["signature_image"] = signature_image

    frappe.db.set_value("E-Sign Recipient", row.name, update_values)

    add_audit(
        envelope=env.name,
        event_type="recipient.signed",
        actor_type="External Signer",
        actor_email=row.signer_email,
        details={
            "recipient": row.name,
            "signature_method": signature_method,
            "signed_at": str(now),
            "signature_image": signature_image,
            "signature_text_present": bool(signature_text),
            "evidence_hash": evidence_hash,
        },
    )

    env.reload()

    required = [r for r in env.recipients if r.role in ("Signer", "Approver", "Witness")]
    all_signed = all(r.status == "Signed" for r in required)

    if all_signed:
        cert_no = make_certificate(env.name)

        env.status = "Signed"
        env.completed_on = now_datetime()
        env.locked = 1
        env.certificate_no = cert_no
        env.save(ignore_permissions=True)

        add_audit(
            envelope=env.name,
            event_type="envelope.completed",
            actor_type="System",
            details={
                "certificate_no": cert_no,
            },
        )

        try:
            from surhan_signature.signing.pdf import finalize_envelope_artifacts
            artifacts = finalize_envelope_artifacts(env.name)
            add_audit(
                envelope=env.name,
                event_type="envelope.artifacts_generated",
                actor_type="System",
                details=artifacts,
            )
        except Exception:
            frappe.log_error(frappe.get_traceback(), "Surhan Signature Final Artifact Generation Failed")
            artifacts = {
                "ok": False,
                "error": "Final artifact generation failed. Check Error Log."
            }

        latest_chain = verify_audit_chain(env.name)
        frappe.db.set_value("E-Sign Envelope", env.name, "audit_root_hash", latest_chain.get("latest_hash"))

        cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": env.name})
        if cert_name:
            frappe.db.set_value("E-Sign Certificate", cert_name, "audit_root_hash", latest_chain.get("latest_hash"))

        env.reload()
    else:
        env.status = "Partially Signed"
        env.save(ignore_permissions=True)

    frappe.db.commit()

    return {
        "ok": True,
        "envelope": env.name,
        "status": env.status,
        "completed": all_signed,
        "certificate_no": env.certificate_no,
        "signature_method": signature_method,
        "signature_image": signature_image,
        "evidence_hash": evidence_hash,
    }




@frappe.whitelist()
def health():
    return {
        "ok": True,
        "app": "surhan_signature",
        "time": now_datetime(),
        "message": "Surhan Signature API is alive",
    }


@frappe.whitelist()
def create_envelope(
    title: str,
    document_html: str | None = None,
    recipients=None,
    signing_level: str = "SES",
    workflow_type: str = "Sequential",
    category: str = "Legal",
    expires_days: int | None = None,
):
    recipients = _parse_json(recipients, [])

    if not title:
        frappe.throw(_("Title is required"))

    if not recipients:
        frappe.throw(_("At least one recipient is required"))

    settings = _settings()
    if expires_days is None:
        expires_days = int(getattr(settings, "default_expiry_days", 7) or 7)

    try:
        document_html = sanitize_document_html(document_html)
    except ValueError as exc:
        frappe.throw(str(exc))

    canonical_payload = {
        "title": title,
        "document_html": document_html or "",
        "recipients": recipients,
        "signing_level": signing_level,
        "workflow_type": workflow_type,
    }

    env = frappe.get_doc({
        "doctype": "E-Sign Envelope",
        "title": title,
        "status": "Draft",
        "signing_level": signing_level,
        "workflow_type": workflow_type,
        "category": category,
        "document_html": document_html or "",
        "canonical_sha256": sha256_hex(canonical_payload),
        "expires_on": add_to_date(now_datetime(), days=int(expires_days)),
        "recipients": [],
    })

    for idx, r in enumerate(recipients, start=1):
        env.append("recipients", {
            "signer_name": r.get("signer_name") or r.get("name"),
            "signer_email": r.get("signer_email") or r.get("email"),
            "signer_phone": r.get("signer_phone") or r.get("phone"),
            "role": r.get("role") or "Signer",
            "sign_order": int(r.get("sign_order") or idx),
            "status": "Pending",
        })

    env.insert()
    add_audit(
        envelope=env.name,
        event_type="envelope.created",
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details={
            "title": title,
            "recipient_count": len(recipients),
            "signing_level": signing_level,
            "workflow_type": workflow_type,
        },
    )
    frappe.db.commit()

    return {
        "ok": True,
        "envelope": env.name,
        "canonical_sha256": env.canonical_sha256,
        "status": env.status,
    }


@frappe.whitelist()
def issue_signing_token(envelope: str, signer_email: str):
    """
    Issue a secure signing token for one recipient.

    Important:
    We update the child row on the loaded parent document, then save the parent.
    Do not call frappe.db.set_value on the child row before env.save(), because
    saving the parent can overwrite child-table changes from stale in-memory rows.
    """
    if not envelope or not signer_email:
        frappe.throw(_("Envelope and signer_email are required"))

    env = frappe.get_doc("E-Sign Envelope", envelope)

    if env.status in ("Signed", "Voided", "Expired", "Archived"):
        frappe.throw(_(f"Cannot issue signing token while envelope status is {env.status}"))

    target = None
    for row in env.recipients:
        if row.signer_email == signer_email:
            target = row
            break

    if not target:
        frappe.throw(_("Recipient not found in envelope"))

    if target.status == "Signed":
        frappe.throw(_("Recipient has already signed"))

    raw_token = secure_token_urlsafe(48)
    digest = token_hash(raw_token)

    settings = _settings()
    expiry_days = int(getattr(settings, "default_expiry_days", 7) or 7)

    # Save child-row values through the parent document to avoid overwrite.
    target.token_hash = digest
    target.token_expires_at = add_to_date(now_datetime(), days=expiry_days)
    target.status = "Invited"

    if env.status in ("Draft", "Prepared"):
        env.status = "Sent"
        env.sent_on = now_datetime()

    env.save(ignore_permissions=True)

    signing_url = f"{get_url()}/sign?token={raw_token}"

    add_audit(
        envelope=envelope,
        event_type="recipient.token_issued",
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details={
            "recipient_email": signer_email,
            "recipient_row": target.name,
            "token_hash": digest,
            "expires_days": expiry_days,
            "portal": "/sign",
        },
    )
    frappe.db.commit()

    return {
        "ok": True,
        "envelope": envelope,
        "recipient_row": target.name,
        "signer_email": signer_email,
        "signing_url": signing_url,
        "token_hash_prefix": digest[:12],
        "warning": "Development output. Later this link will be delivered by email/SMS and hidden from logs.",
    }







@frappe.whitelist(allow_guest=True)
def sign_typed(token: str, signature_text: str, consent_accepted: int = 0):
    return _complete_signature(
        token=token,
        signature_method="Typed",
        consent_accepted=consent_accepted,
        signature_text=signature_text,
    )


@frappe.whitelist(allow_guest=True)
def sign_drawn(token: str, signature_data_url: str, consent_accepted: int = 0):
    row = _get_recipient_by_token(token)
    _ensure_token_active(row)

    ext, raw = _decode_data_url(signature_data_url)
    evidence_hash = sha256_hex(raw)
    file_url = _save_private_signature_file(row.parent, row.name, raw, ext, "drawn")

    return _complete_signature(
        token=token,
        signature_method="Drawn",
        consent_accepted=consent_accepted,
        signature_image=file_url,
        evidence_hash=evidence_hash,
    )


@frappe.whitelist(allow_guest=True)
def sign_uploaded(token: str, file_name: str, file_base64: str, consent_accepted: int = 0):
    row = _get_recipient_by_token(token)
    _ensure_token_active(row)

    try:
        ext, raw = decode_signature_image(file_name, file_base64)
    except ValueError as exc:
        frappe.throw(str(exc))

    evidence_hash = sha256_hex(raw)
    file_url = _save_private_signature_file(row.parent, row.name, raw, ext, "uploaded")

    return _complete_signature(
        token=token,
        signature_method="Uploaded",
        consent_accepted=consent_accepted,
        signature_image=file_url,
        evidence_hash=evidence_hash,
    )

def make_certificate(envelope: str) -> str:
    env = frappe.get_doc("E-Sign Envelope", envelope)

    existing = frappe.db.exists("E-Sign Certificate", {"envelope": envelope})
    if existing:
        return frappe.db.get_value("E-Sign Certificate", existing, "certificate_no")

    settings = _settings()
    prefix = getattr(settings, "certificate_prefix", "ESIGN-CERT") or "ESIGN-CERT"

    cert_no = next_certificate_no(prefix)

    signer_summary = []
    for r in env.recipients:
        signer_summary.append({
            "name": r.signer_name,
            "email": r.signer_email,
            "role": r.role,
            "status": r.status,
            "signed_at": str(r.signed_at) if r.signed_at else None,
            "signature_method": r.signature_method,
        })

    chain = verify_audit_chain(envelope)

    cert = frappe.get_doc({
        "doctype": "E-Sign Certificate",
        "certificate_no": cert_no,
        "envelope": envelope,
        "completed_at": now_datetime(),
        "original_hash": env.canonical_sha256,
        "final_hash": env.final_pdf_sha256,
        "audit_root_hash": chain.get("latest_hash"),
        "signer_summary": json.dumps(signer_summary, ensure_ascii=False, sort_keys=True, default=str),
        "verification_url": f"{get_url()}/verify?certificate_no={cert_no}",
    })

    cert.insert(ignore_permissions=True)

    add_audit(
        envelope=envelope,
        event_type="certificate.generated",
        actor_type="System",
        details={
            "certificate_no": cert_no,
            "audit_root_hash": chain.get("latest_hash"),
        },
    )

    return cert_no


@frappe.whitelist()
def check_audit_chain(envelope: str):
    return verify_audit_chain(envelope)



@frappe.whitelist()
def debug_recipient_tokens(envelope: str):
    """
    Development/admin diagnostic only.
    Shows whether token_hash is actually stored on recipient child rows.
    """
    if not frappe.conf.get("developer_mode"):
        frappe.throw(_("debug_recipient_tokens is available only in developer_mode"))

    env = frappe.get_doc("E-Sign Envelope", envelope)

    rows = []
    for r in env.recipients:
        rows.append({
            "row": r.name,
            "email": r.signer_email,
            "status": r.status,
            "token_hash_present": bool(r.token_hash),
            "token_hash_prefix": (r.token_hash or "")[:12],
            "token_expires_at": r.token_expires_at,
        })

    return {
        "ok": True,
        "envelope": envelope,
        "status": env.status,
        "recipients": rows,
    }




# Phase 08 override: artifact versioning + evidence package + file integrity verification.
@frappe.whitelist()
def finalize_artifacts(envelope: str, force: int = 0):
    from surhan_signature.signing.pdf import finalize_envelope_artifacts, verify_artifact_files

    artifacts = finalize_envelope_artifacts(envelope, force=bool(int(force or 0)))

    event_type = "envelope.artifacts_checked"
    if not artifacts.get("already_finalized"):
        event_type = "envelope.artifacts_generated"

    add_audit(
        envelope=envelope,
        event_type=event_type,
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details=artifacts,
    )

    latest_chain = verify_audit_chain(envelope)
    frappe.db.set_value("E-Sign Envelope", envelope, "audit_root_hash", latest_chain.get("latest_hash"))

    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": envelope})
    if cert_name:
        frappe.db.set_value("E-Sign Certificate", cert_name, "audit_root_hash", latest_chain.get("latest_hash"))

    file_integrity = verify_artifact_files(envelope)

    frappe.db.commit()

    artifacts["audit_chain"] = verify_audit_chain(envelope)
    artifacts["file_integrity"] = file_integrity
    return artifacts


@frappe.whitelist()
def verify_artifacts(envelope: str):
    from surhan_signature.signing.pdf import verify_artifact_files

    result = verify_artifact_files(envelope)

    add_audit(
        envelope=envelope,
        event_type="envelope.artifacts_verified",
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details=result,
    )

    latest_chain = verify_audit_chain(envelope)
    frappe.db.set_value("E-Sign Envelope", envelope, "audit_root_hash", latest_chain.get("latest_hash"))

    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": envelope})
    if cert_name:
        frappe.db.set_value("E-Sign Certificate", cert_name, "audit_root_hash", latest_chain.get("latest_hash"))

    frappe.db.commit()

    result["audit_chain"] = verify_audit_chain(envelope)
    return result




# Phase 09 override: verification must not mutate public records; system updates are flagged.
@frappe.whitelist(allow_guest=True)
def verify_certificate(certificate_no: str):
    from surhan_signature.signing.pdf import verify_artifact_files

    cert_name = frappe.db.exists("E-Sign Certificate", {"certificate_no": certificate_no})
    if not cert_name:
        return {
            "ok": False,
            "valid": False,
            "message": "Certificate not found",
        }

    cert = frappe.get_doc("E-Sign Certificate", cert_name)
    chain = verify_audit_chain(cert.envelope)

    try:
        file_integrity = verify_artifact_files(cert.envelope, update_status=False)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Public Verification File Integrity Failed")
        file_integrity = {
            "all_files_ok": False,
            "error": "Unable to verify artifact files.",
        }

    return {
        "ok": True,
        "valid": bool(chain.get("valid")) and bool(file_integrity.get("all_files_ok")),
        "audit_chain_valid": bool(chain.get("valid")),
        "file_integrity_valid": bool(file_integrity.get("all_files_ok")),
        "certificate_no": cert.certificate_no,
        "envelope": cert.envelope,
        "completed_at": cert.completed_at,
        "original_hash": cert.original_hash,
        "final_hash": cert.final_hash,
        "audit_root_hash": cert.audit_root_hash,
        "certificate_pdf": cert.certificate_pdf,
        "certificate_pdf_sha256": getattr(cert, "certificate_pdf_sha256", None),
        "evidence_package": getattr(cert, "evidence_package", None),
        "evidence_package_sha256": getattr(cert, "evidence_package_sha256", None),
        "audit_chain": chain,
        "file_integrity": file_integrity,
        "verification_url": cert.verification_url,
    }


@frappe.whitelist()
def test_audit_immutability(envelope: str):
    """
    Development safety test.
    Attempts to modify the latest audit log. Expected result: blocked.
    """
    if not frappe.conf.get("developer_mode"):
        frappe.throw("This test is allowed only in developer_mode.")

    latest = frappe.get_all(
        "E-Sign Audit Log",
        filters={"envelope": envelope},
        fields=["name", "event_type"],
        order_by="creation desc",
        limit=1,
    )

    if not latest:
        return {
            "ok": False,
            "message": "No audit logs found.",
        }

    name = latest[0].name

    try:
        doc = frappe.get_doc("E-Sign Audit Log", name)
        doc.event_type = "tampered.event"
        doc.save(ignore_permissions=True)
        return {
            "ok": False,
            "blocked": False,
            "message": "Audit log modification unexpectedly succeeded.",
            "audit_log": name,
        }
    except Exception as exc:
        return {
            "ok": True,
            "blocked": True,
            "message": str(exc),
            "audit_log": name,
        }


@frappe.whitelist()
def test_envelope_lock(envelope: str):
    """
    Development safety test.
    Attempts to modify a signed/locked envelope's title. Expected result: blocked.
    """
    if not frappe.conf.get("developer_mode"):
        frappe.throw("This test is allowed only in developer_mode.")

    try:
        doc = frappe.get_doc("E-Sign Envelope", envelope)
        old_title = doc.title
        doc.title = old_title + " TAMPER"
        doc.save(ignore_permissions=True)
        return {
            "ok": False,
            "blocked": False,
            "message": "Envelope modification unexpectedly succeeded.",
            "envelope": envelope,
        }
    except Exception as exc:
        return {
            "ok": True,
            "blocked": True,
            "message": str(exc),
            "envelope": envelope,
        }


# Phase 10 override: rate limiting, OTP hardening, token revocation, and security events.
from surhan_signature.signing.rate_limit import enforce_rate_limit, hit_rate_limit
from surhan_signature.signing.security_events import add_security_event
from surhan_signature.signing.audit import get_request_ip


def _phase10_token_prefix(token: str | None) -> str:
    if not token:
        return ""
    try:
        return token_hash(token)[:12]
    except Exception:
        return ""


def _phase10_identity(scope: str, token: str | None = None, email: str | None = None) -> str:
    ip = get_request_ip()
    token_part = _phase10_token_prefix(token)
    return f"{scope}:{ip}:{token_part}:{email or ''}"


def _phase10_rate(
    scope: str,
    token: str | None = None,
    email: str | None = None,
    limit: int = 10,
    window_seconds: int = 600,
    envelope: str | None = None,
    recipient_row: str | None = None,
    severity: str = "Medium",
):
    identity = _phase10_identity(scope, token=token, email=email)
    result = hit_rate_limit(scope, identity, limit, window_seconds)

    if not result.get("allowed"):
        add_security_event(
            event_type=f"rate_limit.{scope}",
            severity=severity,
            envelope=envelope,
            recipient_row=recipient_row,
            recipient_email=email,
            token_hash_prefix=_phase10_token_prefix(token),
            rate_key=result.get("key"),
            details=result,
        )
        frappe.throw(
            _("Too many attempts. Please wait before trying again."),
            title=_("Rate limit exceeded"),
        )

    return result


# Override active-token check to treat Failed as inactive.
def _ensure_token_active(row):
    if not row:
        add_security_event(
            event_type="signing.invalid_token",
            severity="Medium",
            details={"reason": "No recipient found for token."},
        )
        frappe.throw(_("Invalid signing link"))

    if row.status in ("Signed", "Declined", "Expired", "Failed"):
        add_security_event(
            event_type="signing.inactive_token_used",
            severity="Medium",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            details={"recipient_status": row.status},
        )
        frappe.throw(_("This signing link is no longer active"))

    if row.token_expires_at and now_datetime() > frappe.utils.get_datetime(row.token_expires_at):
        frappe.db.set_value("E-Sign Recipient", row.name, "status", "Expired")
        add_audit(
            envelope=row.parent,
            event_type="recipient.token_expired",
            actor_type="External Signer",
            actor_email=row.signer_email,
            details={"recipient": row.name},
        )
        add_security_event(
            event_type="signing.expired_token_used",
            severity="Medium",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
        )
        frappe.db.commit()
        frappe.throw(_("This signing link has expired"))


@frappe.whitelist(allow_guest=True)
def signing_link_info(token: str):
    _phase10_rate(
        scope="signing_link_open",
        token=token,
        limit=30,
        window_seconds=600,
        severity="Medium",
    )

    row = _get_recipient_by_token(token)

    if not row:
        add_security_event(
            event_type="signing.invalid_token",
            severity="Medium",
            token_hash_prefix=_phase10_token_prefix(token),
            details={"operation": "signing_link_info"},
        )
        frappe.throw(_("Invalid signing link"))

    _ensure_token_active(row)

    env = frappe.get_doc("E-Sign Envelope", row.parent)
    can_sign, can_sign_reason = _recipient_can_sign(env, row.name)

    current_status = frappe.db.get_value("E-Sign Recipient", row.name, "status")
    if current_status in ("Pending", "Invited"):
        frappe.db.set_value("E-Sign Recipient", row.name, {
            "status": "Viewed",
            "viewed_at": now_datetime(),
        })

    add_audit(
        envelope=env.name,
        event_type="recipient.link_opened",
        actor_type="External Signer",
        actor_email=row.signer_email,
        details={
            "recipient": row.name,
            "can_sign": can_sign,
            "can_sign_reason": can_sign_reason,
            "phase10_rate_limited": True,
        },
    )
    frappe.db.commit()

    env.reload()
    target = _get_child_recipient(env, row.name)

    return {
        "ok": True,
        "envelope": env.name,
        "title": env.title,
        "status": env.status,
        "workflow_type": env.workflow_type,
        "signing_level": env.signing_level,
        "signer_name": row.signer_name,
        "signer_email_masked": mask_email(row.signer_email),
        "recipient_status": target.status if target else row.status,
        "document_html": safe_document_html(env.document_html),
        "canonical_sha256": env.canonical_sha256,
        "expires_on": env.expires_on,
        "requires_otp": True,
        "can_sign": can_sign,
        "can_sign_reason": can_sign_reason,
        "recipients": [_recipient_public_status(r.as_dict()) for r in env.recipients],
    }




@frappe.whitelist(allow_guest=True)
def verify_otp(token: str, otp: str):
    row = _get_recipient_by_token(token)

    if not row:
        _phase10_rate(
            scope="otp_verify_invalid_token",
            token=token,
            limit=5,
            window_seconds=600,
            severity="High",
        )
        add_security_event(
            event_type="otp.invalid_token_verify",
            severity="High",
            token_hash_prefix=_phase10_token_prefix(token),
        )
        frappe.throw(_("Invalid signing link"))

    _phase10_rate(
        scope="otp_verify",
        token=token,
        email=row.signer_email,
        limit=10,
        window_seconds=600,
        envelope=row.parent,
        recipient_row=row.name,
        severity="High",
    )

    _ensure_token_active(row)

    settings = _settings()
    max_attempts = int(getattr(settings, "max_otp_attempts", 5) or 5)

    ok = verify_recipient_otp(row.name, otp, max_attempts=max_attempts)

    recipient_after = frappe.db.get_value(
        "E-Sign Recipient",
        row.name,
        ["otp_attempts", "otp_verified"],
        as_dict=True,
    )

    attempts = int((recipient_after or {}).get("otp_attempts") or 0)

    if ok:
        frappe.db.set_value("E-Sign Recipient", row.name, "status", "OTP Verified")
        event_type = "recipient.otp_verified"
        severity = "Low"
    else:
        event_type = "recipient.otp_failed"
        severity = "Medium"

    add_audit(
        envelope=row.parent,
        event_type=event_type,
        actor_type="External Signer",
        actor_email=row.signer_email,
        details={
            "recipient": row.name,
            "ok": ok,
            "attempts": attempts,
            "max_attempts": max_attempts,
            "phase10_rate_limited": True,
        },
    )

    add_security_event(
        event_type="otp.verified" if ok else "otp.failed",
        severity=severity,
        envelope=row.parent,
        recipient_row=row.name,
        recipient_email=row.signer_email,
        token_hash_prefix=_phase10_token_prefix(token),
        details={"ok": ok, "attempts": attempts, "max_attempts": max_attempts},
    )

    if not ok and attempts >= max_attempts:
        frappe.db.set_value("E-Sign Recipient", row.name, {
            "status": "Failed",
            "token_hash": "",
            "token_expires_at": now_datetime(),
        })

        add_audit(
            envelope=row.parent,
            event_type="recipient.otp_locked",
            actor_type="System",
            actor_email=row.signer_email,
            details={
                "recipient": row.name,
                "attempts": attempts,
                "max_attempts": max_attempts,
                "token_revoked": True,
            },
        )

        add_security_event(
            event_type="otp.locked_token_revoked",
            severity="High",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=_phase10_token_prefix(token),
            details={"attempts": attempts, "max_attempts": max_attempts},
        )

    frappe.db.commit()

    return {
        "ok": ok,
        "verified": ok,
        "attempts": attempts,
        "max_attempts": max_attempts,
        "locked": bool((not ok) and attempts >= max_attempts),
    }


@frappe.whitelist()
def revoke_signing_token(envelope: str, signer_email: str, reason: str = "Manual revocation"):
    from surhan_signature.signing.lifecycle import normalize_lifecycle_reason
    from surhan_signature.signing.transaction import lock_lifecycle_scope

    env = frappe.get_doc("E-Sign Envelope", envelope)

    target = None
    for row in env.recipients:
        if row.signer_email == signer_email:
            target = row
            break

    if not target:
        frappe.throw(_("Recipient not found in envelope"))

    lock_lifecycle_scope(target.name, env.name)
    env = frappe.get_doc("E-Sign Envelope", envelope)
    target = _get_child_recipient(env, target.name)
    try:
        reason = normalize_lifecycle_reason(reason, "Manual revocation")
    except ValueError as exc:
        frappe.throw(_(str(exc)))

    old_hash_prefix = (target.token_hash or "")[:12]

    target.token_hash = ""
    target.token_expires_at = now_datetime()
    if target.status not in ("Signed", "Declined", "Expired", "Failed"):
        target.status = "Expired"

    env.save(ignore_permissions=True)

    add_audit(
        envelope=envelope,
        event_type="recipient.token_revoked",
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details={
            "recipient": target.name,
            "signer_email": signer_email,
            "reason": reason,
            "old_token_hash_prefix": old_hash_prefix,
        },
    )

    add_security_event(
        event_type="token.revoked",
        severity="Medium",
        envelope=envelope,
        recipient_row=target.name,
        recipient_email=signer_email,
        token_hash_prefix=old_hash_prefix,
        details={"reason": reason},
    )

    frappe.db.commit()

    return {
        "ok": True,
        "envelope": envelope,
        "recipient_row": target.name,
        "signer_email": signer_email,
        "status": target.status,
        "revoked": True,
    }


@frappe.whitelist()
def debug_security_events(envelope: str | None = None, limit: int = 20):
    if not frappe.conf.get("developer_mode"):
        frappe.throw(_("debug_security_events is available only in developer_mode"))

    filters = {}
    if envelope:
        filters["envelope"] = envelope

    rows = frappe.get_all(
        "E-Sign Security Event",
        filters=filters,
        fields=[
            "name",
            "event_type",
            "severity",
            "envelope",
            "recipient_email",
            "token_hash_prefix",
            "ip_address",
            "timestamp_utc",
            "details_json",
        ],
        order_by="creation desc",
        limit=int(limit or 20),
    )

    return {
        "ok": True,
        "count": len(rows),
        "events": rows,
    }


# Phase 11: multi-signer workflow, resend invite, decline signing, expiry scheduler.
def _phase11_terminal_envelope_statuses():
    return ("Signed", "Voided", "Expired", "Archived", "Declined")


def _phase11_active_roles():
    return ("Signer", "Approver", "Witness")


def _phase11_recipient_pending(row) -> bool:
    return row.role in _phase11_active_roles() and row.status not in (
        "Signed",
        "Declined",
        "Expired",
        "Failed",
    )


def _phase11_current_recipients(env):
    pending = [r for r in env.recipients if _phase11_recipient_pending(r)]

    if not pending:
        return []

    if env.workflow_type == "Parallel":
        return pending

    current_order = min(int(r.sign_order or 1) for r in pending)
    return [r for r in pending if int(r.sign_order or 1) == current_order]




def _phase11_issue_token_for_row(env, row, reason: str = "send_invite"):
    raw_token = secure_token_urlsafe(48)
    digest = token_hash(raw_token)

    settings = _settings()
    expiry_days = int(getattr(settings, "default_expiry_days", 7) or 7)

    row.token_hash = digest
    row.token_expires_at = add_to_date(now_datetime(), days=expiry_days)
    row.status = "Invited"
    row.last_token_hash_prefix = digest[:12]
    row.last_invite_sent_at = now_datetime()
    row.invite_count = int(row.invite_count or 0) + 1

    signing_url = f"{get_url()}/sign?token={raw_token}"

    delivery = _phase11_send_invite_email(
        recipient_email=row.signer_email,
        signer_name=row.signer_name,
        envelope_title=env.title,
        signing_url=signing_url,
    )

    row.last_invite_delivery_status = json.dumps(delivery, ensure_ascii=False, sort_keys=True, default=str)

    return {
        "recipient_row": row.name,
        "signer_name": row.signer_name,
        "signer_email": row.signer_email,
        "sign_order": row.sign_order,
        "status": row.status,
        "token_hash_prefix": digest[:12],
        "token_expires_at": row.token_expires_at,
        "invite_count": row.invite_count,
        "delivery": delivery,
        "signing_url": production_safe_dev_value(signing_url),
        "reason": reason,
    }


@frappe.whitelist()
def envelope_progress(envelope: str):
    env = frappe.get_doc("E-Sign Envelope", envelope)
    current_rows = {r.name for r in _phase11_current_recipients(env)}

    recipients = []

    for r in env.recipients:
        recipients.append({
            "row": r.name,
            "signer_name": r.signer_name,
            "signer_email": r.signer_email,
            "role": r.role,
            "sign_order": int(r.sign_order or 1),
            "status": r.status,
            "invite_count": int(r.invite_count or 0),
            "last_invite_sent_at": r.last_invite_sent_at,
            "token_expires_at": r.token_expires_at,
            "signed_at": r.signed_at,
            "declined_at": getattr(r, "declined_at", None),
            "is_current_turn": r.name in current_rows,
        })

    required = [r for r in env.recipients if r.role in _phase11_active_roles()]
    signed_count = len([r for r in required if r.status == "Signed"])

    return {
        "ok": True,
        "envelope": env.name,
        "title": env.title,
        "status": env.status,
        "workflow_type": env.workflow_type,
        "required_count": len(required),
        "signed_count": signed_count,
        "pending_count": len(required) - signed_count,
        "current_recipient_rows": list(current_rows),
        "recipients": recipients,
    }


@frappe.whitelist()
def send_envelope_invites(envelope: str):
    env = frappe.get_doc("E-Sign Envelope", envelope)

    if env.status in _phase11_terminal_envelope_statuses():
        frappe.throw(_(f"Cannot send invites while envelope status is {env.status}"))

    current_rows = _phase11_current_recipients(env)

    if not current_rows:
        return {
            "ok": True,
            "envelope": env.name,
            "message": "No pending recipients to invite.",
            "invites": [],
            "progress": envelope_progress(env.name),
        }

    invites = []

    for row in current_rows:
        invites.append(_phase11_issue_token_for_row(env, row, reason="send_envelope_invites"))

    if env.status in ("Draft", "Prepared"):
        env.status = "Sent"
        env.sent_on = now_datetime()

    env.save(ignore_permissions=True)

    for invite in invites:
        add_audit(
            envelope=env.name,
            event_type="recipient.invite_sent",
            actor_type="User",
            actor_user=frappe.session.user,
            actor_email=frappe.session.user,
            details={
                "recipient_row": invite["recipient_row"],
                "signer_email": invite["signer_email"],
                "sign_order": invite["sign_order"],
                "token_hash_prefix": invite["token_hash_prefix"],
                "delivery": invite["delivery"],
                "workflow_type": env.workflow_type,
            },
        )

        add_security_event(
            event_type="invite.sent",
            severity="Low",
            envelope=env.name,
            recipient_row=invite["recipient_row"],
            recipient_email=invite["signer_email"],
            token_hash_prefix=invite["token_hash_prefix"],
            details={"delivery": invite["delivery"], "workflow_type": env.workflow_type},
        )

    frappe.db.commit()

    return {
        "ok": True,
        "envelope": env.name,
        "workflow_type": env.workflow_type,
        "invites": invites,
        "progress": envelope_progress(env.name),
    }


@frappe.whitelist()
def resend_invite(envelope: str, signer_email: str, reason: str = "Manual resend"):
    from surhan_signature.signing.lifecycle import envelope_is_expired, normalize_lifecycle_reason
    from surhan_signature.signing.transaction import lock_lifecycle_scope

    env = frappe.get_doc("E-Sign Envelope", envelope)

    if env.status in _phase11_terminal_envelope_statuses():
        frappe.throw(_(f"Cannot resend invite while envelope status is {env.status}"))

    target = None
    for row in env.recipients:
        if row.signer_email == signer_email:
            target = row
            break

    if not target:
        frappe.throw(_("Recipient not found in envelope"))

    lock_lifecycle_scope(target.name, env.name)
    env = frappe.get_doc("E-Sign Envelope", envelope)
    target = _get_child_recipient(env, target.name)

    if env.status in _phase11_terminal_envelope_statuses():
        frappe.throw(_(f"Cannot resend invite while envelope status is {env.status}"))
    if envelope_is_expired(env.expires_on):
        frappe.throw(_("Cannot resend invite for an expired envelope"))
    try:
        reason = normalize_lifecycle_reason(reason, "Manual resend")
    except ValueError as exc:
        frappe.throw(_(str(exc)))

    if target.status in ("Signed", "Declined", "Expired", "Failed"):
        frappe.throw(_(f"Cannot resend invite to recipient with status {target.status}"))

    can_sign, can_sign_reason = _recipient_can_sign(env, target.name)
    if not can_sign and env.workflow_type != "Parallel":
        frappe.throw(_(can_sign_reason))

    invite = _phase11_issue_token_for_row(env, target, reason="resend_invite")
    env.save(ignore_permissions=True)

    add_audit(
        envelope=env.name,
        event_type="recipient.invite_resent",
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details={
            "recipient_row": target.name,
            "signer_email": signer_email,
            "reason": reason,
            "token_hash_prefix": invite["token_hash_prefix"],
            "delivery": invite["delivery"],
        },
    )

    add_security_event(
        event_type="invite.resent",
        severity="Low",
        envelope=env.name,
        recipient_row=target.name,
        recipient_email=signer_email,
        token_hash_prefix=invite["token_hash_prefix"],
        details={"reason": reason, "delivery": invite["delivery"]},
    )

    frappe.db.commit()

    return {
        "ok": True,
        "envelope": env.name,
        "invite": invite,
        "progress": envelope_progress(env.name),
    }


@frappe.whitelist(allow_guest=True)
def decline_signing(token: str, reason: str = ""):
    from surhan_signature.signing.decline import normalize_decline_reason
    from surhan_signature.signing.transaction import lock_signing_scope

    _phase10_rate(
        scope="decline_signing",
        token=token,
        limit=10,
        window_seconds=600,
        severity="Medium",
    )

    row = _get_recipient_by_token(token)

    if not row:
        add_security_event(
            event_type="decline.invalid_token",
            severity="Medium",
            token_hash_prefix=_phase10_token_prefix(token),
        )
        frappe.throw(_("Invalid signing link"))

    _ensure_token_active(row)
    lock_signing_scope(row.name, row.parent)

    # Re-read after acquiring the locks so signing and declining cannot race.
    row = _get_recipient_by_token(token)
    _ensure_token_active(row)

    env = frappe.get_doc("E-Sign Envelope", row.parent)
    target = _get_child_recipient(env, row.name)

    if not target:
        frappe.throw(_("Recipient not found"))

    if target.status == "Signed":
        frappe.throw(_("Signed recipient cannot decline after signing"))

    can_decline, decline_block_reason = _recipient_can_sign(env, row.name)
    if not can_decline:
        add_security_event(
            event_type="decline.blocked_not_current_signer",
            severity="Medium",
            envelope=env.name,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=_phase10_token_prefix(token),
            details={"reason": decline_block_reason},
        )
        frappe.throw(_(decline_block_reason))

    try:
        decline_reason = normalize_decline_reason(reason)
    except ValueError as exc:
        frappe.throw(_(str(exc)))

    target.status = "Declined"
    target.declined_at = now_datetime()
    target.decline_reason = decline_reason
    target.token_hash = ""
    target.token_expires_at = now_datetime()

    env.status = "Declined"
    env.locked = 1

    env.save(ignore_permissions=True)

    add_audit(
        envelope=env.name,
        event_type="recipient.declined",
        actor_type="External Signer",
        actor_email=target.signer_email,
        details={
            "recipient_row": target.name,
            "signer_email": target.signer_email,
            "reason": target.decline_reason,
            "token_revoked": True,
        },
    )

    add_security_event(
        event_type="signing.declined",
        severity="Medium",
        envelope=env.name,
        recipient_row=target.name,
        recipient_email=target.signer_email,
        token_hash_prefix=_phase10_token_prefix(token),
        details={"reason": target.decline_reason},
    )

    frappe.db.commit()

    return {
        "ok": True,
        "declined": True,
        "envelope": env.name,
        "status": env.status,
        "recipient_row": target.name,
    }


@frappe.whitelist()
def expire_envelopes():
    from surhan_signature.signing.lifecycle import envelope_is_expired
    from surhan_signature.signing.transaction import lock_audit_chain

    now = now_datetime()

    candidates = frappe.get_all(
        "E-Sign Envelope",
        filters=[
            ["status", "not in", list(_phase11_terminal_envelope_statuses())],
            ["expires_on", "<", now],
        ],
        fields=["name", "status", "expires_on"],
        limit=100,
    )

    expired = []

    for item in candidates:
        lock_audit_chain(item.name)
        env = frappe.get_doc("E-Sign Envelope", item.name)

        # Re-check after acquiring the lock; another request may have completed
        # or declined the envelope after the candidate query.
        if env.status in _phase11_terminal_envelope_statuses():
            continue
        if not envelope_is_expired(env.expires_on, current_time=now):
            continue

        for row in env.recipients:
            if row.status not in ("Signed", "Declined", "Expired", "Failed"):
                row.status = "Expired"
                row.token_hash = ""
                row.token_expires_at = now

        env.status = "Expired"
        env.locked = 1

        env.save(ignore_permissions=True)

        add_audit(
            envelope=env.name,
            event_type="envelope.expired",
            actor_type="System",
            details={
                "expired_on": str(now),
                "previous_status": item.status,
                "expires_on": str(item.expires_on),
            },
        )

        add_security_event(
            event_type="envelope.expired",
            severity="Low",
            envelope=env.name,
            details={"expires_on": str(item.expires_on)},
        )

        expired.append(env.name)

    frappe.db.commit()

    return {
        "ok": True,
        "expired_count": len(expired),
        "expired": expired,
    }


# Phase 12 override: complete signature and auto-advance Sequential workflow.
def _phase12_finalize_signed_envelope(env):
    cert_no = make_certificate(env.name)

    env.status = "Signed"
    env.completed_on = now_datetime()
    env.locked = 1
    env.certificate_no = cert_no
    env.save(ignore_permissions=True)

    add_audit(
        envelope=env.name,
        event_type="envelope.completed",
        actor_type="System",
        details={
            "certificate_no": cert_no,
            "phase12": True,
        },
    )

    artifacts = None

    try:
        from surhan_signature.signing.pdf import finalize_envelope_artifacts
        artifacts = finalize_envelope_artifacts(env.name)

        add_audit(
            envelope=env.name,
            event_type="envelope.artifacts_generated",
            actor_type="System",
            details=artifacts,
        )

    except Exception:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Phase 12 Artifact Generation Failed")
        artifacts = {
            "ok": False,
            "error": "Final artifact generation failed. Check Error Log.",
        }

    latest_chain = verify_audit_chain(env.name)
    frappe.db.set_value("E-Sign Envelope", env.name, "audit_root_hash", latest_chain.get("latest_hash"))

    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": env.name})
    if cert_name:
        frappe.db.set_value("E-Sign Certificate", cert_name, "audit_root_hash", latest_chain.get("latest_hash"))

    return cert_no, artifacts, latest_chain


def _phase12_auto_invite_next(env_name: str):
    env = frappe.get_doc("E-Sign Envelope", env_name)

    if env.workflow_type != "Sequential":
        return {
            "ok": True,
            "auto_advance": False,
            "reason": "Envelope workflow is not Sequential.",
            "invites": [],
        }

    pending = [r for r in env.recipients if r.role in _phase11_active_roles() and r.status not in ("Signed", "Declined", "Expired", "Failed")]

    if not pending:
        return {
            "ok": True,
            "auto_advance": False,
            "reason": "No pending recipients.",
            "invites": [],
        }

    current_order = min(int(r.sign_order or 1) for r in pending)
    current_rows = [r for r in pending if int(r.sign_order or 1) == current_order]

    invites = []

    for row in current_rows:
        invite = _phase11_issue_token_for_row(env, row, reason="phase12_auto_advance")
        invites.append(invite)

    if invites:
        env.status = "Partially Signed"
        env.save(ignore_permissions=True)

        for invite in invites:
            add_audit(
                envelope=env.name,
                event_type="recipient.next_invite_sent",
                actor_type="System",
                details={
                    "recipient_row": invite["recipient_row"],
                    "signer_email": invite["signer_email"],
                    "sign_order": invite["sign_order"],
                    "token_hash_prefix": invite["token_hash_prefix"],
                    "delivery": invite["delivery"],
                    "phase12_auto_advance": True,
                },
            )

            add_security_event(
                event_type="workflow.next_invite_sent",
                severity="Low",
                envelope=env.name,
                recipient_row=invite["recipient_row"],
                recipient_email=invite["signer_email"],
                token_hash_prefix=invite["token_hash_prefix"],
                details={
                    "sign_order": invite["sign_order"],
                    "delivery": invite["delivery"],
                    "phase12_auto_advance": True,
                },
            )

    latest_chain = verify_audit_chain(env.name)
    frappe.db.set_value("E-Sign Envelope", env.name, "audit_root_hash", latest_chain.get("latest_hash"))

    return {
        "ok": True,
        "auto_advance": bool(invites),
        "current_order": current_order,
        "invites": invites,
        "audit_chain": latest_chain,
    }


def _complete_signature(
    token: str,
    signature_method: str,
    consent_accepted=0,
    signature_text=None,
    signature_image=None,
    evidence_hash=None,
):
    _phase10_rate(
        scope=f"sign_{str(signature_method or '').lower()}",
        token=token,
        limit=10,
        window_seconds=600,
        severity="High",
    )

    row = _get_recipient_by_token(token)

    if not row:
        add_security_event(
            event_type="signing.invalid_token",
            severity="High",
            token_hash_prefix=_phase10_token_prefix(token),
            details={"operation": "complete_signature", "method": signature_method},
        )
        frappe.throw(_("Invalid signing link"))

    _ensure_token_active(row)

    if not int(consent_accepted or 0):
        add_security_event(
            event_type="signing.consent_missing",
            severity="Medium",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=_phase10_token_prefix(token),
        )
        frappe.throw(_("Consent must be accepted before signing."))

    env = frappe.get_doc("E-Sign Envelope", row.parent)
    can_sign, can_sign_reason = _recipient_can_sign(env, row.name)

    if not can_sign:
        add_security_event(
            event_type="signing.blocked_not_current_turn",
            severity="Medium",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=_phase10_token_prefix(token),
            details={"reason": can_sign_reason},
        )
        frappe.throw(_(can_sign_reason))

    target = _get_child_recipient(env, row.name)

    if not target:
        frappe.throw(_("Recipient not found."))

    if not target.otp_verified:
        add_security_event(
            event_type="signing.blocked_otp_missing",
            severity="High",
            envelope=row.parent,
            recipient_row=row.name,
            recipient_email=row.signer_email,
            token_hash_prefix=_phase10_token_prefix(token),
        )
        frappe.throw(_("OTP must be verified before signing."))

    if signature_method == "Typed" and not signature_text:
        frappe.throw(_("Typed signature text is required."))

    if signature_method in ("Drawn", "Uploaded") and not signature_image:
        frappe.throw(_("Signature image is required."))

    target.status = "Signed"
    target.signed_at = now_datetime()
    target.signature_method = signature_method
    target.signature_text = signature_text if signature_method == "Typed" else None
    target.signature_image = signature_image if signature_method in ("Drawn", "Uploaded") else None
    target.consent_accepted = 1
    target.consent_text_snapshot = "I agree to sign this document electronically."
    target.token_hash = ""
    target.token_expires_at = now_datetime()

    env.save(ignore_permissions=True)

    add_audit(
        envelope=env.name,
        event_type="recipient.signed",
        actor_type="External Signer",
        actor_email=target.signer_email,
        details={
            "recipient": target.name,
            "signature_method": signature_method,
            "signature_text_present": bool(signature_text),
            "signature_image": signature_image,
            "evidence_hash": evidence_hash,
            "token_revoked_after_signing": True,
            "phase12": True,
        },
    )

    add_security_event(
        event_type="signing.completed",
        severity="Low",
        envelope=env.name,
        recipient_row=target.name,
        recipient_email=target.signer_email,
        token_hash_prefix=_phase10_token_prefix(token),
        details={
            "signature_method": signature_method,
            "token_revoked_after_signing": True,
            "phase12": True,
        },
    )

    env.reload()

    required_rows = [r for r in env.recipients if r.role in _phase11_active_roles()]
    all_signed = bool(required_rows) and all(r.status == "Signed" for r in required_rows)

    cert_no = None
    artifacts = None
    auto_advance = None
    latest_chain = None

    if all_signed:
        cert_no, artifacts, latest_chain = _phase12_finalize_signed_envelope(env)
        final_status = "Signed"
        completed = True

    else:
        env.status = "Partially Signed"
        env.save(ignore_permissions=True)

        add_audit(
            envelope=env.name,
            event_type="envelope.partially_signed",
            actor_type="System",
            details={
                "signed_recipient": target.name,
                "workflow_type": env.workflow_type,
                "phase12": True,
            },
        )

        auto_advance = _phase12_auto_invite_next(env.name)

        latest_chain = verify_audit_chain(env.name)
        frappe.db.set_value("E-Sign Envelope", env.name, "audit_root_hash", latest_chain.get("latest_hash"))

        final_status = "Partially Signed"
        completed = False

    frappe.db.commit()

    progress = envelope_progress(env.name)

    return {
        "ok": True,
        "envelope": env.name,
        "status": final_status,
        "completed": completed,
        "certificate_no": cert_no,
        "signature_method": signature_method,
        "signature_image": signature_image,
        "evidence_hash": evidence_hash,
        "auto_advance": auto_advance,
        "artifacts": artifacts,
        "audit_chain": latest_chain,
        "progress": progress,
    }


# Phase 13: dashboard APIs, email readiness, and parallel workflow support utilities.
@frappe.whitelist()
def email_setup_status():
    """
    Check whether outgoing email is ready for invite/OTP delivery.
    """
    accounts = frappe.get_all(
        "Email Account",
        fields=[
            "name",
            "email_id",
            "enable_outgoing",
            "default_outgoing",
            "smtp_server",
            "login_id",
        ],
        order_by="modified desc",
        limit=50,
    )

    outgoing = [a for a in accounts if int(a.get("enable_outgoing") or 0)]
    default_outgoing = [a for a in outgoing if int(a.get("default_outgoing") or 0)]

    return {
        "ok": True,
        "ready": bool(default_outgoing),
        "message": "Outgoing email is ready." if default_outgoing else "Default outgoing Email Account is not configured.",
        "total_accounts": len(accounts),
        "outgoing_accounts": outgoing,
        "default_outgoing_accounts": default_outgoing,
        "setup_hint": "Go to Tools > Email Account and enable outgoing + default outgoing account.",
    }


@frappe.whitelist()
def signature_dashboard_summary(status: str | None = None, limit: int = 25):
    filters = {}

    if status:
        filters["status"] = status

    rows = frappe.get_all(
        "E-Sign Envelope",
        filters=filters,
        fields=[
            "name",
            "title",
            "status",
            "workflow_type",
            "signing_level",
            "certificate_no",
            "sent_on",
            "completed_on",
            "expires_on",
            "creation",
            "modified",
        ],
        order_by="modified desc",
        limit=int(limit or 25),
    )

    counts = frappe.db.sql(
        """
        SELECT status, COUNT(*) AS count
        FROM `tabE-Sign Envelope`
        GROUP BY status
        ORDER BY status
        """,
        as_dict=True,
    )

    email_status = email_setup_status()

    return {
        "ok": True,
        "status_filter": status,
        "count": len(rows),
        "status_counts": counts,
        "email": {
            "ready": email_status.get("ready"),
            "message": email_status.get("message"),
        },
        "envelopes": rows,
    }


@frappe.whitelist()
def signature_dashboard_details(envelope: str):
    progress = envelope_progress(envelope)

    cert = None
    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": envelope})
    if cert_name:
        c = frappe.get_doc("E-Sign Certificate", cert_name)
        cert = {
            "certificate_no": c.certificate_no,
            "verification_url": c.verification_url,
            "certificate_pdf": c.certificate_pdf,
            "certificate_pdf_sha256": getattr(c, "certificate_pdf_sha256", None),
            "evidence_package": getattr(c, "evidence_package", None),
            "evidence_package_sha256": getattr(c, "evidence_package_sha256", None),
            "final_hash": c.final_hash,
            "audit_root_hash": c.audit_root_hash,
        }

    chain = check_audit_chain(envelope)

    security = debug_security_events(envelope=envelope, limit=15) if frappe.conf.get("developer_mode") else None

    return {
        "ok": True,
        "envelope": envelope,
        "progress": progress,
        "certificate": cert,
        "audit_chain": chain,
        "security_events": security,
    }


@frappe.whitelist()
def dashboard_send_invites(envelope: str):
    return send_envelope_invites(envelope)


@frappe.whitelist()
def dashboard_resend_invite(envelope: str, signer_email: str, reason: str = "Dashboard resend"):
    return resend_invite(envelope=envelope, signer_email=signer_email, reason=reason)


@frappe.whitelist()
def dashboard_verify_certificate(certificate_no: str):
    return verify_certificate(certificate_no=certificate_no)


# Phase 14: access control summary and role assignment helper.
SIGNATURE_ACCESS_ROLES = [
    "Signature Administrator",
    "Signature Manager",
    "Signature Sender",
    "Signature Auditor",
    "Signature Viewer",
]


def _phase14_only_system_manager():
    if frappe.session.user == "Administrator":
        return

    if "System Manager" not in frappe.get_roles():
        frappe.throw(_("Only System Manager can perform this action."))


@frappe.whitelist()
def access_control_summary():
    doctypes = [
        "E-Sign Envelope",
        "E-Sign Certificate",
        "E-Sign Audit Log",
        "E-Sign Security Event",
        "E-Sign Settings",
    ]

    roles = frappe.get_all(
        "Role",
        filters={"role_name": ["in", SIGNATURE_ACCESS_ROLES]},
        fields=["role_name", "desk_access", "disabled"],
        order_by="role_name asc",
    )

    matrix = {}

    for dt in doctypes:
        meta = frappe.get_meta(dt)
        rows = []

        for p in meta.permissions:
            if p.role in SIGNATURE_ACCESS_ROLES or p.role == "System Manager":
                rows.append({
                    "role": p.role,
                    "read": p.read,
                    "write": p.write,
                    "create": p.create,
                    "delete": p.delete,
                    "report": p.report,
                    "export": p.export,
                    "print": p.print,
                    "email": p.email,
                    "share": p.share,
                })

        matrix[dt] = rows

    workspace = frappe.get_all(
        "Workspace",
        filters={"label": "Surhan Signature"},
        fields=["name", "label", "title", "public", "module"],
        limit=1,
    )

    return {
        "ok": True,
        "roles": roles,
        "workspace": workspace[0] if workspace else None,
        "permissions": matrix,
        "dashboard_url": "/signature-dashboard",
        "desk_workspace_url": "/app/surhan-signature",
    }


@frappe.whitelist()
def assign_signature_role(user: str, role: str):
    _phase14_only_system_manager()

    if role not in SIGNATURE_ACCESS_ROLES:
        frappe.throw(_("Invalid Signature role."))

    if not frappe.db.exists("User", user):
        frappe.throw(_("User not found."))

    if not frappe.db.exists("Role", role):
        frappe.throw(_("Role does not exist."))

    doc = frappe.get_doc("User", user)
    existing = {r.role for r in doc.roles}

    added = False

    if role not in existing:
        doc.append("roles", {"role": role})
        doc.save(ignore_permissions=True)
        frappe.db.commit()
        added = True

    return {
        "ok": True,
        "user": user,
        "role": role,
        "added": added,
        "message": "Role assigned." if added else "User already has this role.",
    }


# Phase 15: email production readiness and safe developer output.
def _phase15_setting(fieldname, default=None):
    try:
        value = frappe.db.get_single_value("E-Sign Settings", fieldname)
        return default if value in (None, "") else value
    except Exception:
        return default


def _phase15_bool_setting(fieldname, default=0):
    try:
        value = _phase15_setting(fieldname, default)
        return int(value or 0)
    except Exception:
        return int(default or 0)


def _phase15_public_base_url():
    configured = _phase15_setting("signing_base_url")
    if configured:
        return str(configured).rstrip("/")
    return get_url().rstrip("/")


def production_safe_dev_value(value):
    """
    Overrides earlier helper.
    In developer mode we still obey E-Sign Settings flags.
    In production this returns None to avoid leaking tokens/OTP in logs/API output.
    """
    developer_mode = bool(frappe.conf.get("developer_mode"))

    if not developer_mode:
        return None

    if isinstance(value, str) and "/sign?token=" in value:
        return value if _phase15_bool_setting("expose_dev_signing_links", 1) else None

    return value


def _phase15_email_ready():
    accounts = frappe.get_all(
        "Email Account",
        fields=[
            "name",
            "email_id",
            "enable_outgoing",
            "default_outgoing",
            "smtp_server",
            "login_id",
        ],
        order_by="modified desc",
        limit=50,
    )

    outgoing = [a for a in accounts if int(a.get("enable_outgoing") or 0)]
    default_outgoing = [a for a in outgoing if int(a.get("default_outgoing") or 0)]

    return {
        "ready": bool(default_outgoing),
        "accounts": accounts,
        "outgoing_accounts": outgoing,
        "default_outgoing_accounts": default_outgoing,
        "message": "Outgoing email is ready." if default_outgoing else "Default outgoing Email Account is not configured.",
    }


def _phase15_render_invite_email(signer_name, envelope_title, signing_url):
    return f"""
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
      <h2 style="margin-bottom:8px">Signature Request</h2>
      <p>Hello {frappe.utils.escape_html(signer_name or '')},</p>
      <p>You have a document waiting for your electronic signature:</p>
      <p><b>{frappe.utils.escape_html(envelope_title or '')}</b></p>
      <p>
        <a href="{frappe.utils.escape_html(signing_url)}"
           style="display:inline-block;background:#111827;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none">
          Open Signing Link
        </a>
      </p>
      <p>If the button does not work, copy this link:</p>
      <p style="word-break:break-all">{frappe.utils.escape_html(signing_url)}</p>
      <hr>
      <p style="font-size:12px;color:#6b7280">
        This message was sent by Surhan Signature.
      </p>
    </div>
    """


def _phase15_render_otp_email(signer_name, otp):
    return f"""
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
      <h2 style="margin-bottom:8px">Signing Verification Code</h2>
      <p>Hello {frappe.utils.escape_html(signer_name or '')},</p>
      <p>Your verification code is:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:4px;background:#f3f4f6;padding:14px 18px;border-radius:10px;display:inline-block">
        {frappe.utils.escape_html(str(otp))}
      </div>
      <p>This code is required to complete your electronic signature.</p>
      <hr>
      <p style="font-size:12px;color:#6b7280">
        If you did not request this code, ignore this email.
      </p>
    </div>
    """


def _phase11_send_invite_email(recipient_email: str, signer_name: str, envelope_title: str, signing_url: str):
    if not recipient_email:
        return {
            "sent": False,
            "reason": "No recipient email.",
        }

    readiness = _phase15_email_ready()

    if not readiness["ready"]:
        return {
            "sent": False,
            "reason": readiness["message"],
        }

    public_url = signing_url

    try:
        if "/sign?token=" in signing_url:
            token_part = signing_url.split("/sign?token=", 1)[1]
            public_url = f"{_phase15_public_base_url()}/sign?token={token_part}"
    except Exception:
        public_url = signing_url

    subject_template = _phase15_setting("invite_email_subject", "Signature request: {title}")
    subject = str(subject_template).replace("{title}", envelope_title or "Document")

    try:
        frappe.sendmail(
            recipients=[recipient_email],
            subject=subject,
            message=_phase15_render_invite_email(signer_name, envelope_title, public_url),
            now=True,
        )
        return {
            "sent": True,
            "channel": "email",
            "recipient_email": recipient_email,
        }
    except Exception as exc:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Invite Email Failed")
        return {
            "sent": False,
            "reason": str(exc),
        }


def _send_otp_email(row, otp):
    if not getattr(row, "signer_email", None):
        return {
            "sent": False,
            "reason": "No signer email.",
        }

    readiness = _phase15_email_ready()

    if not readiness["ready"]:
        return {
            "sent": False,
            "reason": readiness["message"],
        }

    subject = _phase15_setting("otp_email_subject", "Your signing verification code")

    try:
        frappe.sendmail(
            recipients=[row.signer_email],
            subject=subject,
            message=_phase15_render_otp_email(getattr(row, "signer_name", ""), otp),
            now=True,
        )
        return {
            "sent": True,
            "channel": "email",
            "recipient_email": row.signer_email,
        }
    except Exception as exc:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature OTP Email Failed")
        return {
            "sent": False,
            "reason": str(exc),
        }


@frappe.whitelist()
def production_readiness_report():
    email = _phase15_email_ready()

    settings = {
        "developer_mode": bool(frappe.conf.get("developer_mode")),
        "signing_base_url": _phase15_public_base_url(),
        "expose_dev_signing_links": _phase15_bool_setting("expose_dev_signing_links", 1),
        "expose_dev_otp": _phase15_bool_setting("expose_dev_otp", 1),
    }

    warnings = []

    if settings["developer_mode"]:
        warnings.append("developer_mode is enabled. Disable before production.")

    if settings["expose_dev_signing_links"]:
        warnings.append("expose_dev_signing_links is enabled. Disable before production.")

    if settings["expose_dev_otp"]:
        warnings.append("expose_dev_otp is enabled. Disable before production.")

    if not email["ready"]:
        warnings.append("Default outgoing Email Account is not configured.")

    signed_count = frappe.db.count("E-Sign Envelope", {"status": "Signed"})
    sent_count = frappe.db.count("E-Sign Envelope", {"status": "Sent"})
    declined_count = frappe.db.count("E-Sign Envelope", {"status": "Declined"})

    return {
        "ok": True,
        "production_ready": not warnings,
        "warnings": warnings,
        "settings": settings,
        "email": {
            "ready": email["ready"],
            "message": email["message"],
            "outgoing_count": len(email["outgoing_accounts"]),
            "default_outgoing_count": len(email["default_outgoing_accounts"]),
        },
        "envelope_counts": {
            "signed": signed_count,
            "sent": sent_count,
            "declined": declined_count,
        },
        "urls": {
            "signature_dashboard": "/signature-dashboard",
            "desk_workspace": "/app/surhan-signature",
        },
    }


@frappe.whitelist()
def send_test_signature_email(recipient_email: str):
    readiness = _phase15_email_ready()

    if not readiness["ready"]:
        return {
            "ok": False,
            "sent": False,
            "reason": readiness["message"],
            "hint": "Configure Tools > Email Account with enable_outgoing and default_outgoing.",
        }

    try:
        frappe.sendmail(
            recipients=[recipient_email],
            subject="Surhan Signature email test",
            message="""
                <p>This is a test email from Surhan Signature.</p>
                <p>If you received this message, outgoing email is working.</p>
            """,
            now=True,
        )

        return {
            "ok": True,
            "sent": True,
            "recipient_email": recipient_email,
        }

    except Exception as exc:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Test Email Failed")
        return {
            "ok": False,
            "sent": False,
            "reason": str(exc),
        }


@frappe.whitelist()
def disable_developer_outputs():
    if frappe.session.user != "Administrator" and "System Manager" not in frappe.get_roles():
        frappe.throw(_("Only System Manager can change developer output settings."))

    frappe.db.set_single_value("E-Sign Settings", "expose_dev_signing_links", 0)
    frappe.db.set_single_value("E-Sign Settings", "expose_dev_otp", 0)
    frappe.db.commit()

    return {
        "ok": True,
        "expose_dev_signing_links": 0,
        "expose_dev_otp": 0,
        "message": "Developer signing links and OTP outputs disabled.",
    }


@frappe.whitelist()
def enable_developer_outputs():
    if frappe.session.user != "Administrator" and "System Manager" not in frappe.get_roles():
        frappe.throw(_("Only System Manager can change developer output settings."))

    frappe.db.set_single_value("E-Sign Settings", "expose_dev_signing_links", 1)
    frappe.db.set_single_value("E-Sign Settings", "expose_dev_otp", 1)
    frappe.db.commit()

    return {
        "ok": True,
        "expose_dev_signing_links": 1,
        "expose_dev_otp": 1,
        "message": "Developer signing links and OTP outputs enabled.",
    }


# Phase 15 override: request OTP with configurable dev_otp visibility.
@frappe.whitelist(allow_guest=True)
def request_otp(token: str):
    _phase10_rate(
        scope="request_otp",
        token=token,
        limit=5,
        window_seconds=600,
        severity="Medium",
    )

    row = _get_recipient_by_token(token)

    if not row:
        add_security_event(
            event_type="otp.invalid_token",
            severity="Medium",
            token_hash_prefix=_phase10_token_prefix(token),
            details={"operation": "request_otp"},
        )
        frappe.throw(_("Invalid signing link"))

    _ensure_token_active(row)

    otp = generate_recipient_otp(row.name)
    delivery = _send_otp_email(row, otp)

    add_security_event(
        event_type="otp.requested",
        severity="Low",
        envelope=row.parent,
        recipient_row=row.name,
        recipient_email=row.signer_email,
        token_hash_prefix=getattr(row, "last_token_hash_prefix", None) or _phase10_token_prefix(token),
        details={"delivery": delivery},
    )

    frappe.db.commit()

    response = {
        "ok": True,
        "message": "OTP generated.",
        "delivery": delivery,
    }

    if bool(frappe.conf.get("developer_mode")) and _phase15_bool_setting("expose_dev_otp", 1):
        response["dev_otp"] = otp
        response["warning"] = "dev_otp appears only because developer_mode and expose_dev_otp are enabled."

    return response



# Phase 17: webhook endpoints and delivery log.
import hmac as _phase17_hmac
import hashlib as _phase17_hashlib
import json as _phase17_json


def _phase17_json_dumps(data):
    return _phase17_json.dumps(data or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _phase17_parse_events(events):
    if events in (None, "", []):
        return ["*"]

    if isinstance(events, list):
        return events

    if isinstance(events, str):
        try:
            parsed = _phase17_json.loads(events)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return [e.strip() for e in events.split(",") if e.strip()]

    return ["*"]


def _phase17_endpoint_allows(endpoint, event_type):
    events = _phase17_parse_events(getattr(endpoint, "events", None))
    return "*" in events or event_type in events


def _phase17_sign(secret, body):
    secret = secret or ""
    digest = _phase17_hmac.new(
        secret.encode("utf-8"),
        body.encode("utf-8"),
        _phase17_hashlib.sha256,
    ).hexdigest()

    return f"sha256={digest}"


def _phase17_default_payload(event_type, envelope=None, certificate_no=None, extra=None):
    payload = {
        "event_type": event_type,
        "event_time": str(now_datetime()),
        "source": "surhan_signature",
        "site": get_url(),
        "envelope": envelope,
        "certificate_no": certificate_no,
    }

    if envelope:
        try:
            env = frappe.get_doc("E-Sign Envelope", envelope)
            payload["envelope_status"] = env.status
            payload["workflow_type"] = env.workflow_type
            payload["title"] = env.title
            payload["final_signed_pdf"] = getattr(env, "final_signed_pdf", None)
            payload["evidence_package"] = getattr(env, "evidence_package", None)
        except Exception:
            pass

    if certificate_no:
        try:
            cert = frappe.get_doc("E-Sign Certificate", certificate_no)
            payload["verification_url"] = cert.verification_url
            payload["final_hash"] = cert.final_hash
            payload["audit_root_hash"] = cert.audit_root_hash
        except Exception:
            pass

    if extra:
        payload["data"] = extra

    return payload


@frappe.whitelist()
def create_webhook_endpoint(
    title: str,
    target_url: str,
    events=None,
    enabled: int = 1,
    dry_run: int = 0,
    secret: str | None = None,
    timeout_seconds: int = 10,
    max_attempts: int = 3,
):
    if frappe.session.user != "Administrator" and "System Manager" not in frappe.get_roles() and "Signature Administrator" not in frappe.get_roles():
        frappe.throw(_("Not permitted to create webhook endpoints."))

    try:
        target_url = validate_outbound_url(target_url)
    except ValueError as exc:
        frappe.throw(str(exc))

    if not secret:
        secret = secure_token_urlsafe(32)

    event_list = _phase17_parse_events(events)

    doc = frappe.get_doc({
        "doctype": "E-Sign Webhook Endpoint",
        "enabled": int(enabled or 0),
        "dry_run": int(dry_run or 0),
        "title": title,
        "target_url": target_url,
        "secret": secret,
        "events": _phase17_json.dumps(event_list, ensure_ascii=False),
        "timeout_seconds": int(timeout_seconds or 10),
        "max_attempts": int(max_attempts or 3),
        "last_status": "Pending",
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {
        "ok": True,
        "endpoint": doc.name,
        "title": title,
        "target_url": target_url,
        "events": event_list,
        "enabled": int(enabled or 0),
        "dry_run": int(dry_run or 0),
        "secret_preview": secret[:8] + "...",
    }


@frappe.whitelist()
def list_webhook_endpoints():
    rows = frappe.get_all(
        "E-Sign Webhook Endpoint",
        fields=[
            "name",
            "enabled",
            "dry_run",
            "title",
            "target_url",
            "events",
            "last_status",
            "last_delivery_at",
            "timeout_seconds",
            "max_attempts",
        ],
        order_by="modified desc",
        limit=100,
    )

    return {
        "ok": True,
        "count": len(rows),
        "endpoints": rows,
    }


@frappe.whitelist()
def emit_webhook_event(
    event_type: str,
    envelope: str | None = None,
    certificate_no: str | None = None,
    payload=None,
    deliver_now: int = 0,
):
    endpoints = frappe.get_all(
        "E-Sign Webhook Endpoint",
        filters={"enabled": 1},
        fields=["name"],
        limit=100,
    )

    extra = None

    if payload:
        if isinstance(payload, str):
            try:
                extra = _phase17_json.loads(payload)
            except Exception:
                extra = {"raw": payload}
        elif isinstance(payload, dict):
            extra = payload

    base_payload = _phase17_default_payload(
        event_type=event_type,
        envelope=envelope,
        certificate_no=certificate_no,
        extra=extra,
    )

    created = []
    delivered = []

    for item in endpoints:
        endpoint = frappe.get_doc("E-Sign Webhook Endpoint", item.name)

        if not _phase17_endpoint_allows(endpoint, event_type):
            continue

        doc = frappe.get_doc({
            "doctype": "E-Sign Webhook Delivery",
            "endpoint": endpoint.name,
            "event_type": event_type,
            "status": "Pending",
            "envelope": envelope,
            "certificate_no": certificate_no,
            "target_url": endpoint.target_url,
            "attempt_count": 0,
            "payload_json": _phase17_json.dumps(base_payload, ensure_ascii=False, sort_keys=True, default=str),
        })

        doc.insert(ignore_permissions=True)
        created.append(doc.name)

        if int(deliver_now or 0):
            delivered.append(deliver_webhook_delivery(doc.name))

    frappe.db.commit()

    return {
        "ok": True,
        "event_type": event_type,
        "created_count": len(created),
        "deliveries": created,
        "delivered": delivered,
    }


@frappe.whitelist()
def deliver_webhook_delivery(delivery: str):
    doc = frappe.get_doc("E-Sign Webhook Delivery", delivery)
    endpoint = frappe.get_doc("E-Sign Webhook Endpoint", doc.endpoint)

    payload = _phase17_json.loads(doc.payload_json or "{}")
    payload["delivery_id"] = doc.name
    body = _phase17_json_dumps(payload)

    signature = _phase17_sign(endpoint.get_password("secret") or endpoint.secret or "", body)

    headers = {
        "Content-Type": "application/json",
        "X-Surhan-Event": doc.event_type,
        "X-Surhan-Delivery": doc.name,
        "X-Surhan-Signature": signature,
    }

    frappe.flags.in_signature_system_update = True
    try:
        doc.attempt_count = int(doc.attempt_count or 0) + 1
        doc.request_sha256 = sha256_hex(body)
        doc.headers_json = _phase17_json.dumps(headers, ensure_ascii=False, sort_keys=True)

        if int(getattr(endpoint, "dry_run", 0) or 0):
            doc.status = "Delivered"
            doc.http_status = 0
            doc.response_text = "Dry run delivery. No HTTP request was sent."
            doc.error = ""
            doc.delivered_at = now_datetime()
        else:
            response = safe_post(
                endpoint.target_url,
                data=body.encode("utf-8"),
                headers=headers,
                timeout=int(endpoint.timeout_seconds or 10),
            )

            doc.http_status = int(response.status_code)
            doc.response_text = (response.text or "")[:2000]

            if 200 <= int(response.status_code) < 300:
                doc.status = "Delivered"
                doc.error = ""
                doc.delivered_at = now_datetime()
            else:
                doc.status = "Failed"
                doc.error = f"HTTP {response.status_code}"
                doc.next_retry_at = add_to_date(now_datetime(), minutes=15)

        doc.save(ignore_permissions=True)

        frappe.db.set_value("E-Sign Webhook Endpoint", endpoint.name, {
            "last_status": doc.status,
            "last_delivery_at": now_datetime(),
        })

        frappe.db.commit()

    except Exception as exc:
        doc.status = "Failed"
        doc.error = str(exc)[:2000]
        doc.next_retry_at = add_to_date(now_datetime(), minutes=15)
        doc.save(ignore_permissions=True)

        frappe.db.set_value("E-Sign Webhook Endpoint", endpoint.name, {
            "last_status": "Failed",
            "last_delivery_at": now_datetime(),
        })

        frappe.db.commit()

    finally:
        frappe.flags.in_signature_system_update = False

    return {
        "ok": doc.status == "Delivered",
        "delivery": doc.name,
        "endpoint": endpoint.name,
        "event_type": doc.event_type,
        "status": doc.status,
        "http_status": doc.http_status,
        "attempt_count": doc.attempt_count,
        "target_url": doc.target_url,
        "error": doc.error,
    }


@frappe.whitelist()
def retry_failed_webhooks(limit: int = 20):
    rows = frappe.get_all(
        "E-Sign Webhook Delivery",
        filters={"status": "Failed"},
        fields=["name", "endpoint", "attempt_count"],
        order_by="modified asc",
        limit=int(limit or 20),
    )

    results = []

    for row in rows:
        try:
            endpoint = frappe.get_doc("E-Sign Webhook Endpoint", row.endpoint)
            max_attempts = int(endpoint.max_attempts or 3)

            if int(row.attempt_count or 0) >= max_attempts:
                continue

            results.append(deliver_webhook_delivery(row.name))
        except Exception as exc:
            results.append({
                "ok": False,
                "delivery": row.name,
                "error": str(exc),
            })

    return {
        "ok": True,
        "retried_count": len(results),
        "results": results,
    }


@frappe.whitelist()
def webhook_delivery_summary(envelope: str | None = None, limit: int = 50):
    filters = {}

    if envelope:
        filters["envelope"] = envelope

    rows = frappe.get_all(
        "E-Sign Webhook Delivery",
        filters=filters,
        fields=[
            "name",
            "endpoint",
            "event_type",
            "status",
            "envelope",
            "certificate_no",
            "target_url",
            "attempt_count",
            "http_status",
            "request_sha256",
            "delivered_at",
            "next_retry_at",
            "error",
            "creation",
        ],
        order_by="creation desc",
        limit=int(limit or 50),
    )

    return {
        "ok": True,
        "count": len(rows),
        "deliveries": rows,
    }


@frappe.whitelist()
def test_webhook_event(envelope: str | None = None):
    certificate_no = None

    if envelope:
        certificate_no = frappe.db.get_value("E-Sign Envelope", envelope, "certificate_no")

    return emit_webhook_event(
        event_type="test.ping",
        envelope=envelope,
        certificate_no=certificate_no,
        payload={
            "message": "Test webhook from Surhan Signature",
        },
        deliver_now=1,
    )


# Phase 17 wrapper: emit webhook after signature completion.
_phase17_previous_complete_signature = _complete_signature


def _complete_signature(
    token: str,
    signature_method: str,
    consent_accepted=0,
    signature_text=None,
    signature_image=None,
    evidence_hash=None,
):
    result = _phase17_previous_complete_signature(
        token=token,
        signature_method=signature_method,
        consent_accepted=consent_accepted,
        signature_text=signature_text,
        signature_image=signature_image,
        evidence_hash=evidence_hash,
    )

    try:
        emit_webhook_event(
            event_type="recipient.signed",
            envelope=result.get("envelope"),
            certificate_no=result.get("certificate_no"),
            payload={
                "signature_method": signature_method,
                "completed": result.get("completed"),
                "status": result.get("status"),
            },
            deliver_now=1,
        )

        if result.get("completed"):
            emit_webhook_event(
                event_type="envelope.completed",
                envelope=result.get("envelope"),
                certificate_no=result.get("certificate_no"),
                payload={
                    "artifacts": result.get("artifacts"),
                    "audit_chain": result.get("audit_chain"),
                },
                deliver_now=1,
            )

    except Exception:
        frappe.log_error(frappe.get_traceback(), "Surhan Signature Phase 17 Webhook Emit Failed")

    return result


# Phase 19: compliance report, evidence export, and system health.
import json as _phase19_json
import hashlib as _phase19_hashlib


def _phase19_sha256_text(text: str) -> str:
    return _phase19_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase19_json(data) -> str:
    return _phase19_json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def _phase19_get_certificate_no(envelope: str):
    cert_no = frappe.db.get_value("E-Sign Envelope", envelope, "certificate_no")
    if cert_no:
        return cert_no

    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": envelope})
    if cert_name:
        return frappe.db.get_value("E-Sign Certificate", cert_name, "certificate_no")

    return None








# Phase 19A: safe compliance report overrides for schema-compatible field selection.
import json as _phase19a_json_module
import hashlib as _phase19a_hashlib_module


def _phase19a_json_dumps(data) -> str:
    return _phase19a_json_module.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase19a_sha256_text(text: str) -> str:
    return _phase19a_hashlib_module.sha256((text or "").encode("utf-8")).hexdigest()


def _phase19a_existing_fields(doctype: str, wanted: list[str]) -> list[str]:
    meta = frappe.get_meta(doctype)
    standard = {
        "name",
        "owner",
        "creation",
        "modified",
        "modified_by",
        "docstatus",
        "idx",
        "parent",
        "parentfield",
        "parenttype",
    }
    fieldnames = {df.fieldname for df in meta.fields if df.fieldname}
    allowed = standard | fieldnames

    return [f for f in wanted if f in allowed]


def _phase19a_get_rows(doctype: str, filters=None, fields=None, order_by=None, limit=500):
    safe_fields = _phase19a_existing_fields(doctype, fields or ["name"])
    if not safe_fields:
        safe_fields = ["name"]

    return frappe.get_all(
        doctype,
        filters=filters or {},
        fields=safe_fields,
        order_by=order_by,
        limit=limit,
    )


def _phase19a_get_certificate_no(envelope: str):
    cert_no = frappe.db.get_value("E-Sign Envelope", envelope, "certificate_no")
    if cert_no:
        return cert_no

    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": envelope})
    if cert_name:
        return frappe.db.get_value("E-Sign Certificate", cert_name, "certificate_no")

    return None


@frappe.whitelist()
def envelope_compliance_report(envelope: str):
    if not frappe.db.exists("E-Sign Envelope", envelope):
        frappe.throw(_("Envelope not found."))

    env = frappe.get_doc("E-Sign Envelope", envelope)
    certificate_no = _phase19a_get_certificate_no(envelope)

    recipients = _phase19a_get_rows(
        "E-Sign Recipient",
        filters={
            "parent": envelope,
            "parenttype": "E-Sign Envelope",
        },
        fields=[
            "name",
            "signer_name",
            "signer_email",
            "role",
            "sign_order",
            "status",
            "signature_method",
            "signature_image",
            "signed_at",
            "declined_at",
            "invite_count",
            "last_invite_sent_at",
            "token_expires_at",
            "creation",
        ],
        order_by="sign_order asc, idx asc",
        limit=100,
    )

    audit_chain = check_audit_chain(envelope)

    certificate_verification = None
    if certificate_no:
        try:
            certificate_verification = verify_certificate(certificate_no=certificate_no)
        except Exception as exc:
            certificate_verification = {
                "ok": False,
                "valid": False,
                "error": str(exc),
            }

    security_events = _phase19a_get_rows(
        "E-Sign Security Event",
        filters={"envelope": envelope},
        fields=[
            "name",
            "event_type",
            "severity",
            "recipient_email",
            "token_hash_prefix",
            "ip_address",
            "timestamp_utc",
            "details_json",
            "creation",
        ],
        order_by="creation asc",
        limit=500,
    )

    webhook_deliveries = _phase19a_get_rows(
        "E-Sign Webhook Delivery",
        filters={"envelope": envelope},
        fields=[
            "name",
            "endpoint",
            "event_type",
            "status",
            "envelope",
            "certificate_no",
            "target_url",
            "attempt_count",
            "http_status",
            "request_sha256",
            "delivered_at",
            "next_retry_at",
            "error",
            "creation",
        ],
        order_by="creation asc",
        limit=500,
    )

    audit_log_wanted_fields = [
        "name",
        "event_type",
        "actor_type",
        "actor_user",
        "actor_email",
        "ip_address",
        "user_agent",
        "timestamp_utc",
        "prev_hash",
        "previous_hash",
        "event_hash",
        "hash",
        "details_json",
        "creation",
    ]

    audit_logs = _phase19a_get_rows(
        "E-Sign Audit Log",
        filters={"envelope": envelope},
        fields=audit_log_wanted_fields,
        order_by="creation asc",
        limit=1000,
    )

    required_recipients = [
        r for r in recipients
        if r.get("role") in ("Signer", "Approver", "Witness")
    ]

    verdict_checks = {
        "envelope_signed": env.status == "Signed",
        "has_required_recipients": bool(required_recipients),
        "all_required_recipients_signed": bool(required_recipients) and all(
            r.get("status") == "Signed" for r in required_recipients
        ),
        "audit_chain_valid": bool(audit_chain.get("valid")),
        "certificate_valid": bool(certificate_verification and certificate_verification.get("valid")),
        "file_integrity_valid": bool(certificate_verification and certificate_verification.get("file_integrity_valid")),
        "has_final_signed_pdf": bool(getattr(env, "final_signed_pdf", None)),
        "has_evidence_package": bool(getattr(env, "evidence_package", None)),
    }

    if certificate_no:
        compliance_passed = all(verdict_checks.values())
    else:
        compliance_passed = (
            verdict_checks["has_required_recipients"]
            and verdict_checks["audit_chain_valid"]
        )

    return {
        "ok": True,
        "report_type": "Surhan Signature Compliance Report",
        "schema_fix": "phase19a_dynamic_fields",
        "generated_at": str(now_datetime()),
        "generated_by": frappe.session.user,
        "envelope": {
            "name": env.name,
            "title": env.title,
            "status": env.status,
            "workflow_type": env.workflow_type,
            "signing_level": env.signing_level,
            "category": getattr(env, "category", None),
            "sent_on": env.sent_on,
            "completed_on": env.completed_on,
            "expires_on": env.expires_on,
            "certificate_no": certificate_no,
            "original_hash": getattr(env, "canonical_sha256", None),
            "final_signed_pdf": getattr(env, "final_signed_pdf", None),
            "final_pdf_sha256": getattr(env, "final_pdf_sha256", None),
            "evidence_package": getattr(env, "evidence_package", None),
            "evidence_package_sha256": getattr(env, "evidence_package_sha256", None),
            "audit_root_hash": getattr(env, "audit_root_hash", None),
        },
        "recipients": recipients,
        "certificate_verification": certificate_verification,
        "audit_chain": audit_chain,
        "audit_logs_count": len(audit_logs),
        "audit_logs": audit_logs,
        "security_events_count": len(security_events),
        "security_events": security_events,
        "webhook_deliveries_count": len(webhook_deliveries),
        "webhook_deliveries": webhook_deliveries,
        "verdict_checks": verdict_checks,
        "compliance_passed": compliance_passed,
    }


@frappe.whitelist()
def export_envelope_compliance_json(envelope: str):
    from frappe.utils.file_manager import save_file

    report = envelope_compliance_report(envelope)
    raw = _phase19a_json_dumps(report)
    digest = _phase19a_sha256_text(raw)

    fname = f"{envelope}-compliance-report-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Envelope",
        dn=envelope,
        is_private=1,
    )

    add_audit(
        envelope=envelope,
        event_type="compliance.report_exported",
        actor_type="User",
        actor_user=frappe.session.user,
        actor_email=frappe.session.user,
        details={
            "file_url": file_doc.file_url,
            "sha256": digest,
            "report_type": "compliance_json",
            "schema_fix": "phase19a",
        },
    )

    frappe.db.commit()

    return {
        "ok": True,
        "envelope": envelope,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
    }


@frappe.whitelist()
def phase19a_compliance_quick_check(envelope: str):
    report = envelope_compliance_report(envelope)

    return {
        "ok": True,
        "envelope": envelope,
        "compliance_passed": report.get("compliance_passed"),
        "verdict_checks": report.get("verdict_checks"),
        "audit_logs_count": report.get("audit_logs_count"),
        "security_events_count": report.get("security_events_count"),
        "webhook_deliveries_count": report.get("webhook_deliveries_count"),
        "certificate_no": report.get("envelope", {}).get("certificate_no"),
    }


@frappe.whitelist()
def signature_system_health():
    readiness = production_readiness_report()

    status_counts = frappe.db.sql(
        """
        SELECT status, COUNT(*) AS count
        FROM `tabE-Sign Envelope`
        GROUP BY status
        ORDER BY status
        """,
        as_dict=True,
    )

    webhook_counts = frappe.db.sql(
        """
        SELECT status, COUNT(*) AS count
        FROM `tabE-Sign Webhook Delivery`
        GROUP BY status
        ORDER BY status
        """,
        as_dict=True,
    )

    security_counts = frappe.db.sql(
        """
        SELECT severity, COUNT(*) AS count
        FROM `tabE-Sign Security Event`
        GROUP BY severity
        ORDER BY severity
        """,
        as_dict=True,
    )

    latest_signed = frappe.get_all(
        "E-Sign Envelope",
        filters={"status": "Signed"},
        fields=["name", "title", "workflow_type", "certificate_no", "completed_on", "modified"],
        order_by="completed_on desc",
        limit=5,
    )

    failed_webhooks = frappe.db.count("E-Sign Webhook Delivery", {"status": "Failed"})
    invalid_certificates = 0

    recent_certs = frappe.get_all(
        "E-Sign Certificate",
        fields=["certificate_no"],
        order_by="creation desc",
        limit=10,
    )

    for c in recent_certs:
        try:
            res = verify_certificate(c.certificate_no)
            if not res.get("valid"):
                invalid_certificates += 1
        except Exception:
            invalid_certificates += 1

    health_ok = failed_webhooks == 0 and invalid_certificates == 0

    return {
        "ok": True,
        "health_ok": health_ok,
        "generated_at": str(now_datetime()),
        "production_readiness": readiness,
        "envelope_status_counts": status_counts,
        "webhook_delivery_counts": webhook_counts,
        "security_event_counts": security_counts,
        "latest_signed_envelopes": latest_signed,
        "failed_webhooks": failed_webhooks,
        "invalid_recent_certificates": invalid_certificates,
    }


# Phase 19B: reconcile legacy signed envelopes/certificates created before artifact hardening.
@frappe.whitelist()
def diagnose_certificates(limit: int = 50):
    certs = frappe.get_all(
        "E-Sign Certificate",
        fields=["certificate_no", "envelope", "creation"],
        order_by="creation desc",
        limit=int(limit or 50),
    )

    rows = []

    for c in certs:
        try:
            res = verify_certificate(c.certificate_no)
            rows.append({
                "certificate_no": c.certificate_no,
                "envelope": c.envelope,
                "valid": res.get("valid"),
                "audit_chain_valid": res.get("audit_chain_valid"),
                "file_integrity_valid": res.get("file_integrity_valid"),
                "final_signed_pdf": res.get("file_integrity", {}).get("final_signed_pdf"),
                "certificate_pdf": res.get("certificate_pdf"),
                "evidence_package": res.get("evidence_package"),
                "error": None,
            })
        except Exception as exc:
            rows.append({
                "certificate_no": c.certificate_no,
                "envelope": c.envelope,
                "valid": False,
                "audit_chain_valid": False,
                "file_integrity_valid": False,
                "error": str(exc),
            })

    invalid = [r for r in rows if not r.get("valid")]

    return {
        "ok": True,
        "total": len(rows),
        "invalid_count": len(invalid),
        "invalid": invalid,
        "certificates": rows,
    }


@frappe.whitelist()
def reconcile_legacy_signed_envelopes(force: int = 1):
    signed = frappe.get_all(
        "E-Sign Envelope",
        filters={"status": "Signed"},
        fields=[
            "name",
            "certificate_no",
            "final_signed_pdf",
            "evidence_package",
            "creation",
        ],
        order_by="creation asc",
        limit=100,
    )

    results = []

    for row in signed:
        needs_reconcile = bool(force) or not row.final_signed_pdf or not row.evidence_package

        if not needs_reconcile:
            results.append({
                "envelope": row.name,
                "skipped": True,
                "reason": "Artifacts already present.",
            })
            continue

        try:
            res = finalize_artifacts(envelope=row.name, force=1)

            add_audit(
                envelope=row.name,
                event_type="legacy.artifacts_reconciled",
                actor_type="System",
                details={
                    "phase": "19B",
                    "force": int(force or 0),
                    "result": res,
                },
            )

            results.append({
                "envelope": row.name,
                "certificate_no": res.get("certificate_no") or row.certificate_no,
                "ok": True,
                "artifact_version": res.get("artifact_version"),
                "final_signed_pdf": res.get("final_signed_pdf"),
                "certificate_pdf": res.get("certificate_pdf"),
                "evidence_package": res.get("evidence_package"),
            })

        except Exception as exc:
            frappe.log_error(frappe.get_traceback(), "Surhan Signature Phase 19B Legacy Reconcile Failed")
            results.append({
                "envelope": row.name,
                "certificate_no": row.certificate_no,
                "ok": False,
                "error": str(exc),
            })

    frappe.db.commit()

    return {
        "ok": True,
        "processed": len(results),
        "results": results,
        "diagnostics_after": diagnose_certificates(limit=100),
    }


# Phase 20A: production release gate and readiness snapshot.
import os as _phase20a_os
import json as _phase20a_json
import hashlib as _phase20a_hashlib


def _phase20a_json_dumps(data) -> str:
    return _phase20a_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase20a_sha256(text: str) -> str:
    return _phase20a_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase20a_role_exists(role: str) -> bool:
    return bool(frappe.db.exists("Role", role))


def _phase20a_doctype_exists(doctype: str) -> bool:
    return bool(frappe.db.exists("DocType", doctype))


def _phase20a_table_count(doctype: str, filters=None) -> int:
    if not _phase20a_doctype_exists(doctype):
        return 0
    return frappe.db.count(doctype, filters or {})


def _phase20a_latest_backup_info():
    backup_dir = frappe.get_site_path("private", "backups")
    items = []

    if not _phase20a_os.path.isdir(backup_dir):
        return {
            "backup_dir": backup_dir,
            "exists": False,
            "files_count": 0,
            "latest_file": None,
            "latest_mtime": None,
        }

    for fname in _phase20a_os.listdir(backup_dir):
        path = _phase20a_os.path.join(backup_dir, fname)
        if _phase20a_os.path.isfile(path):
            items.append({
                "file": fname,
                "mtime": _phase20a_os.path.getmtime(path),
                "size": _phase20a_os.path.getsize(path),
            })

    items.sort(key=lambda x: x["mtime"], reverse=True)

    latest = items[0] if items else None

    return {
        "backup_dir": backup_dir,
        "exists": True,
        "files_count": len(items),
        "latest_file": latest.get("file") if latest else None,
        "latest_mtime": frappe.utils.format_datetime(
            frappe.utils.get_datetime(
                frappe.utils.datetime.datetime.fromtimestamp(latest["mtime"])
            )
        ) if latest else None,
    }


def _phase20a_certificate_diagnostics():
    if "diagnose_certificates" in globals():
        return diagnose_certificates(limit=200)

    certs = frappe.get_all(
        "E-Sign Certificate",
        fields=["certificate_no", "envelope"],
        order_by="creation desc",
        limit=200,
    )

    rows = []

    for c in certs:
        try:
            res = verify_certificate(c.certificate_no)
            rows.append({
                "certificate_no": c.certificate_no,
                "envelope": c.envelope,
                "valid": bool(res.get("valid")),
                "audit_chain_valid": bool(res.get("audit_chain_valid")),
                "file_integrity_valid": bool(res.get("file_integrity_valid")),
                "error": None,
            })
        except Exception as exc:
            rows.append({
                "certificate_no": c.certificate_no,
                "envelope": c.envelope,
                "valid": False,
                "error": str(exc),
            })

    invalid = [r for r in rows if not r.get("valid")]

    return {
        "ok": True,
        "total": len(rows),
        "invalid_count": len(invalid),
        "invalid": invalid,
        "certificates": rows,
    }


def _phase20a_signed_envelope_audit_diagnostics():
    signed = frappe.get_all(
        "E-Sign Envelope",
        filters={"status": "Signed"},
        fields=["name", "certificate_no"],
        order_by="creation asc",
        limit=200,
    )

    rows = []

    for env in signed:
        try:
            res = check_audit_chain(env.name)
            rows.append({
                "envelope": env.name,
                "certificate_no": env.certificate_no,
                "valid": bool(res.get("valid")),
                "total_logs": res.get("total_logs"),
                "broken_at": res.get("broken_at"),
            })
        except Exception as exc:
            rows.append({
                "envelope": env.name,
                "certificate_no": env.certificate_no,
                "valid": False,
                "error": str(exc),
            })

    invalid = [r for r in rows if not r.get("valid")]

    return {
        "ok": True,
        "total": len(rows),
        "invalid_count": len(invalid),
        "invalid": invalid,
        "audit_chains": rows,
    }


@frappe.whitelist()
def production_release_gate(strict: int = 1):
    blockers = []
    warnings = []
    checks = {}

    readiness = production_readiness_report()

    checks["developer_mode"] = {
        "ok": not bool(readiness.get("settings", {}).get("developer_mode")),
        "value": readiness.get("settings", {}).get("developer_mode"),
    }

    if readiness.get("settings", {}).get("developer_mode"):
        blockers.append("developer_mode is enabled.")

    checks["email"] = readiness.get("email", {})
    if not readiness.get("email", {}).get("ready"):
        blockers.append("Default outgoing Email Account is not configured.")

    dev_links_visible = bool(readiness.get("settings", {}).get("expose_dev_signing_links"))
    dev_otp_visible = bool(readiness.get("settings", {}).get("expose_dev_otp"))

    checks["developer_outputs"] = {
        "dev_signing_links_hidden": not dev_links_visible,
        "dev_otp_hidden": not dev_otp_visible,
    }

    if dev_links_visible:
        blockers.append("Developer signing links are visible.")

    if dev_otp_visible:
        blockers.append("Developer OTP output is visible.")

    cert_diag = _phase20a_certificate_diagnostics()
    checks["certificates"] = {
        "ok": cert_diag.get("invalid_count", 0) == 0,
        "total": cert_diag.get("total", 0),
        "invalid_count": cert_diag.get("invalid_count", 0),
        "invalid": cert_diag.get("invalid", []),
    }

    if cert_diag.get("invalid_count", 0):
        blockers.append(f"{cert_diag.get('invalid_count')} certificate(s) failed verification.")

    audit_diag = _phase20a_signed_envelope_audit_diagnostics()
    checks["signed_envelope_audit_chains"] = {
        "ok": audit_diag.get("invalid_count", 0) == 0,
        "total": audit_diag.get("total", 0),
        "invalid_count": audit_diag.get("invalid_count", 0),
        "invalid": audit_diag.get("invalid", []),
    }

    if audit_diag.get("invalid_count", 0):
        blockers.append(f"{audit_diag.get('invalid_count')} signed envelope audit chain(s) failed.")

    failed_webhooks = _phase20a_table_count("E-Sign Webhook Delivery", {"status": "Failed"})
    checks["webhooks"] = {
        "failed_webhooks": failed_webhooks,
        "ok": failed_webhooks == 0,
    }

    if failed_webhooks:
        blockers.append(f"{failed_webhooks} failed webhook delivery record(s) exist.")

    required_roles = [
        "Signature Administrator",
        "Signature Manager",
        "Signature Sender",
        "Signature Auditor",
        "Signature Viewer",
    ]

    missing_roles = [r for r in required_roles if not _phase20a_role_exists(r)]

    checks["roles"] = {
        "ok": not missing_roles,
        "required": required_roles,
        "missing": missing_roles,
    }

    if missing_roles:
        blockers.append(f"Missing signature roles: {', '.join(missing_roles)}")

    workspace_exists = bool(
        frappe.db.exists("Workspace", {"label": "Surhan Signature"})
        or frappe.db.exists("Workspace", "Surhan Signature")
    )

    checks["workspace"] = {
        "ok": workspace_exists,
        "label": "Surhan Signature",
    }

    if not workspace_exists:
        blockers.append("Surhan Signature workspace is missing.")

    backup_info = _phase20a_latest_backup_info()
    checks["backups"] = backup_info

    if not backup_info.get("exists") or not backup_info.get("files_count"):
        warnings.append("No site backup files found in private/backups.")

    scheduler_paused = bool(frappe.conf.get("pause_scheduler"))
    checks["scheduler"] = {
        "ok": not scheduler_paused,
        "pause_scheduler": scheduler_paused,
    }

    if scheduler_paused:
        warnings.append("Scheduler appears paused.")

    counts = {
        "envelopes": _phase20a_table_count("E-Sign Envelope"),
        "signed_envelopes": _phase20a_table_count("E-Sign Envelope", {"status": "Signed"}),
        "sent_envelopes": _phase20a_table_count("E-Sign Envelope", {"status": "Sent"}),
        "declined_envelopes": _phase20a_table_count("E-Sign Envelope", {"status": "Declined"}),
        "certificates": _phase20a_table_count("E-Sign Certificate"),
        "audit_logs": _phase20a_table_count("E-Sign Audit Log"),
        "security_events": _phase20a_table_count("E-Sign Security Event"),
        "webhook_deliveries": _phase20a_table_count("E-Sign Webhook Delivery"),
    }

    if counts["sent_envelopes"]:
        warnings.append(f"{counts['sent_envelopes']} envelope(s) are still Sent/Pending completion.")

    release_ready = not blockers

    if int(strict or 0):
        production_ready = release_ready and readiness.get("production_ready")
    else:
        production_ready = release_ready

    return {
        "ok": True,
        "release_ready": release_ready,
        "production_ready": bool(production_ready),
        "strict": int(strict or 0),
        "generated_at": str(frappe.utils.now_datetime()),
        "site": frappe.local.site,
        "base_url": frappe.utils.get_url(),
        "blockers": blockers,
        "warnings": warnings,
        "checks": checks,
        "counts": counts,
        "next_required_actions": [
            "Configure default outgoing Email Account." if any("Email" in b or "email" in b for b in blockers) else None,
            "Disable developer_mode before production." if any("developer_mode" in b for b in blockers) else None,
            "Keep dev OTP/signing link outputs disabled." if dev_links_visible or dev_otp_visible else None,
            "Run a fresh bench backup immediately before go-live.",
        ],
    }


@frappe.whitelist()
def export_production_release_gate_json(strict: int = 1):
    from frappe.utils.file_manager import save_file

    report = production_release_gate(strict=strict)
    raw = _phase20a_json_dumps(report)
    digest = _phase20a_sha256(raw)

    fname = f"surhan-signature-release-gate-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "release_ready": report.get("release_ready"),
        "production_ready": report.get("production_ready"),
        "blockers": report.get("blockers"),
        "warnings": report.get("warnings"),
    }


@frappe.whitelist()
def set_signature_base_url(base_url: str):
    if frappe.session.user != "Administrator" and "System Manager" not in frappe.get_roles():
        frappe.throw(_("Only System Manager can update signing base URL."))

    if not base_url or not str(base_url).startswith(("http://", "https://")):
        frappe.throw(_("Base URL must start with http:// or https://"))

    frappe.db.set_single_value("E-Sign Settings", "signing_base_url", str(base_url).rstrip("/"))
    frappe.db.commit()

    return {
        "ok": True,
        "signing_base_url": str(base_url).rstrip("/"),
    }


# Phase 20B: backup / restore / monitoring runbook.
import os as _phase20b_os
import json as _phase20b_json
import hashlib as _phase20b_hashlib


def _phase20b_json_dumps(data) -> str:
    return _phase20b_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase20b_sha256(text: str) -> str:
    return _phase20b_hashlib.sha256((text or "").encode("utf-8")).hexdigest()












# Phase 20B-FIX: corrected public/private backup detection and restore commands.
import os as _phase20bfix_os
import json as _phase20bfix_json
import hashlib as _phase20bfix_hashlib


def _phase20bfix_backup_dir_abs():
    bench_path = frappe.utils.get_bench_path()
    return _phase20bfix_os.path.join(
        bench_path,
        "sites",
        frappe.local.site,
        "private",
        "backups",
    )


def _phase20b_backup_files():
    backup_dir = _phase20bfix_backup_dir_abs()
    files = []

    if not _phase20bfix_os.path.isdir(backup_dir):
        return {
            "backup_dir": backup_dir,
            "exists": False,
            "files": [],
        }

    for fname in _phase20bfix_os.listdir(backup_dir):
        path = _phase20bfix_os.path.join(backup_dir, fname)

        if not _phase20bfix_os.path.isfile(path):
            continue

        files.append({
            "file": fname,
            "path": path,
            "size_bytes": _phase20bfix_os.path.getsize(path),
            "mtime_epoch": _phase20bfix_os.path.getmtime(path),
            "mtime": str(
                frappe.utils.get_datetime(
                    frappe.utils.datetime.datetime.fromtimestamp(
                        _phase20bfix_os.path.getmtime(path)
                    )
                )
            ),
        })

    files.sort(key=lambda x: x["mtime_epoch"], reverse=True)

    return {
        "backup_dir": backup_dir,
        "exists": True,
        "files": files,
    }


def _phase20b_latest_backup_group():
    data = _phase20b_backup_files()
    files = data.get("files", [])

    def is_db(f):
        name = f["file"]
        return name.endswith(".sql.gz") or name.endswith(".sql")

    def is_public_files(f):
        name = f["file"]
        return (
            ("-files." in name or name.endswith("-files.tgz") or name.endswith("-files.tar"))
            and "-private-files" not in name
        )

    def is_private_files(f):
        name = f["file"]
        return "-private-files" in name

    def is_config(f):
        name = f["file"]
        return "site_config" in name or name.endswith(".json")

    latest_db = next((f for f in files if is_db(f)), None)
    latest_public = next((f for f in files if is_public_files(f)), None)
    latest_private = next((f for f in files if is_private_files(f)), None)
    latest_config = next((f for f in files if is_config(f)), None)

    return {
        "backup_dir": data.get("backup_dir"),
        "exists": data.get("exists"),
        "files_count": len(files),
        "latest_db": latest_db,
        "latest_public_files": latest_public,
        "latest_private_files": latest_private,
        "latest_config": latest_config,
        "latest_10": files[:10],
    }




@frappe.whitelist()
def backup_restore_monitoring_status():
    backups = _phase20b_latest_backup_group()

    health = signature_system_health()
    release_gate = production_release_gate(strict=1)

    expiring_soon = frappe.get_all(
        "E-Sign Envelope",
        filters=[
            ["status", "in", ["Sent", "Partially Signed"]],
            ["expires_on", "<=", frappe.utils.add_days(frappe.utils.now_datetime(), 2)],
        ],
        fields=["name", "title", "status", "workflow_type", "expires_on"],
        order_by="expires_on asc",
        limit=20,
    )

    failed_webhooks = frappe.db.count("E-Sign Webhook Delivery", {"status": "Failed"})
    medium_security_events = frappe.db.count("E-Sign Security Event", {"severity": "Medium"})
    pending_envelopes = frappe.db.count("E-Sign Envelope", {"status": "Sent"})

    monitoring_ok = (
        bool(backups.get("latest_db"))
        and bool(backups.get("latest_public_files"))
        and bool(backups.get("latest_private_files"))
        and bool(health.get("health_ok"))
        and failed_webhooks == 0
    )

    return {
        "ok": True,
        "schema_fix": "phase20b_fix_public_private_paths",
        "monitoring_ok": monitoring_ok,
        "generated_at": str(frappe.utils.now_datetime()),
        "site": frappe.local.site,
        "base_url": frappe.utils.get_url(),
        "backups": backups,
        "health": health,
        "release_gate": {
            "release_ready": release_gate.get("release_ready"),
            "production_ready": release_gate.get("production_ready"),
            "blockers": release_gate.get("blockers"),
            "warnings": release_gate.get("warnings"),
        },
        "operational_signals": {
            "failed_webhooks": failed_webhooks,
            "medium_security_events": medium_security_events,
            "pending_sent_envelopes": pending_envelopes,
            "expiring_soon_count": len(expiring_soon),
            "expiring_soon": expiring_soon,
        },
    }




# Phase 20B-FIX2: clean command formatting in Backup / Restore Runbook.
import json as _phase20bfix2_json
import hashlib as _phase20bfix2_hashlib


@frappe.whitelist()
def backup_restore_runbook():
    backups = _phase20b_latest_backup_group()

    latest_db = backups.get("latest_db") or {}
    latest_public = backups.get("latest_public_files") or {}
    latest_private = backups.get("latest_private_files") or {}

    db_path = latest_db.get("path", "/absolute/path/to/database.sql.gz")
    public_path = latest_public.get("path", "/absolute/path/to/public-files.tgz")
    private_path = latest_private.get("path", "/absolute/path/to/private-files.tgz")

    bench_path = frappe.utils.get_bench_path()
    site = frappe.local.site

    cd_cmd = "cd " + bench_path

    return {
        "ok": True,
        "schema_fix": "phase20b_fix2_clean_command_format",
        "title": "Surhan Signature Backup / Restore / Monitoring Runbook",
        "generated_at": str(frappe.utils.now_datetime()),
        "site": site,
        "bench_path": bench_path,
        "backup_location": backups.get("backup_dir"),
        "latest_backup_group": backups,
        "restore_policy": {
            "do_not_restore_on_live_without_approval": True,
            "always_take_fresh_backup_before_restore": True,
            "restore_should_be_tested_on_staging_first": True,
            "preferred_restore_method": "bench restore with --with-public-files and --with-private-files",
        },
        "backup_commands": [
            cd_cmd,
            f"bench --site {site} backup --with-files --compress",
            f"ls -lah sites/{site}/private/backups | tail -20",
        ],
        "restore_commands_template": [
            "IMPORTANT: run on staging first, not directly on production.",
            cd_cmd,
            f"bench --site {site} backup --with-files --compress",
            f"bench --site {site} restore {db_path} --with-public-files {public_path} --with-private-files {private_path}",
            f"bench --site {site} migrate",
            f"bench --site {site} clear-cache",
            "bench restart",
        ],
        "manual_restore_fallback": [
            "Use only if bench restore file flags are unavailable in this bench version.",
            cd_cmd,
            f"bench --site {site} restore {db_path}",
            f"mkdir -p sites/{site}/public/files sites/{site}/private/files",
            f"tar -xzf {public_path} -C sites/{site}/public/files || true",
            f"tar -xzf {private_path} -C sites/{site}/private/files || true",
            f"bench --site {site} migrate",
            f"bench --site {site} clear-cache",
            "bench restart",
        ],
        "post_restore_verification": [
            f"bench --site {site} execute surhan_signature.api.signature_system_health",
            f"bench --site {site} execute surhan_signature.api.production_release_gate --kwargs '{{\"strict\":1}}'",
            f"bench --site {site} execute surhan_signature.api.diagnose_certificates --kwargs '{{\"limit\":100}}'",
            f"bench --site {site} execute surhan_signature.api.webhook_delivery_summary --kwargs '{{\"limit\":20}}'",
        ],
        "monitoring_schedule_recommendation": {
            "daily": [
                "Run backup_restore_monitoring_status",
                "Check failed_webhooks",
                "Check invalid certificates",
                "Check expiring envelopes",
            ],
            "before_go_live": [
                "Run fresh backup",
                "Configure outgoing email",
                "Disable developer_mode",
                "Run production_release_gate strict=1",
            ],
        },
    }


@frappe.whitelist()
def export_backup_restore_runbook_json():
    from frappe.utils.file_manager import save_file

    runbook = backup_restore_runbook()
    raw = _phase20bfix2_json.dumps(
        runbook,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )
    digest = _phase20bfix2_hashlib.sha256(raw.encode("utf-8")).hexdigest()

    fname = f"surhan-signature-backup-restore-runbook-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "schema_fix": "phase20b_fix2_clean_command_format",
    }


# Phase 21: automated test suite for unit/API/security smoke validation.
import json as _phase21_json
import hashlib as _phase21_hashlib


def _phase21_json_dumps(data) -> str:
    return _phase21_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase21_sha256(text: str) -> str:
    return _phase21_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase21_add_result(results, name, category, status, details=None, error=None, severity="normal"):
    results.append({
        "name": name,
        "category": category,
        "status": status,
        "severity": severity,
        "details": details or {},
        "error": error,
    })


def _phase21_latest_signed_envelope():
    rows = frappe.get_all(
        "E-Sign Envelope",
        filters={"status": "Signed"},
        fields=["name", "certificate_no", "modified"],
        order_by="modified desc",
        limit=1,
    )

    return rows[0] if rows else None


def _phase21_required_doctypes():
    return [
        "E-Sign Envelope",
        "E-Sign Recipient",
        "E-Sign Signature Field",
        "E-Sign Audit Log",
        "E-Sign Certificate",
        "E-Sign Settings",
        "E-Sign Security Event",
        "E-Sign Webhook Endpoint",
        "E-Sign Webhook Delivery",
        "E-Sign Test Run",
    ]


def _phase21_required_apis():
    return [
        "health",
        "production_readiness_report",
        "production_release_gate",
        "signature_system_health",
        "backup_restore_monitoring_status",
        "backup_restore_runbook",
        "diagnose_certificates",
        "verify_certificate",
        "check_audit_chain",
        "envelope_compliance_report",
        "webhook_delivery_summary",
        "list_webhook_endpoints",
    ]


def _phase21_run_tests(mode="safe"):
    results = []

    # Unit/schema: required DocTypes
    try:
        missing = [dt for dt in _phase21_required_doctypes() if not frappe.db.exists("DocType", dt)]
        _phase21_add_result(
            results,
            "required_doctypes_exist",
            "unit",
            "passed" if not missing else "failed",
            {"missing": missing},
        )
    except Exception as exc:
        _phase21_add_result(results, "required_doctypes_exist", "unit", "failed", error=str(exc))

    # Unit/API: methods exist
    try:
        missing = [m for m in _phase21_required_apis() if m not in globals()]
        _phase21_add_result(
            results,
            "required_apis_exist",
            "api",
            "passed" if not missing else "failed",
            {"missing": missing},
        )
    except Exception as exc:
        _phase21_add_result(results, "required_apis_exist", "api", "failed", error=str(exc))

    # Health API
    try:
        res = signature_system_health()
        _phase21_add_result(
            results,
            "signature_system_health",
            "api",
            "passed" if res.get("health_ok") else "failed",
            {
                "health_ok": res.get("health_ok"),
                "failed_webhooks": res.get("failed_webhooks"),
                "invalid_recent_certificates": res.get("invalid_recent_certificates"),
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "signature_system_health", "api", "failed", error=str(exc))

    # Release gate integrity: allow only known environment blockers
    try:
        gate = production_release_gate(strict=1)
        blockers = gate.get("blockers") or []
        allowed = {
            "developer_mode is enabled.",
            "Default outgoing Email Account is not configured.",
        }
        unexpected = [b for b in blockers if b not in allowed]

        status = "passed" if not unexpected else "failed"

        _phase21_add_result(
            results,
            "production_release_gate_integrity",
            "api",
            status,
            {
                "release_ready": gate.get("release_ready"),
                "production_ready": gate.get("production_ready"),
                "blockers": blockers,
                "unexpected_blockers": unexpected,
                "warnings": gate.get("warnings"),
            },
            severity="release",
        )
    except Exception as exc:
        _phase21_add_result(results, "production_release_gate_integrity", "api", "failed", error=str(exc))

    # Certificate diagnostics
    try:
        diag = diagnose_certificates(limit=100)
        _phase21_add_result(
            results,
            "certificate_integrity_all_recent",
            "security",
            "passed" if diag.get("invalid_count") == 0 else "failed",
            {
                "total": diag.get("total"),
                "invalid_count": diag.get("invalid_count"),
                "invalid": diag.get("invalid"),
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "certificate_integrity_all_recent", "security", "failed", error=str(exc))

    # Latest signed envelope compliance
    try:
        latest = _phase21_latest_signed_envelope()

        if not latest:
            _phase21_add_result(results, "latest_signed_envelope_compliance", "compliance", "warning", {"reason": "No signed envelope found."})
        else:
            report = envelope_compliance_report(latest.name)
            _phase21_add_result(
                results,
                "latest_signed_envelope_compliance",
                "compliance",
                "passed" if report.get("compliance_passed") else "failed",
                {
                    "envelope": latest.name,
                    "certificate_no": latest.certificate_no,
                    "compliance_passed": report.get("compliance_passed"),
                    "verdict_checks": report.get("verdict_checks"),
                },
            )
    except Exception as exc:
        _phase21_add_result(results, "latest_signed_envelope_compliance", "compliance", "failed", error=str(exc))

    # Audit chain for all signed envelopes
    try:
        signed = frappe.get_all(
            "E-Sign Envelope",
            filters={"status": "Signed"},
            fields=["name", "certificate_no"],
            limit=200,
        )

        invalid = []

        for env in signed:
            res = check_audit_chain(env.name)
            if not res.get("valid"):
                invalid.append({
                    "envelope": env.name,
                    "certificate_no": env.certificate_no,
                    "result": res,
                })

        _phase21_add_result(
            results,
            "audit_chain_all_signed_envelopes",
            "security",
            "passed" if not invalid else "failed",
            {
                "total_signed": len(signed),
                "invalid_count": len(invalid),
                "invalid": invalid,
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "audit_chain_all_signed_envelopes", "security", "failed", error=str(exc))

    # Webhook state
    try:
        deliveries = webhook_delivery_summary(limit=100)
        failed = [
            d for d in deliveries.get("deliveries", [])
            if d.get("status") == "Failed"
        ]

        _phase21_add_result(
            results,
            "webhook_deliveries_no_failed",
            "integration",
            "passed" if not failed else "failed",
            {
                "total": deliveries.get("count"),
                "failed_count": len(failed),
                "failed": failed,
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "webhook_deliveries_no_failed", "integration", "failed", error=str(exc))

    # Optional full webhook test
    if str(mode) == "full":
        try:
            latest = _phase21_latest_signed_envelope()
            if latest:
                res = test_webhook_event(envelope=latest.name)
                ok = bool(res.get("ok")) and all(
                    item.get("ok") for item in res.get("delivered", [])
                )
                _phase21_add_result(
                    results,
                    "full_dry_run_webhook_emit",
                    "integration",
                    "passed" if ok else "failed",
                    res,
                )
            else:
                _phase21_add_result(results, "full_dry_run_webhook_emit", "integration", "warning", {"reason": "No signed envelope found."})
        except Exception as exc:
            _phase21_add_result(results, "full_dry_run_webhook_emit", "integration", "failed", error=str(exc))

    # Developer output security
    try:
        readiness = production_readiness_report()
        settings = readiness.get("settings") or {}

        hidden = (
            not bool(settings.get("expose_dev_signing_links"))
            and not bool(settings.get("expose_dev_otp"))
        )

        _phase21_add_result(
            results,
            "developer_outputs_hidden",
            "security",
            "passed" if hidden else "failed",
            {
                "expose_dev_signing_links": settings.get("expose_dev_signing_links"),
                "expose_dev_otp": settings.get("expose_dev_otp"),
                "developer_mode": settings.get("developer_mode"),
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "developer_outputs_hidden", "security", "failed", error=str(exc))

    # Invalid certificate must not verify as valid
    try:
        try:
            res = verify_certificate("ESIGN-CERT-DOES-NOT-EXIST")
            invalid_blocked = not bool(res.get("valid"))
        except Exception:
            invalid_blocked = True

        _phase21_add_result(
            results,
            "invalid_certificate_rejected",
            "security",
            "passed" if invalid_blocked else "failed",
            {"invalid_certificate_rejected": invalid_blocked},
        )
    except Exception as exc:
        _phase21_add_result(results, "invalid_certificate_rejected", "security", "failed", error=str(exc))

    # Invalid signing token should be rejected
    try:
        try:
            signing_link_info(token="invalid-token-phase21-test")
            invalid_token_rejected = False
        except Exception:
            invalid_token_rejected = True

        _phase21_add_result(
            results,
            "invalid_signing_token_rejected",
            "security",
            "passed" if invalid_token_rejected else "failed",
            {"invalid_token_rejected": invalid_token_rejected},
        )
    except Exception as exc:
        _phase21_add_result(results, "invalid_signing_token_rejected", "security", "failed", error=str(exc))

    # Backup/monitoring
    try:
        mon = backup_restore_monitoring_status()
        _phase21_add_result(
            results,
            "backup_restore_monitoring_ok",
            "operations",
            "passed" if mon.get("monitoring_ok") else "failed",
            {
                "monitoring_ok": mon.get("monitoring_ok"),
                "latest_db": (mon.get("backups") or {}).get("latest_db"),
                "latest_public_files": (mon.get("backups") or {}).get("latest_public_files"),
                "latest_private_files": (mon.get("backups") or {}).get("latest_private_files"),
                "failed_webhooks": (mon.get("operational_signals") or {}).get("failed_webhooks"),
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "backup_restore_monitoring_ok", "operations", "failed", error=str(exc))

    # Roles/workspace
    try:
        required_roles = [
            "Signature Administrator",
            "Signature Manager",
            "Signature Sender",
            "Signature Auditor",
            "Signature Viewer",
        ]

        missing_roles = [r for r in required_roles if not frappe.db.exists("Role", r)]
        workspace_exists = bool(
            frappe.db.exists("Workspace", {"label": "Surhan Signature"})
            or frappe.db.exists("Workspace", "Surhan Signature")
        )

        ok = not missing_roles and workspace_exists

        _phase21_add_result(
            results,
            "roles_and_workspace_ready",
            "access_control",
            "passed" if ok else "failed",
            {
                "missing_roles": missing_roles,
                "workspace_exists": workspace_exists,
            },
        )
    except Exception as exc:
        _phase21_add_result(results, "roles_and_workspace_ready", "access_control", "failed", error=str(exc))

    # Existing hardening tests if available
    for fn_name in ["test_audit_immutability", "test_envelope_lock"]:
        if fn_name in globals():
            try:
                fn = globals()[fn_name]
                latest = _phase21_latest_signed_envelope()

                try:
                    if latest:
                        res = fn(envelope=latest.name)
                    else:
                        res = {
                            "ok": False,
                            "reason": "No signed envelope found for hardening test.",
                        }
                except TypeError:
                    res = fn()
                _phase21_add_result(
                    results,
                    fn_name,
                    "security",
                    "passed" if res.get("ok") else "failed",
                    res,
                )
            except Exception as exc:
                _phase21_add_result(results, fn_name, "security", "failed", error=str(exc))
        else:
            _phase21_add_result(
                results,
                fn_name,
                "security",
                "warning",
                {"reason": "Optional hardening test function not found."},
            )

    return results


@frappe.whitelist()
def run_signature_test_suite(mode: str = "safe"):
    started_at = now_datetime()
    mode = str(mode or "safe").lower()

    if mode not in ("safe", "full"):
        frappe.throw(_("mode must be safe or full"))

    results = _phase21_run_tests(mode=mode)

    total = len(results)
    passed = len([r for r in results if r.get("status") == "passed"])
    failed = len([r for r in results if r.get("status") == "failed"])
    warnings = len([r for r in results if r.get("status") == "warning"])

    status = "Passed" if failed == 0 else "Failed"

    try:
        gate = production_release_gate(strict=1)
    except Exception:
        gate = {}

    report = {
        "ok": failed == 0,
        "suite": "signature_system",
        "mode": mode,
        "status": status,
        "started_at": str(started_at),
        "finished_at": str(now_datetime()),
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": failed,
        "warning_tests": warnings,
        "release_ready": gate.get("release_ready"),
        "production_ready": gate.get("production_ready"),
        "release_blockers": gate.get("blockers"),
        "release_warnings": gate.get("warnings"),
        "results": results,
    }

    raw = _phase21_json_dumps(report)
    digest = _phase21_sha256(raw)

    frappe.flags.in_signature_system_update = True
    try:
        doc = frappe.get_doc({
            "doctype": "E-Sign Test Run",
            "suite": "signature_system",
            "mode": mode,
            "status": status,
            "started_at": started_at,
            "finished_at": now_datetime(),
            "total_tests": total,
            "passed_tests": passed,
            "failed_tests": failed,
            "warning_tests": warnings,
            "release_ready": 1 if gate.get("release_ready") else 0,
            "production_ready": 1 if gate.get("production_ready") else 0,
            "result_sha256": digest,
            "result_json": raw,
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
        report["test_run"] = doc.name
        report["result_sha256"] = digest
    finally:
        frappe.flags.in_signature_system_update = False

    return report


@frappe.whitelist()
def latest_signature_test_runs(limit: int = 10):
    rows = frappe.get_all(
        "E-Sign Test Run",
        fields=[
            "name",
            "suite",
            "mode",
            "status",
            "started_at",
            "finished_at",
            "total_tests",
            "passed_tests",
            "failed_tests",
            "warning_tests",
            "release_ready",
            "production_ready",
            "result_sha256",
            "creation",
        ],
        order_by="creation desc",
        limit=int(limit or 10),
    )

    return {
        "ok": True,
        "count": len(rows),
        "test_runs": rows,
    }


@frappe.whitelist()
def export_signature_test_report_json(test_run: str | None = None):
    from frappe.utils.file_manager import save_file

    if not test_run:
        rows = frappe.get_all(
            "E-Sign Test Run",
            fields=["name"],
            order_by="creation desc",
            limit=1,
        )

        if not rows:
            frappe.throw(_("No test run found."))

        test_run = rows[0].name

    doc = frappe.get_doc("E-Sign Test Run", test_run)
    raw = doc.result_json or "{}"
    digest = _phase21_sha256(raw)

    fname = f"{test_run}-signature-test-report-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Test Run",
        dn=test_run,
        is_private=1,
    )

    return {
        "ok": True,
        "test_run": test_run,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
    }


# Phase 22: AI Risk Engine, deterministic rule-based version.
import json as _phase22_json
import hashlib as _phase22_hashlib


RISK_ENGINE_VERSION = "22.0-rule-based"


def _phase22_json_dumps(data) -> str:
    return _phase22_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase22_sha256(text: str) -> str:
    return _phase22_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase22_add_factor(factors, code, label, points, severity, evidence=None, action=None):
    factors.append({
        "code": code,
        "label": label,
        "points": int(points),
        "severity": severity,
        "evidence": evidence or {},
        "recommended_action": action,
    })


def _phase22_risk_level(score: int):
    score = int(score or 0)

    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _phase22_assessment_status(score: int):
    if score >= 80:
        return "Failed"
    if score >= 25:
        return "Warning"
    return "Passed"


def _phase22_safe_count(doctype, filters=None):
    if not frappe.db.exists("DocType", doctype):
        return 0
    return frappe.db.count(doctype, filters or {})


def _phase22_get_security_events(envelope):
    if not frappe.db.exists("DocType", "E-Sign Security Event"):
        return []

    return frappe.get_all(
        "E-Sign Security Event",
        filters={"envelope": envelope},
        fields=[
            "name",
            "event_type",
            "severity",
            "recipient_email",
            "token_hash_prefix",
            "ip_address",
            "timestamp_utc",
            "creation",
        ],
        order_by="creation asc",
        limit=1000,
    )


def _phase22_get_webhook_deliveries(envelope):
    if not frappe.db.exists("DocType", "E-Sign Webhook Delivery"):
        return []

    return frappe.get_all(
        "E-Sign Webhook Delivery",
        filters={"envelope": envelope},
        fields=[
            "name",
            "event_type",
            "status",
            "target_url",
            "attempt_count",
            "http_status",
            "error",
            "creation",
        ],
        order_by="creation asc",
        limit=500,
    )


def _phase22_certificate_no_for_envelope(env):
    cert = getattr(env, "certificate_no", None)

    if cert:
        return cert

    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": env.name})

    if cert_name:
        return frappe.db.get_value("E-Sign Certificate", cert_name, "certificate_no")

    return None


@frappe.whitelist()
def calculate_envelope_risk(envelope: str, save: int = 1):
    if not frappe.db.exists("E-Sign Envelope", envelope):
        frappe.throw(_("Envelope not found."))

    env = frappe.get_doc("E-Sign Envelope", envelope)
    certificate_no = _phase22_certificate_no_for_envelope(env)

    factors = []
    details = {
        "engine_version": RISK_ENGINE_VERSION,
        "envelope": envelope,
        "status": env.status,
        "workflow_type": env.workflow_type,
        "certificate_no": certificate_no,
        "generated_at": str(now_datetime()),
    }

    # Security event factors
    security_events = _phase22_get_security_events(envelope)
    details["security_events_count"] = len(security_events)

    otp_failed = [e for e in security_events if e.get("event_type") in ("otp.failed", "otp.invalid", "otp.invalid_token")]
    invalid_token = [e for e in security_events if "invalid_token" in str(e.get("event_type") or "")]
    medium_events = [e for e in security_events if e.get("severity") == "Medium"]
    high_events = [e for e in security_events if e.get("severity") in ("High", "Critical")]

    if otp_failed:
        points = min(25, 5 * len(otp_failed))
        _phase22_add_factor(
            factors,
            "OTP_FAILURES",
            "OTP failure attempts detected.",
            points,
            "Medium",
            {"count": len(otp_failed)},
            "Review signer verification attempts and confirm signer identity.",
        )

    if invalid_token:
        points = min(25, 8 * len(invalid_token))
        _phase22_add_factor(
            factors,
            "INVALID_TOKEN_ATTEMPTS",
            "Invalid signing token attempts detected.",
            points,
            "High",
            {"count": len(invalid_token)},
            "Review access logs and revoke/rotate affected signing links if needed.",
        )

    if medium_events:
        points = min(20, 5 * len(medium_events))
        _phase22_add_factor(
            factors,
            "MEDIUM_SECURITY_EVENTS",
            "Medium severity security events exist.",
            points,
            "Medium",
            {"count": len(medium_events)},
            "Review security event log.",
        )

    if high_events:
        points = min(40, 15 * len(high_events))
        _phase22_add_factor(
            factors,
            "HIGH_SECURITY_EVENTS",
            "High/Critical severity security events exist.",
            points,
            "Critical",
            {"count": len(high_events)},
            "Escalate to administrator before relying on this envelope.",
        )

    ip_values = sorted({e.get("ip_address") for e in security_events if e.get("ip_address")})
    details["distinct_security_ips"] = ip_values

    if len(ip_values) >= 3:
        _phase22_add_factor(
            factors,
            "MULTIPLE_IPS",
            "Multiple distinct IP addresses involved in signing/security events.",
            15,
            "Medium",
            {"distinct_ips": ip_values},
            "Confirm signers and access pattern.",
        )

    # Webhook factors
    webhook_deliveries = _phase22_get_webhook_deliveries(envelope)
    failed_webhooks = [w for w in webhook_deliveries if w.get("status") == "Failed"]
    details["webhook_deliveries_count"] = len(webhook_deliveries)
    details["failed_webhooks_count"] = len(failed_webhooks)

    if failed_webhooks:
        _phase22_add_factor(
            factors,
            "FAILED_WEBHOOKS",
            "Failed webhook deliveries exist.",
            min(25, 10 * len(failed_webhooks)),
            "Medium",
            {"count": len(failed_webhooks)},
            "Retry or investigate failed webhook deliveries.",
        )

    # Expiry / pending factors
    now_dt = now_datetime()

    if getattr(env, "expires_on", None):
        try:
            expires = get_datetime(env.expires_on)
            hours_left = (expires - now_dt).total_seconds() / 3600
            details["hours_to_expiry"] = round(hours_left, 2)

            if env.status in ("Sent", "Partially Signed") and hours_left < 0:
                _phase22_add_factor(
                    factors,
                    "EXPIRED_PENDING_ENVELOPE",
                    "Envelope is expired while still pending.",
                    40,
                    "High",
                    {"expires_on": env.expires_on},
                    "Expire or resend the envelope.",
                )
            elif env.status in ("Sent", "Partially Signed") and hours_left <= 48:
                _phase22_add_factor(
                    factors,
                    "NEAR_EXPIRY",
                    "Envelope is near expiry.",
                    15,
                    "Medium",
                    {"expires_on": env.expires_on, "hours_left": round(hours_left, 2)},
                    "Notify pending signers or extend the envelope if allowed.",
                )
        except Exception:
            pass

    if env.status in ("Sent", "Partially Signed") and getattr(env, "sent_on", None):
        try:
            sent_on = get_datetime(env.sent_on)
            days_pending = (now_dt - sent_on).total_seconds() / 86400
            details["days_pending"] = round(days_pending, 2)

            if days_pending >= 7:
                _phase22_add_factor(
                    factors,
                    "PENDING_TOO_LONG",
                    "Envelope has been pending for 7+ days.",
                    20,
                    "Medium",
                    {"days_pending": round(days_pending, 2)},
                    "Follow up with recipients or void/resend envelope.",
                )
        except Exception:
            pass

    if env.status == "Declined":
        _phase22_add_factor(
            factors,
            "DECLINED_ENVELOPE",
            "Envelope was declined.",
            20,
            "Medium",
            {"status": env.status},
            "Review decline reason and decide whether to recreate the envelope.",
        )

    # Signed envelope integrity factors
    audit_result = None

    try:
        audit_result = check_audit_chain(envelope)
        details["audit_chain"] = {
            "valid": audit_result.get("valid"),
            "total_logs": audit_result.get("total_logs"),
            "broken_at": audit_result.get("broken_at"),
        }

        if not audit_result.get("valid"):
            _phase22_add_factor(
                factors,
                "AUDIT_CHAIN_INVALID",
                "Audit hash chain is invalid.",
                80,
                "Critical",
                audit_result,
                "Do not rely on this envelope until investigated.",
            )
    except Exception as exc:
        _phase22_add_factor(
            factors,
            "AUDIT_CHAIN_CHECK_FAILED",
            "Audit chain check failed.",
            50,
            "High",
            {"error": str(exc)},
            "Investigate audit subsystem.",
        )

    if env.status == "Signed":
        if not certificate_no:
            _phase22_add_factor(
                factors,
                "SIGNED_WITHOUT_CERTIFICATE",
                "Signed envelope has no certificate.",
                80,
                "Critical",
                {},
                "Regenerate or reconcile certificate artifacts.",
            )
        else:
            try:
                cert_res = verify_certificate(certificate_no)
                details["certificate_verification"] = {
                    "valid": cert_res.get("valid"),
                    "audit_chain_valid": cert_res.get("audit_chain_valid"),
                    "file_integrity_valid": cert_res.get("file_integrity_valid"),
                }

                if not cert_res.get("valid"):
                    _phase22_add_factor(
                        factors,
                        "CERTIFICATE_INVALID",
                        "Certificate verification failed.",
                        80,
                        "Critical",
                        {
                            "certificate_no": certificate_no,
                            "audit_chain_valid": cert_res.get("audit_chain_valid"),
                            "file_integrity_valid": cert_res.get("file_integrity_valid"),
                        },
                        "Reconcile artifacts and investigate certificate integrity.",
                    )

                if not cert_res.get("file_integrity_valid"):
                    _phase22_add_factor(
                        factors,
                        "FILE_INTEGRITY_INVALID",
                        "Final PDF/certificate/evidence package integrity failed.",
                        80,
                        "Critical",
                        {"certificate_no": certificate_no},
                        "Do not rely on exported artifacts until repaired.",
                    )

            except Exception as exc:
                _phase22_add_factor(
                    factors,
                    "CERTIFICATE_CHECK_FAILED",
                    "Certificate verification check failed.",
                    60,
                    "High",
                    {"certificate_no": certificate_no, "error": str(exc)},
                    "Investigate certificate verification endpoint.",
                )

        if not getattr(env, "final_signed_pdf", None):
            _phase22_add_factor(
                factors,
                "MISSING_FINAL_PDF",
                "Signed envelope is missing final signed PDF.",
                60,
                "High",
                {},
                "Run artifact reconciliation.",
            )

        if not getattr(env, "evidence_package", None):
            _phase22_add_factor(
                factors,
                "MISSING_EVIDENCE_PACKAGE",
                "Signed envelope is missing evidence package.",
                60,
                "High",
                {},
                "Run artifact reconciliation.",
            )

    score = min(100, sum(int(f.get("points") or 0) for f in factors))
    risk_level = _phase22_risk_level(score)
    assessment_status = _phase22_assessment_status(score)

    recommended_actions = [
        f.get("recommended_action")
        for f in factors
        if f.get("recommended_action")
    ]

    result = {
        "ok": True,
        "engine_version": RISK_ENGINE_VERSION,
        "envelope": envelope,
        "certificate_no": certificate_no,
        "envelope_status": env.status,
        "risk_score": score,
        "risk_level": risk_level,
        "assessment_status": assessment_status,
        "risk_factors_count": len(factors),
        "risk_factors": factors,
        "recommended_actions": recommended_actions,
        "details": details,
    }

    raw = _phase22_json_dumps(result)
    digest = _phase22_sha256(raw)
    result["result_sha256"] = digest

    if int(save or 0):
        frappe.flags.in_signature_system_update = True
        try:
            doc = frappe.get_doc({
                "doctype": "E-Sign Risk Assessment",
                "envelope": envelope,
                "certificate_no": certificate_no,
                "envelope_status": env.status,
                "risk_score": score,
                "risk_level": risk_level,
                "assessment_status": assessment_status,
                "assessed_at": now_datetime(),
                "engine_version": RISK_ENGINE_VERSION,
                "risk_factors_count": len(factors),
                "risk_factors_json": _phase22_json.dumps(factors, ensure_ascii=False, indent=2, default=str),
                "recommended_actions_json": _phase22_json.dumps(recommended_actions, ensure_ascii=False, indent=2, default=str),
                "details_json": _phase22_json.dumps(details, ensure_ascii=False, indent=2, default=str),
                "result_sha256": digest,
            })
            doc.insert(ignore_permissions=True)
            frappe.db.commit()
            result["risk_assessment"] = doc.name
        finally:
            frappe.flags.in_signature_system_update = False

    return result


@frappe.whitelist()
def assess_all_envelope_risks(status_filter: str | None = None, limit: int = 100):
    filters = {}

    if status_filter:
        filters["status"] = status_filter

    rows = frappe.get_all(
        "E-Sign Envelope",
        filters=filters,
        fields=["name", "status", "modified"],
        order_by="modified desc",
        limit=int(limit or 100),
    )

    results = []

    for row in rows:
        try:
            results.append(calculate_envelope_risk(row.name, save=1))
        except Exception as exc:
            results.append({
                "ok": False,
                "envelope": row.name,
                "error": str(exc),
            })

    summary = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0,
        "Errors": 0,
    }

    for r in results:
        if not r.get("ok"):
            summary["Errors"] += 1
        else:
            summary[r.get("risk_level") or "Low"] = summary.get(r.get("risk_level") or "Low", 0) + 1

    return {
        "ok": True,
        "count": len(results),
        "summary": summary,
        "results": results,
    }


@frappe.whitelist()
def risk_dashboard_summary(limit: int = 20):
    latest = frappe.get_all(
        "E-Sign Risk Assessment",
        fields=[
            "name",
            "envelope",
            "certificate_no",
            "envelope_status",
            "risk_score",
            "risk_level",
            "assessment_status",
            "risk_factors_count",
            "assessed_at",
            "creation",
        ],
        order_by="creation desc",
        limit=int(limit or 20),
    )

    counts = frappe.db.sql(
        """
        SELECT risk_level, COUNT(*) AS count
        FROM `tabE-Sign Risk Assessment`
        GROUP BY risk_level
        ORDER BY risk_level
        """,
        as_dict=True,
    )

    high_or_critical = frappe.db.count(
        "E-Sign Risk Assessment",
        {"risk_level": ["in", ["High", "Critical"]]},
    )

    return {
        "ok": True,
        "latest_count": len(latest),
        "risk_level_counts": counts,
        "high_or_critical_count": high_or_critical,
        "latest_assessments": latest,
    }


@frappe.whitelist()
def export_envelope_risk_report_json(envelope: str):
    from frappe.utils.file_manager import save_file

    report = calculate_envelope_risk(envelope=envelope, save=1)
    raw = _phase22_json_dumps(report)
    digest = _phase22_sha256(raw)

    fname = f"{envelope}-risk-report-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Envelope",
        dn=envelope,
        is_private=1,
    )

    return {
        "ok": True,
        "envelope": envelope,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "risk_score": report.get("risk_score"),
        "risk_level": report.get("risk_level"),
    }


# Phase 22A: current risk snapshot, risk gate, and risk-aware test wrapper.
import json as _phase22a_json
import hashlib as _phase22a_hashlib


def _phase22a_json_dumps(data) -> str:
    return _phase22a_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase22a_sha256(text: str) -> str:
    return _phase22a_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase22a_latest_assessments_by_envelope(limit=1000):
    rows = frappe.get_all(
        "E-Sign Risk Assessment",
        fields=[
            "name",
            "envelope",
            "certificate_no",
            "envelope_status",
            "risk_score",
            "risk_level",
            "assessment_status",
            "risk_factors_count",
            "assessed_at",
            "result_sha256",
            "creation",
        ],
        order_by="creation desc",
        limit=int(limit or 1000),
    )

    latest = {}

    for row in rows:
        if not row.get("envelope"):
            continue

        if row.envelope not in latest:
            latest[row.envelope] = row

    return list(latest.values())


@frappe.whitelist()
def risk_current_snapshot(limit: int = 100):
    latest = _phase22a_latest_assessments_by_envelope(limit=1000)

    latest = latest[: int(limit or 100)]

    counts = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0,
        "Unknown": 0,
    }

    for row in latest:
        level = row.get("risk_level") or "Unknown"
        counts[level] = counts.get(level, 0) + 1

    high_or_critical = [
        row for row in latest
        if row.get("risk_level") in ("High", "Critical")
    ]

    medium = [
        row for row in latest
        if row.get("risk_level") == "Medium"
    ]

    return {
        "ok": True,
        "snapshot_type": "latest_assessment_per_envelope",
        "generated_at": str(now_datetime()),
        "current_envelopes_count": len(latest),
        "risk_level_counts": counts,
        "medium_count": len(medium),
        "high_or_critical_count": len(high_or_critical),
        "high_or_critical": high_or_critical,
        "medium": medium,
        "latest_assessments": latest,
    }


@frappe.whitelist()
def risk_release_gate(refresh: int = 1, limit: int = 100):
    if int(refresh or 0):
        assess_all_envelope_risks(limit=int(limit or 100))

    snapshot = risk_current_snapshot(limit=int(limit or 100))

    blockers = []
    warnings = []

    high_or_critical_count = snapshot.get("high_or_critical_count") or 0
    medium_count = snapshot.get("medium_count") or 0

    if high_or_critical_count:
        blockers.append(f"{high_or_critical_count} envelope(s) have High/Critical risk.")

    if medium_count:
        warnings.append(f"{medium_count} envelope(s) have Medium risk.")

    risk_ready = not blockers

    return {
        "ok": True,
        "risk_ready": risk_ready,
        "generated_at": str(now_datetime()),
        "blockers": blockers,
        "warnings": warnings,
        "snapshot": snapshot,
        "policy": {
            "Low": "Allowed",
            "Medium": "Allowed with review",
            "High": "Blocked until reviewed",
            "Critical": "Blocked",
        },
    }


@frappe.whitelist()
def export_risk_current_snapshot_json(refresh: int = 1, limit: int = 100):
    from frappe.utils.file_manager import save_file

    report = risk_release_gate(refresh=refresh, limit=limit)
    raw = _phase22a_json_dumps(report)
    digest = _phase22a_sha256(raw)

    fname = f"surhan-signature-current-risk-snapshot-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "risk_ready": report.get("risk_ready"),
        "blockers": report.get("blockers"),
        "warnings": report.get("warnings"),
    }


@frappe.whitelist()
def run_signature_test_suite_with_risk(mode: str = "safe"):
    base = run_signature_test_suite(mode=mode)
    risk_gate = risk_release_gate(refresh=1, limit=100)

    failed = int(base.get("failed_tests") or 0)
    risk_blockers = risk_gate.get("blockers") or []

    combined_ok = bool(base.get("ok")) and not risk_blockers

    return {
        "ok": combined_ok,
        "suite": "signature_system_with_risk",
        "mode": mode,
        "base_test_status": base.get("status"),
        "base_test_run": base.get("test_run"),
        "base_failed_tests": failed,
        "base_warning_tests": base.get("warning_tests"),
        "risk_ready": risk_gate.get("risk_ready"),
        "risk_blockers": risk_blockers,
        "risk_warnings": risk_gate.get("warnings"),
        "release_ready": base.get("release_ready"),
        "production_ready": base.get("production_ready"),
        "base_result_sha256": base.get("result_sha256"),
        "risk_snapshot": risk_gate.get("snapshot"),
    }


# Phase 23A: professional UI integration layer and frontend API contract.
import json as _phase23a_json
import hashlib as _phase23a_hashlib


def _phase23a_json_dumps(data) -> str:
    return _phase23a_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase23a_sha256(text: str) -> str:
    return _phase23a_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase23a_has_role():
    roles = set(frappe.get_roles() or [])

    allowed = {
        "System Manager",
        "Signature Administrator",
        "Signature Manager",
        "Signature Sender",
        "Signature Auditor",
        "Signature Viewer",
    }

    return bool(roles.intersection(allowed))


def _phase23a_require_ui_access():
    if frappe.session.user == "Guest":
        frappe.throw("Login required.")

    if not _phase23a_has_role():
        frappe.throw("You do not have access to Surhan Signature UI.")


@frappe.whitelist()
def ui_integration_manifest():
    _phase23a_require_ui_access()

    return {
        "ok": True,
        "app": "surhan_signature",
        "product": "Surhan Signature",
        "version": "23A-ui-integration-layer",
        "generated_at": str(now_datetime()),
        "ui_strategy": {
            "current_primary_ui": "Frappe Native",
            "legacy_react_status": "Prototype only; not deployed as production server.",
            "recommended_react_strategy": "Use React as a static authenticated frontend consuming Frappe whitelisted APIs, not the old Express server.",
            "reason": [
                "Frappe already owns auth, roles, permissions, files, audit, and CSRF/session security.",
                "Old React prototype contains mock/demo flows that should not replace server-side signing controls.",
                "Production UI should consume verified APIs only.",
            ],
        },
        "routes": {
            "admin_dashboard": "/signature-dashboard",
            "professional_console": "/signature-console",
            "signing_portal": "/sign?token=<secure-token>",
            "public_verification": "/verify?certificate_no=<certificate-no>",
            "desk_workspace": "/app/surhan-signature",
        },
        "capabilities": {
            "envelope_management": True,
            "external_signing_portal": True,
            "typed_signature": True,
            "drawn_signature": True,
            "uploaded_signature": True,
            "otp_server_side": True,
            "audit_hash_chain": True,
            "certificate_of_completion": True,
            "final_signed_pdf": True,
            "evidence_package": True,
            "public_verification": True,
            "webhooks_hmac": True,
            "risk_engine": True,
            "automated_tests": True,
            "backup_restore_monitoring": True,
            "production_release_gate": True,
        },
        "production_blockers_expected_now": [
            "developer_mode is enabled.",
            "Default outgoing Email Account is not configured.",
        ],
        "frontend_rules": [
            "Never trust client-side status.",
            "Never expose OTP in production.",
            "Never expose signing token except inside recipient-specific signing URL.",
            "Never send signature completion directly without verified OTP.",
            "Always use server-side audit events.",
            "Always verify certificate/file integrity from backend.",
        ],
    }


@frappe.whitelist()
def ui_frontend_api_contract():
    _phase23a_require_ui_access()

    return {
        "ok": True,
        "generated_at": str(now_datetime()),
        "auth": {
            "admin_console": "Authenticated Frappe session + Signature roles",
            "external_signing": "Secure signing token + server OTP",
            "public_verify": "Certificate number only; read-only endpoint",
        },
        "admin_console_apis": [
            {"method": "surhan_signature.api.signature_dashboard_summary", "purpose": "Dashboard summary"},
            {"method": "surhan_signature.api.signature_dashboard_details", "purpose": "Envelope details"},
            {"method": "surhan_signature.api.production_readiness_report", "purpose": "Production readiness"},
            {"method": "surhan_signature.api.production_release_gate", "purpose": "Strict production release gate"},
            {"method": "surhan_signature.api.signature_system_health", "purpose": "System health"},
            {"method": "surhan_signature.api.backup_restore_monitoring_status", "purpose": "Monitoring snapshot"},
            {"method": "surhan_signature.api.run_signature_test_suite", "purpose": "Automated tests"},
            {"method": "surhan_signature.api.risk_current_snapshot", "purpose": "Latest risk per envelope"},
            {"method": "surhan_signature.api.risk_release_gate", "purpose": "Risk blockers/warnings"},
            {"method": "surhan_signature.api.webhook_delivery_summary", "purpose": "Webhook delivery log"},
            {"method": "surhan_signature.api.ui_console_snapshot", "purpose": "Unified UI snapshot"},
        ],
        "signing_portal_apis": [
            {"method": "surhan_signature.api.signing_link_info", "purpose": "Read signing token status"},
            {"method": "surhan_signature.api.request_otp", "purpose": "Request OTP"},
            {"method": "surhan_signature.api.verify_otp", "purpose": "Verify OTP"},
            {"method": "surhan_signature.api.sign_typed", "purpose": "Typed signature completion"},
            {"method": "surhan_signature.api.sign_drawn", "purpose": "Drawn signature completion"},
            {"method": "surhan_signature.api.sign_uploaded", "purpose": "Uploaded signature completion"},
            {"method": "surhan_signature.api.decline_signing", "purpose": "Decline envelope"},
        ],
        "verification_apis": [
            {"method": "surhan_signature.api.verify_certificate", "purpose": "Certificate validation"},
            {"method": "surhan_signature.api.verify_artifacts", "purpose": "Artifact integrity validation"},
            {"method": "surhan_signature.api.envelope_compliance_report", "purpose": "Compliance report"},
        ],
        "response_policy": {
            "ok_true": "Request completed at API level.",
            "valid_true": "Certificate/signature/artifact is cryptographically or procedurally valid.",
            "release_ready_true": "No release blockers except deployment environment may still not be production.",
            "production_ready_true": "Ready after email configured and developer mode disabled.",
            "risk_ready_true": "No High/Critical risk envelopes.",
        },
    }


@frappe.whitelist()
def ui_console_snapshot():
    _phase23a_require_ui_access()

    snapshot = {
        "ok": True,
        "generated_at": str(now_datetime()),
        "user": frappe.session.user,
        "routes": {
            "admin_dashboard": "/signature-dashboard",
            "professional_console": "/signature-console",
            "desk_workspace": "/app/surhan-signature",
            "verification": "/verify",
            "signing": "/sign",
        },
    }

    def safe_call(key, fn, *args, **kwargs):
        try:
            snapshot[key] = fn(*args, **kwargs)
        except Exception as exc:
            snapshot[key] = {
                "ok": False,
                "error": str(exc),
            }

    safe_call("dashboard_summary", signature_dashboard_summary)
    safe_call("system_health", signature_system_health)
    safe_call("release_gate", production_release_gate, strict=1)
    safe_call("risk_gate", risk_release_gate, refresh=0, limit=100)
    safe_call("risk_snapshot", risk_current_snapshot, limit=100)
    safe_call("monitoring", backup_restore_monitoring_status)
    safe_call("latest_tests", latest_signature_test_runs, limit=5)
    safe_call("webhooks", webhook_delivery_summary, limit=10)

    return snapshot


@frappe.whitelist()
def export_ui_integration_manifest_json():
    from frappe.utils.file_manager import save_file

    manifest = ui_integration_manifest()
    contract = ui_frontend_api_contract()

    report = {
        "ok": True,
        "manifest": manifest,
        "api_contract": contract,
    }

    raw = _phase23a_json_dumps(report)
    digest = _phase23a_sha256(raw)

    fname = f"surhan-signature-ui-integration-manifest-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
    }


# Phase 24A: QR verification and certificate enhancement.
import io as _phase24a_io
import os as _phase24a_os
import json as _phase24a_json
import hashlib as _phase24a_hashlib
from urllib.parse import quote as _phase24a_quote


def _phase24a_json_dumps(data) -> str:
    return _phase24a_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase24a_sha256_bytes(data: bytes) -> str:
    return _phase24a_hashlib.sha256(data or b"").hexdigest()


def _phase24a_sha256_text(text: str) -> str:
    return _phase24a_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase24a_get_certificate_doc(certificate_no: str):
    name = (
        frappe.db.exists("E-Sign Certificate", {"certificate_no": certificate_no})
        or frappe.db.exists("E-Sign Certificate", certificate_no)
    )

    if not name:
        frappe.throw("Certificate not found.")

    return frappe.get_doc("E-Sign Certificate", name)


def _phase24a_base_url():
    base = None

    try:
        if frappe.db.exists("DocType", "E-Sign Settings"):
            base = frappe.db.get_single_value("E-Sign Settings", "signing_base_url")
    except Exception:
        base = None

    if not base:
        base = frappe.utils.get_url()

    return str(base).rstrip("/")


def _phase24a_verification_url(certificate_no: str):
    return f"{_phase24a_base_url()}/verify?certificate_no={_phase24a_quote(certificate_no)}"


def _phase24a_file_path(file_url: str):
    if not file_url:
        return None

    if file_url.startswith("/private/files/"):
        return frappe.get_site_path("private", "files", file_url.split("/private/files/", 1)[1])

    if file_url.startswith("/files/"):
        return frappe.get_site_path("public", "files", file_url.split("/files/", 1)[1])

    return None


def _phase24a_qr_drawing(value: str, size: int = 160):
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing

    qr = QrCodeWidget(value)
    bounds = qr.getBounds()
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]

    drawing = Drawing(
        size,
        size,
        transform=[
            size / float(width),
            0,
            0,
            size / float(height),
            0,
            0,
        ],
    )
    drawing.add(qr)

    return drawing


def _phase24a_qr_svg(value: str):
    from reportlab.graphics import renderSVG

    drawing = _phase24a_qr_drawing(value, size=180)
    svg = renderSVG.drawToString(drawing)

    if isinstance(svg, bytes):
        svg = svg.decode("utf-8")

    return svg


def _phase24a_qr_pdf(certificate_no: str, verification_url: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.graphics import renderPDF

    cert = _phase24a_get_certificate_doc(certificate_no)

    envelope = getattr(cert, "envelope", None)
    completed_at = getattr(cert, "completed_at", None)
    final_hash = getattr(cert, "final_hash", None)
    audit_root_hash = getattr(cert, "audit_root_hash", None)

    buffer = _phase24a_io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)

    width, height = A4

    c.setTitle(f"Verification QR Addendum - {certificate_no}")

    c.setFont("Helvetica-Bold", 18)
    c.drawString(25 * mm, height - 30 * mm, "Surhan Signature")
    c.setFont("Helvetica", 11)
    c.drawString(25 * mm, height - 38 * mm, "Certificate Verification QR Addendum")

    c.setLineWidth(0.7)
    c.line(25 * mm, height - 45 * mm, width - 25 * mm, height - 45 * mm)

    c.setFont("Helvetica-Bold", 11)
    y = height - 60 * mm

    fields = [
        ("Certificate No", certificate_no),
        ("Envelope", envelope or ""),
        ("Completed At", str(completed_at or "")),
        ("Verification URL", verification_url),
        ("Final Hash", final_hash or ""),
        ("Audit Root Hash", audit_root_hash or ""),
    ]

    for label, value in fields:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(25 * mm, y, f"{label}:")
        c.setFont("Helvetica", 9)
        text = str(value)

        if len(text) > 88:
            text = text[:88] + "..."

        c.drawString(62 * mm, y, text)
        y -= 8 * mm

    qr_drawing = _phase24a_qr_drawing(verification_url, size=170)
    renderPDF.draw(qr_drawing, c, 25 * mm, height - 150 * mm)

    c.setFont("Helvetica-Bold", 10)
    c.drawString(25 * mm, height - 160 * mm, "Scan to verify certificate authenticity.")

    c.setFont("Helvetica", 8)
    c.drawString(25 * mm, 25 * mm, "Generated by Surhan Signature. Verification is performed server-side.")

    c.showPage()
    c.save()

    return buffer.getvalue()






@frappe.whitelist()
def generate_all_certificate_qr_artifacts(limit: int = 100, force: int = 1):
    certs = frappe.get_all(
        "E-Sign Certificate",
        fields=["name", "certificate_no", "envelope"],
        order_by="creation desc",
        limit=int(limit or 100),
    )

    results = []

    for cert in certs:
        certificate_no = cert.get("certificate_no") or cert.get("name")

        try:
            results.append(generate_certificate_qr_artifacts(certificate_no, force=force))
        except Exception as exc:
            results.append({
                "ok": False,
                "certificate_no": certificate_no,
                "error": str(exc),
            })

    failed = [r for r in results if not r.get("ok")]

    return {
        "ok": not failed,
        "count": len(results),
        "failed_count": len(failed),
        "failed": failed,
        "results": results,
    }




@frappe.whitelist()
def export_certificate_qr_manifest_json():
    from frappe.utils.file_manager import save_file

    manifest = certificate_qr_status(limit=500)
    raw = _phase24a_json_dumps(manifest)
    digest = _phase24a_sha256_text(raw)

    fname = f"surhan-signature-certificate-qr-manifest-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "missing_or_invalid_count": manifest.get("missing_or_invalid_count"),
    }


# Phase 24A-FIX2: compute QR PDF SHA256 from the actual saved file, not pre-save bytes.
import os as _phase24a_fix2_os
import hashlib as _phase24a_fix2_hashlib


def _phase24a_fix2_file_path(file_url: str):
    if not file_url:
        return None

    if file_url.startswith("/private/files/"):
        return frappe.get_site_path("private", "files", file_url.split("/private/files/", 1)[1])

    if file_url.startswith("/files/"):
        return frappe.get_site_path("public", "files", file_url.split("/files/", 1)[1])

    return None


def _phase24a_fix2_sha256_file_url(file_url: str):
    path = _phase24a_fix2_file_path(file_url)

    if not path or not _phase24a_fix2_os.path.exists(path):
        return None

    h = _phase24a_fix2_hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


@frappe.whitelist()
def generate_certificate_qr_artifacts(certificate_no: str, force: int = 1):
    from frappe.utils.file_manager import save_file

    cert = _phase24a_get_certificate_doc(certificate_no)
    verification_url = _phase24a_verification_url(certificate_no)

    if not int(force or 0) and getattr(cert, "verification_qr_pdf", None):
        verify = verify_certificate_qr_artifacts(certificate_no)

        return {
            "ok": True,
            "skipped": True,
            "reason": "QR artifacts already exist.",
            "certificate_no": certificate_no,
            "verification_url": getattr(cert, "verification_url", None),
            "verification_qr_pdf": getattr(cert, "verification_qr_pdf", None),
            "verification_qr_pdf_sha256": getattr(cert, "verification_qr_pdf_sha256", None),
            "valid": verify.get("valid"),
        }

    qr_svg = _phase24a_qr_svg(verification_url)
    pdf_bytes = _phase24a_qr_pdf(certificate_no, verification_url)

    pre_save_sha = _phase24a_sha256_bytes(pdf_bytes)
    fname = f"{certificate_no}-verification-qr-{pre_save_sha[:8]}.pdf"

    file_doc = save_file(
        fname=fname,
        content=pdf_bytes,
        dt="E-Sign Certificate",
        dn=cert.name,
        is_private=1,
    )

    actual_sha = _phase24a_fix2_sha256_file_url(file_doc.file_url)

    if not actual_sha:
        frappe.throw("QR PDF file was saved but could not be read for SHA256 verification.")

    frappe.db.set_value(
        "E-Sign Certificate",
        cert.name,
        {
            "verification_url": verification_url,
            "verification_qr_svg": qr_svg,
            "verification_qr_pdf": file_doc.file_url,
            "verification_qr_pdf_sha256": actual_sha,
            "verification_qr_generated_at": frappe.utils.now_datetime(),
        },
        update_modified=False,
    )

    try:
        envelope = getattr(cert, "envelope", None)
        if envelope:
            add_audit(
                envelope=envelope,
                event_type="certificate.qr_generated",
                actor_type="System",
                details={
                    "phase": "24A-FIX2",
                    "certificate_no": certificate_no,
                    "verification_url": verification_url,
                    "verification_qr_pdf": file_doc.file_url,
                    "pre_save_sha256": pre_save_sha,
                    "saved_file_sha256": actual_sha,
                },
            )
    except Exception:
        pass

    frappe.db.commit()

    return {
        "ok": True,
        "phase_fix": "24A-FIX2",
        "certificate_no": certificate_no,
        "envelope": getattr(cert, "envelope", None),
        "verification_url": verification_url,
        "verification_qr_pdf": file_doc.file_url,
        "verification_qr_pdf_sha256": actual_sha,
        "pre_save_sha256": pre_save_sha,
        "sha_source": "saved_file",
        "verification_qr_svg_present": bool(qr_svg),
    }


@frappe.whitelist()
def verify_certificate_qr_artifacts(certificate_no: str):
    cert = _phase24a_get_certificate_doc(certificate_no)

    file_url = getattr(cert, "verification_qr_pdf", None)
    recorded = getattr(cert, "verification_qr_pdf_sha256", None)
    path = _phase24a_fix2_file_path(file_url)

    exists = bool(path and _phase24a_fix2_os.path.exists(path))
    actual = _phase24a_fix2_sha256_file_url(file_url) if exists else None

    valid = bool(exists and recorded and actual == recorded)

    return {
        "ok": True,
        "phase_fix": "24A-FIX2",
        "valid": valid,
        "certificate_no": certificate_no,
        "verification_url": getattr(cert, "verification_url", None),
        "verification_qr_pdf": file_url,
        "recorded_sha256": recorded,
        "actual_sha256": actual,
        "file_exists": exists,
        "sha_matches": bool(recorded and actual and recorded == actual),
    }


@frappe.whitelist()
def repair_certificate_qr_hashes(limit: int = 100):
    certs = frappe.get_all(
        "E-Sign Certificate",
        fields=[
            "name",
            "certificate_no",
            "envelope",
            "verification_qr_pdf",
            "verification_qr_pdf_sha256",
        ],
        order_by="creation desc",
        limit=int(limit or 100),
    )

    results = []

    for cert in certs:
        certificate_no = cert.get("certificate_no") or cert.get("name")
        file_url = cert.get("verification_qr_pdf")
        actual = _phase24a_fix2_sha256_file_url(file_url)

        if not file_url or not actual:
            results.append({
                "ok": False,
                "certificate_no": certificate_no,
                "reason": "Missing QR PDF or file not readable.",
                "verification_qr_pdf": file_url,
            })
            continue

        frappe.db.set_value(
            "E-Sign Certificate",
            cert.get("name"),
            "verification_qr_pdf_sha256",
            actual,
            update_modified=False,
        )

        results.append({
            "ok": True,
            "certificate_no": certificate_no,
            "verification_qr_pdf": file_url,
            "old_sha256": cert.get("verification_qr_pdf_sha256"),
            "new_sha256": actual,
            "changed": cert.get("verification_qr_pdf_sha256") != actual,
        })

    frappe.db.commit()

    return {
        "ok": True,
        "count": len(results),
        "failed_count": len([r for r in results if not r.get("ok")]),
        "results": results,
    }


@frappe.whitelist()
def certificate_qr_status(limit: int = 100):
    certs = frappe.get_all(
        "E-Sign Certificate",
        fields=[
            "name",
            "certificate_no",
            "envelope",
            "verification_url",
            "verification_qr_pdf",
            "verification_qr_pdf_sha256",
            "verification_qr_generated_at",
            "creation",
        ],
        order_by="creation desc",
        limit=int(limit or 100),
    )

    rows = []
    missing = []

    for cert in certs:
        certificate_no = cert.get("certificate_no") or cert.get("name")
        valid = verify_certificate_qr_artifacts(certificate_no)

        row = {
            "certificate_no": certificate_no,
            "envelope": cert.get("envelope"),
            "verification_url": cert.get("verification_url"),
            "verification_qr_pdf": cert.get("verification_qr_pdf"),
            "verification_qr_generated_at": cert.get("verification_qr_generated_at"),
            "valid": valid.get("valid"),
            "file_exists": valid.get("file_exists"),
            "sha_matches": valid.get("sha_matches"),
            "recorded_sha256": valid.get("recorded_sha256"),
            "actual_sha256": valid.get("actual_sha256"),
        }

        rows.append(row)

        if not row["valid"]:
            missing.append(row)

    return {
        "ok": True,
        "phase_fix": "24A-FIX2",
        "count": len(rows),
        "valid_count": len([r for r in rows if r.get("valid")]),
        "missing_or_invalid_count": len(missing),
        "missing_or_invalid": missing,
        "certificates": rows,
    }


# Phase 24B: enhanced public verification page and safe verification bundles.
import json as _phase24b_json
import hashlib as _phase24b_hashlib


def _phase24b_json_dumps(data) -> str:
    return _phase24b_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase24b_sha256(text: str) -> str:
    return _phase24b_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase24b_certificate_doc(certificate_no: str):
    if not certificate_no:
        frappe.throw("Certificate number is required.")

    name = (
        frappe.db.exists("E-Sign Certificate", {"certificate_no": certificate_no})
        or frappe.db.exists("E-Sign Certificate", certificate_no)
    )

    if not name:
        frappe.throw("Certificate not found.")

    return frappe.get_doc("E-Sign Certificate", name)


def _phase24b_has_admin_verify_access():
    if frappe.session.user == "Guest":
        return False

    roles = set(frappe.get_roles() or [])

    allowed = {
        "System Manager",
        "Signature Administrator",
        "Signature Manager",
        "Signature Sender",
        "Signature Auditor",
        "Signature Viewer",
    }

    return bool(roles.intersection(allowed))


def _phase24b_safe_verify_certificate(certificate_no: str):
    try:
        res = verify_certificate(certificate_no=certificate_no)
        return res
    except TypeError:
        res = verify_certificate(certificate_no)
        return res
    except Exception as exc:
        return {
            "ok": False,
            "valid": False,
            "error": str(exc),
        }


@frappe.whitelist(allow_guest=True)
def public_verify_certificate_bundle(certificate_no: str):
    from surhan_signature.security.file_security import assert_public_payload_safe

    cert = _phase24b_certificate_doc(certificate_no)

    verify = _phase24b_safe_verify_certificate(certificate_no)

    qr_status = {}
    try:
        qr_status = verify_certificate_qr_artifacts(certificate_no)
    except Exception as exc:
        qr_status = {
            "ok": False,
            "valid": False,
            "error": str(exc),
        }

    envelope = getattr(cert, "envelope", None)

    public_bundle = {
        "ok": True,
        "public": True,
        "generated_at": str(frappe.utils.now_datetime()),
        "certificate_no": certificate_no,
        "envelope": envelope,
        "completed_at": str(getattr(cert, "completed_at", "") or ""),
        "verification_url": getattr(cert, "verification_url", None) or _phase24a_verification_url(certificate_no),
        "verification_qr_svg": getattr(cert, "verification_qr_svg", None),
        "verification_qr_valid": bool(qr_status.get("valid")),
        "certificate_valid": bool(verify.get("valid")),
        "audit_chain_valid": bool(verify.get("audit_chain_valid")),
        "file_integrity_valid": bool(verify.get("file_integrity_valid")),
        "final_hash": verify.get("final_hash") or getattr(cert, "final_hash", None),
        "original_hash": verify.get("original_hash") or getattr(cert, "original_hash", None),
        "audit_root_hash": verify.get("audit_root_hash") or getattr(cert, "audit_root_hash", None),
        "certificate_pdf_sha256": verify.get("certificate_pdf_sha256") or getattr(cert, "certificate_pdf_sha256", None),
        "evidence_package_sha256": verify.get("evidence_package_sha256") or getattr(cert, "evidence_package_sha256", None),
        "qr_pdf_sha256": getattr(cert, "verification_qr_pdf_sha256", None),
        "status": "Valid" if verify.get("valid") and qr_status.get("valid") else "Invalid",
        "privacy_note": "Private certificate files and evidence packages are not exposed on the public verification page.",
    }

    assert_public_payload_safe(public_bundle)
    public_bundle["bundle_sha256"] = _phase24b_sha256(_phase24b_json_dumps(public_bundle))

    return public_bundle


@frappe.whitelist()
def admin_verify_certificate_bundle(certificate_no: str):
    if not _phase24b_has_admin_verify_access():
        frappe.throw("You do not have access to admin verification details.")

    public_bundle = public_verify_certificate_bundle(certificate_no)
    cert = _phase24b_certificate_doc(certificate_no)

    admin_files = {
        "certificate_pdf": getattr(cert, "certificate_pdf", None),
        "evidence_package": getattr(cert, "evidence_package", None),
        "verification_qr_pdf": getattr(cert, "verification_qr_pdf", None),
        "final_signed_pdf": None,
    }

    envelope = getattr(cert, "envelope", None)

    if envelope and frappe.db.exists("E-Sign Envelope", envelope):
        try:
            env = frappe.get_doc("E-Sign Envelope", envelope)
            admin_files["final_signed_pdf"] = getattr(env, "final_signed_pdf", None)
        except Exception:
            pass

    public_bundle["public"] = False
    public_bundle["admin_files"] = admin_files
    public_bundle["admin_note"] = "Private artifact links are visible only to authenticated authorized users."
    public_bundle["bundle_sha256"] = _phase24b_sha256(_phase24b_json_dumps(public_bundle))

    return public_bundle


@frappe.whitelist(allow_guest=True)
def public_verify_page_health():
    return {
        "ok": True,
        "page": "/verify",
        "generated_at": str(frappe.utils.now_datetime()),
        "message": "Surhan Signature public verification page is available.",
    }


@frappe.whitelist()
def export_public_verification_bundle_json(certificate_no: str):
    from frappe.utils.file_manager import save_file

    if not _phase24b_has_admin_verify_access():
        frappe.throw("You do not have access to export verification bundle.")

    bundle = admin_verify_certificate_bundle(certificate_no)
    raw = _phase24b_json_dumps(bundle)
    digest = _phase24b_sha256(raw)

    fname = f"{certificate_no}-public-verification-bundle-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Certificate",
        dn=_phase24b_certificate_doc(certificate_no).name,
        is_private=1,
    )

    return {
        "ok": True,
        "certificate_no": certificate_no,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
    }


# Phase 25A: production finalization toolkit and go-live manifest.
import json as _phase25a_json
import hashlib as _phase25a_hashlib


def _phase25a_json_dumps(data) -> str:
    return _phase25a_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase25a_sha256(text: str) -> str:
    return _phase25a_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase25a_is_test_envelope(row):
    text = " ".join([
        str(row.get("name") or ""),
        str(row.get("title") or ""),
    ]).lower()

    markers = [
        "test",
        "phase",
        "demo",
        "otp security",
        "security event",
        "decline",
        "workflow test",
    ]

    return any(m in text for m in markers)


@frappe.whitelist()
def identify_non_production_envelopes(limit: int = 200):
    rows = frappe.get_all(
        "E-Sign Envelope",
        fields=[
            "name",
            "title",
            "status",
            "workflow_type",
            "certificate_no",
            "sent_on",
            "completed_on",
            "expires_on",
            "creation",
            "modified",
        ],
        order_by="creation asc",
        limit=int(limit or 200),
    )

    test_like = []
    pending = []
    signed = []
    declined = []
    draft = []

    for row in rows:
        item = dict(row)
        item["test_like"] = _phase25a_is_test_envelope(item)

        if item["test_like"]:
            test_like.append(item)

        if item.get("status") in ("Sent", "Partially Signed"):
            pending.append(item)

        if item.get("status") == "Signed":
            signed.append(item)

        if item.get("status") == "Declined":
            declined.append(item)

        if item.get("status") == "Draft":
            draft.append(item)

    return {
        "ok": True,
        "total": len(rows),
        "test_like_count": len(test_like),
        "pending_count": len(pending),
        "signed_count": len(signed),
        "declined_count": len(declined),
        "draft_count": len(draft),
        "test_like": test_like,
        "pending": pending,
        "signed": signed,
        "declined": declined,
        "draft": draft,
        "recommendation": [
            "Before production, review test-like envelopes.",
            "Do not delete signed envelopes if they are needed for audit evidence.",
            "Void/expire pending demo envelopes only after explicit approval.",
            "Keep historical test records if this is a staging/dev system.",
        ],
    }


@frappe.whitelist()
def production_final_snapshot():
    health = signature_system_health()
    release_gate = production_release_gate(strict=1)
    risk_gate = risk_release_gate(refresh=1, limit=200)
    tests = run_signature_test_suite_with_risk(mode="safe")
    qr_status = certificate_qr_status(limit=200)
    verify_health = public_verify_page_health()
    monitoring = backup_restore_monitoring_status()
    non_prod = identify_non_production_envelopes(limit=200)

    final_blockers = []

    if not health.get("health_ok"):
        final_blockers.append("System health failed.")

    if not release_gate.get("release_ready"):
        final_blockers.extend(release_gate.get("blockers") or [])

    if not risk_gate.get("risk_ready"):
        final_blockers.extend(risk_gate.get("blockers") or [])

    if not tests.get("ok"):
        final_blockers.append("Automated test suite with risk failed.")

    if qr_status.get("missing_or_invalid_count"):
        final_blockers.append("One or more certificate QR artifacts are missing or invalid.")

    if not monitoring.get("monitoring_ok"):
        final_blockers.append("Backup/restore monitoring status is not OK.")

    warnings = []

    warnings.extend(release_gate.get("warnings") or [])
    warnings.extend(risk_gate.get("warnings") or [])

    if non_prod.get("pending_count"):
        warnings.append(f"{non_prod.get('pending_count')} envelope(s) are pending.")

    if non_prod.get("test_like_count"):
        warnings.append(f"{non_prod.get('test_like_count')} test-like envelope(s) detected.")

    snapshot = {
        "ok": True,
        "generated_at": str(now_datetime()),
        "site": frappe.local.site,
        "base_url": frappe.utils.get_url(),
        "production_final_ready": not final_blockers,
        "production_environment_ready": bool(release_gate.get("production_ready")),
        "final_blockers": final_blockers,
        "warnings": warnings,
        "health": health,
        "release_gate": release_gate,
        "risk_gate": risk_gate,
        "tests_with_risk": tests,
        "certificate_qr_status": qr_status,
        "public_verify_page_health": verify_health,
        "monitoring": monitoring,
        "non_production_envelopes": non_prod,
    }

    snapshot["snapshot_sha256"] = _phase25a_sha256(_phase25a_json_dumps(snapshot))

    return snapshot


@frappe.whitelist()
def production_go_live_checklist():
    snapshot = production_final_snapshot()

    checklist = [
        {
            "item": "System health",
            "status": "Passed" if snapshot.get("health", {}).get("health_ok") else "Failed",
            "required": True,
        },
        {
            "item": "Certificate and artifact integrity",
            "status": "Passed" if snapshot.get("health", {}).get("invalid_recent_certificates") == 0 else "Failed",
            "required": True,
        },
        {
            "item": "QR verification artifacts",
            "status": "Passed" if snapshot.get("certificate_qr_status", {}).get("missing_or_invalid_count") == 0 else "Failed",
            "required": True,
        },
        {
            "item": "Risk release gate",
            "status": "Passed" if snapshot.get("risk_gate", {}).get("risk_ready") else "Failed",
            "required": True,
        },
        {
            "item": "Automated tests with risk",
            "status": "Passed" if snapshot.get("tests_with_risk", {}).get("ok") else "Failed",
            "required": True,
        },
        {
            "item": "Webhook failures",
            "status": "Passed" if snapshot.get("health", {}).get("failed_webhooks") == 0 else "Failed",
            "required": True,
        },
        {
            "item": "Backup/restore monitoring",
            "status": "Passed" if snapshot.get("monitoring", {}).get("monitoring_ok") else "Failed",
            "required": True,
        },
        {
            "item": "Outgoing email account",
            "status": "Passed" if snapshot.get("release_gate", {}).get("checks", {}).get("email", {}).get("ready") else "Blocked",
            "required": True,
        },
        {
            "item": "Developer mode disabled",
            "status": "Passed" if snapshot.get("release_gate", {}).get("checks", {}).get("developer_mode", {}).get("ok") else "Blocked",
            "required": True,
        },
        {
            "item": "Pending/test-like envelopes reviewed",
            "status": "Review" if snapshot.get("non_production_envelopes", {}).get("pending_count") or snapshot.get("non_production_envelopes", {}).get("test_like_count") else "Passed",
            "required": False,
        },
    ]

    return {
        "ok": True,
        "generated_at": str(now_datetime()),
        "production_final_ready": snapshot.get("production_final_ready"),
        "production_environment_ready": snapshot.get("production_environment_ready"),
        "final_blockers": snapshot.get("final_blockers"),
        "warnings": snapshot.get("warnings"),
        "checklist": checklist,
        "next_human_actions": [
            "Configure default outgoing Email Account in Frappe.",
            "Send a test signature email and confirm delivery.",
            "Set signing_base_url to the final public HTTPS domain.",
            "Run fresh bench backup immediately before go-live.",
            "Disable developer_mode only after email/domain are confirmed.",
            "Run production_go_live_checklist again.",
        ],
    }


@frappe.whitelist()
def export_production_go_live_manifest_json():
    from frappe.utils.file_manager import save_file

    manifest = {
        "ok": True,
        "snapshot": production_final_snapshot(),
        "checklist": production_go_live_checklist(),
    }

    raw = _phase25a_json_dumps(manifest)
    digest = _phase25a_sha256(raw)

    fname = f"surhan-signature-go-live-manifest-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "production_final_ready": manifest.get("snapshot", {}).get("production_final_ready"),
        "production_environment_ready": manifest.get("snapshot", {}).get("production_environment_ready"),
        "final_blockers": manifest.get("snapshot", {}).get("final_blockers"),
        "warnings": manifest.get("snapshot", {}).get("warnings"),
    }


@frappe.whitelist()
def final_smoke_check():
    return {
        "ok": True,
        "generated_at": str(now_datetime()),
        "health": signature_system_health().get("health_ok"),
        "tests_with_risk": run_signature_test_suite_with_risk(mode="safe").get("ok"),
        "risk_ready": risk_release_gate(refresh=1, limit=200).get("risk_ready"),
        "qr_valid": certificate_qr_status(limit=200).get("missing_or_invalid_count") == 0,
        "public_verify": public_verify_certificate_bundle("ESIGN-CERT-2026-00004").get("status") == "Valid",
        "release_gate": production_release_gate(strict=1).get("release_ready"),
        "production_ready": production_release_gate(strict=1).get("production_ready"),
    }


# Phase 25B: production environment control layer and dry-run go-live decision.
import json as _phase25b_json
import hashlib as _phase25b_hashlib
from urllib.parse import urlparse as _phase25b_urlparse


def _phase25b_json_dumps(data) -> str:
    return _phase25b_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase25b_sha256(text: str) -> str:
    return _phase25b_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase25b_current_signing_base_url():
    try:
        value = frappe.db.get_single_value("E-Sign Settings", "signing_base_url")
        if value:
            return str(value).rstrip("/")
    except Exception:
        pass

    return frappe.utils.get_url().rstrip("/")


def _phase25b_url_status(url: str):
    parsed = _phase25b_urlparse(str(url or ""))

    is_https = parsed.scheme == "https"
    host = parsed.netloc or parsed.path

    local_hosts = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "ysmo",
    }

    is_local = host.split(":")[0] in local_hosts or host.startswith("192.168.")

    return {
        "url": url,
        "scheme": parsed.scheme,
        "host": host,
        "is_https": is_https,
        "is_local_or_dev": is_local,
        "production_acceptable": bool(is_https and not is_local),
    }


def _phase25b_latest_backup_age_hours():
    try:
        mon = backup_restore_monitoring_status()
        latest_db = (mon.get("backups") or {}).get("latest_db") or {}
        mtime_epoch = latest_db.get("mtime_epoch")

        if not mtime_epoch:
            return {
                "ok": False,
                "reason": "No latest DB backup mtime found.",
                "latest_db": latest_db,
            }

        import time
        age_hours = (time.time() - float(mtime_epoch)) / 3600

        return {
            "ok": True,
            "age_hours": round(age_hours, 2),
            "fresh_24h": age_hours <= 24,
            "latest_db": latest_db,
        }
    except Exception as exc:
        return {
            "ok": False,
            "reason": str(exc),
        }


@frappe.whitelist()
def production_environment_matrix(public_base_url: str | None = None):
    current_url = _phase25b_current_signing_base_url()
    candidate_url = str(public_base_url).rstrip("/") if public_base_url else current_url

    current_url_status = _phase25b_url_status(current_url)
    candidate_url_status = _phase25b_url_status(candidate_url)

    readiness = production_readiness_report()
    release_gate = production_release_gate(strict=1)
    final_snapshot = production_final_snapshot()
    backup_age = _phase25b_latest_backup_age_hours()

    blockers = []
    warnings = []

    email_ready = bool((readiness.get("email") or {}).get("ready"))
    developer_mode = bool((readiness.get("settings") or {}).get("developer_mode"))
    dev_links_visible = bool((readiness.get("settings") or {}).get("expose_dev_signing_links"))
    dev_otp_visible = bool((readiness.get("settings") or {}).get("expose_dev_otp"))

    if not email_ready:
        blockers.append("Default outgoing Email Account is not configured.")

    if developer_mode:
        blockers.append("developer_mode is enabled.")

    if dev_links_visible:
        blockers.append("Developer signing links are visible.")

    if dev_otp_visible:
        blockers.append("Developer OTP output is visible.")

    if not candidate_url_status.get("production_acceptable"):
        blockers.append("Production signing_base_url must be a public HTTPS URL.")

    if not backup_age.get("fresh_24h"):
        warnings.append("Latest DB backup is older than 24 hours or backup age could not be determined.")

    if release_gate.get("warnings"):
        warnings.extend(release_gate.get("warnings") or [])

    if final_snapshot.get("warnings"):
        for w in final_snapshot.get("warnings") or []:
            if w not in warnings:
                warnings.append(w)

    environment_ready = not blockers

    return {
        "ok": True,
        "generated_at": str(now_datetime()),
        "site": frappe.local.site,
        "environment_ready": environment_ready,
        "production_ready": bool(environment_ready and final_snapshot.get("production_final_ready")),
        "blockers": blockers,
        "warnings": warnings,
        "current_signing_base_url": current_url,
        "candidate_signing_base_url": candidate_url,
        "current_url_status": current_url_status,
        "candidate_url_status": candidate_url_status,
        "email_ready": email_ready,
        "developer_mode": developer_mode,
        "developer_outputs": {
            "expose_dev_signing_links": int(dev_links_visible),
            "expose_dev_otp": int(dev_otp_visible),
        },
        "backup_age": backup_age,
        "release_gate": {
            "release_ready": release_gate.get("release_ready"),
            "production_ready": release_gate.get("production_ready"),
            "blockers": release_gate.get("blockers"),
            "warnings": release_gate.get("warnings"),
        },
        "final_snapshot": {
            "production_final_ready": final_snapshot.get("production_final_ready"),
            "production_environment_ready": final_snapshot.get("production_environment_ready"),
            "final_blockers": final_snapshot.get("final_blockers"),
            "warnings": final_snapshot.get("warnings"),
        },
    }


@frappe.whitelist()
def production_go_live_commands(public_base_url: str):
    if not public_base_url:
        frappe.throw("public_base_url is required, for example: https://sign.example.com")

    matrix = production_environment_matrix(public_base_url=public_base_url)

    site = frappe.local.site
    base_url = str(public_base_url).rstrip("/")

    commands = [
        "cd " + frappe.utils.get_bench_path(),
        f"bench --site {site} backup --with-files --compress",
        f"bench --site {site} execute surhan_signature.api.set_signature_base_url --kwargs '{{\"base_url\":\"{base_url}\"}}'",
        f"bench --site {site} execute surhan_signature.api.disable_developer_outputs",
        f"bench --site {site} execute surhan_signature.api.send_test_signature_email --kwargs '{{\"to\":\"YOUR_EMAIL@example.com\"}}'",
        "# Confirm the test email was delivered before continuing.",
        f"bench --site {site} set-config developer_mode 0",
        f"bench --site {site} clear-cache",
        f"bench --site {site} clear-website-cache",
        "bench restart",
        f"bench --site {site} execute surhan_signature.api.production_go_live_checklist",
        f"bench --site {site} execute surhan_signature.api.production_release_gate --kwargs '{{\"strict\":1}}'",
        f"bench --site {site} execute surhan_signature.api.final_smoke_check",
    ]

    return {
        "ok": True,
        "dry_run": True,
        "public_base_url": base_url,
        "environment_ready_now": matrix.get("environment_ready"),
        "production_ready_now": matrix.get("production_ready"),
        "current_blockers": matrix.get("blockers"),
        "warnings": matrix.get("warnings"),
        "commands": commands,
        "important_note": "These commands are not executed by this API. Review SMTP, domain, and email delivery first.",
    }


@frappe.whitelist()
def dry_run_production_go_live(public_base_url: str | None = None):
    matrix = production_environment_matrix(public_base_url=public_base_url)
    checklist = production_go_live_checklist()

    go_live_allowed_now = bool(
        matrix.get("environment_ready")
        and checklist.get("production_final_ready")
        and checklist.get("production_environment_ready")
    )

    return {
        "ok": True,
        "dry_run": True,
        "go_live_allowed_now": go_live_allowed_now,
        "generated_at": str(now_datetime()),
        "matrix": matrix,
        "checklist": checklist,
        "decision": "ALLOW" if go_live_allowed_now else "BLOCK",
        "required_before_allow": [
            "Configure outgoing Email Account.",
            "Use a public HTTPS signing_base_url.",
            "Send and confirm test signature email.",
            "Run a fresh bench backup.",
            "Disable developer_mode.",
            "Re-run final_smoke_check and production_release_gate.",
        ],
    }


@frappe.whitelist()
def export_production_environment_manifest_json(public_base_url: str | None = None):
    from frappe.utils.file_manager import save_file

    manifest = {
        "ok": True,
        "environment_matrix": production_environment_matrix(public_base_url=public_base_url),
        "dry_run_go_live": dry_run_production_go_live(public_base_url=public_base_url),
    }

    raw = _phase25b_json_dumps(manifest)
    digest = _phase25b_sha256(raw)

    fname = f"surhan-signature-production-environment-manifest-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "environment_ready": manifest.get("environment_matrix", {}).get("environment_ready"),
        "go_live_allowed_now": manifest.get("dry_run_go_live", {}).get("go_live_allowed_now"),
        "blockers": manifest.get("environment_matrix", {}).get("blockers"),
    }


# Phase 25C-SKIP: LAN/Staging mode when no public domain is available.
import json as _phase25c_skip_json
import hashlib as _phase25c_skip_hashlib


def _phase25c_skip_json_dumps(data) -> str:
    return _phase25c_skip_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase25c_skip_sha256(text: str) -> str:
    return _phase25c_skip_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


@frappe.whitelist()
def set_staging_lan_base_url(base_url: str = "http://192.168.71.128"):
    base_url = str(base_url or "").strip().rstrip("/")

    if not base_url:
        frappe.throw("base_url is required.")

    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        frappe.throw("base_url must start with http:// or https://")

    try:
        set_signature_base_url(base_url)
    except Exception:
        if frappe.db.exists("DocType", "E-Sign Settings"):
            frappe.db.set_single_value("E-Sign Settings", "signing_base_url", base_url)
            frappe.db.commit()

    qr_result = None

    try:
        qr_result = generate_all_certificate_qr_artifacts(limit=200, force=1)
    except Exception as exc:
        qr_result = {
            "ok": False,
            "error": str(exc),
        }

    return {
        "ok": True,
        "mode": "LAN/Staging",
        "base_url": base_url,
        "note": "This is not production HTTPS go-live. It is suitable for internal network testing.",
        "qr_regenerated": qr_result,
    }


@frappe.whitelist()
def staging_release_gate():
    blockers = []
    warnings = []

    health = signature_system_health()
    tests = run_signature_test_suite_with_risk(mode="safe")
    risk = risk_release_gate(refresh=1, limit=200)
    qr = certificate_qr_status(limit=200)
    verify_page = public_verify_page_health()
    monitoring = backup_restore_monitoring_status()
    non_prod = identify_non_production_envelopes(limit=200)
    readiness = production_readiness_report()

    if not health.get("health_ok"):
        blockers.append("System health failed.")

    if not tests.get("ok"):
        blockers.append("Automated tests with risk failed.")

    if not risk.get("risk_ready"):
        blockers.extend(risk.get("blockers") or ["Risk gate failed."])

    if qr.get("missing_or_invalid_count"):
        blockers.append("Certificate QR artifacts are missing or invalid.")

    if not verify_page.get("ok"):
        blockers.append("Public verify page is not healthy.")

    if not monitoring.get("monitoring_ok"):
        blockers.append("Backup/restore monitoring is not OK.")

    settings = readiness.get("settings") or {}
    email = readiness.get("email") or {}

    if settings.get("developer_mode"):
        warnings.append("developer_mode is enabled. Acceptable for staging, not production.")

    if not email.get("ready"):
        warnings.append("Default outgoing Email Account is not configured. Email invitations will not be production-ready.")

    if non_prod.get("pending_count"):
        warnings.append(f"{non_prod.get('pending_count')} pending envelope(s) exist.")

    if non_prod.get("test_like_count"):
        warnings.append(f"{non_prod.get('test_like_count')} test-like envelope(s) detected.")

    staging_ready = not blockers

    return {
        "ok": True,
        "mode": "LAN/Staging",
        "staging_ready": staging_ready,
        "production_ready": False,
        "generated_at": str(now_datetime()),
        "blockers": blockers,
        "warnings": warnings,
        "health_ok": health.get("health_ok"),
        "tests_ok": tests.get("ok"),
        "risk_ready": risk.get("risk_ready"),
        "qr_valid": qr.get("missing_or_invalid_count") == 0,
        "public_verify_page_ok": verify_page.get("ok"),
        "monitoring_ok": monitoring.get("monitoring_ok"),
        "email_ready": email.get("ready"),
        "developer_mode": settings.get("developer_mode"),
        "base_url": settings.get("signing_base_url"),
        "non_production_envelopes": {
            "total": non_prod.get("total"),
            "pending_count": non_prod.get("pending_count"),
            "test_like_count": non_prod.get("test_like_count"),
            "signed_count": non_prod.get("signed_count"),
            "declined_count": non_prod.get("declined_count"),
        },
        "note": "Staging-ready means internal testing can continue. It does not mean public production go-live.",
    }


@frappe.whitelist()
def export_staging_release_manifest_json():
    from frappe.utils.file_manager import save_file

    manifest = {
        "ok": True,
        "staging_gate": staging_release_gate(),
        "production_go_live": dry_run_production_go_live(),
    }

    raw = _phase25c_skip_json_dumps(manifest)
    digest = _phase25c_skip_sha256(raw)

    fname = f"surhan-signature-staging-release-manifest-{digest[:12]}.json"

    file_doc = save_file(
        fname=fname,
        content=raw,
        dt="E-Sign Settings",
        dn="E-Sign Settings",
        is_private=1,
    )

    return {
        "ok": True,
        "file_url": file_doc.file_url,
        "sha256": digest,
        "file_name": fname,
        "staging_ready": manifest.get("staging_gate", {}).get("staging_ready"),
        "production_ready": False,
        "blockers": manifest.get("staging_gate", {}).get("blockers"),
        "warnings": manifest.get("staging_gate", {}).get("warnings"),
    }


# Phase 26A: Employee Signature Profile + Professional Drawing Studio.
import base64 as _phase26a_base64
import json as _phase26a_json
import hashlib as _phase26a_hashlib
import re as _phase26a_re


PHASE26A_PROFILE_DT = "Employee Signature Profile"
PHASE26A_VERSION_DT = "Employee Signature Profile Version"


def _phase26a_now():
    return str(now_datetime())


def _phase26a_json_dumps(data) -> str:
    return _phase26a_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _phase26a_sha256_text(text: str) -> str:
    return _phase26a_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase26a_sha256_bytes(data: bytes) -> str:
    return _phase26a_hashlib.sha256(data or b"").hexdigest()


def _phase26a_request_ip():
    try:
        return frappe.local.request_ip or frappe.get_request_header("X-Forwarded-For") or ""
    except Exception:
        return ""


def _phase26a_user_agent():
    try:
        return frappe.get_request_header("User-Agent") or ""
    except Exception:
        return ""


def _phase26a_require_login():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required to use signature profile.")


def _phase26a_has_role(*roles):
    if frappe.session.user == "Administrator":
        return True
    user_roles = set(frappe.get_roles() or [])
    return bool(user_roles.intersection(set(roles)))


def _phase26a_ensure_role(role_name):
    if not frappe.db.exists("Role", role_name):
        frappe.get_doc({
            "doctype": "Role",
            "role_name": role_name,
            "desk_access": 1,
        }).insert(ignore_permissions=True)
    return role_name


def _phase26a_field(label, fieldname, fieldtype, options=None, reqd=0, hidden=0, read_only=0,
                    unique=0, in_list_view=0, default=None, description=None):
    f = {
        "label": label,
        "fieldname": fieldname,
        "fieldtype": fieldtype,
        "reqd": reqd,
        "hidden": hidden,
        "read_only": read_only,
        "unique": unique,
        "in_list_view": in_list_view,
    }
    if options:
        f["options"] = options
    if default is not None:
        f["default"] = default
    if description:
        f["description"] = description
    return f


def _phase26a_permission(role, read=1, write=0, create=0, delete=0, submit=0, cancel=0, amend=0, if_owner=0):
    return {
        "role": role,
        "read": read,
        "write": write,
        "create": create,
        "delete": delete,
        "submit": submit,
        "cancel": cancel,
        "amend": amend,
        "if_owner": if_owner,
    }




def _phase26a_current_employee_for_user(user=None):
    user = user or frappe.session.user

    employee = None
    designation = None
    department = None

    if frappe.db.exists("DocType", "Employee"):
        employee = frappe.db.get_value("Employee", {"user_id": user}, "name")
        if employee:
            designation, department = frappe.db.get_value(
                "Employee",
                employee,
                ["designation", "department"],
            ) or (None, None)

    full_name = frappe.db.get_value("User", user, "full_name") or user

    return {
        "user": user,
        "employee": employee,
        "full_name": full_name,
        "designation": designation,
        "department": department,
    }


def _phase26a_sanitize_svg(svg: str) -> str:
    svg = (svg or "").strip()

    if not svg:
        frappe.throw("Signature SVG is required.")

    if len(svg) > 450000:
        frappe.throw("Signature SVG is too large.")

    lowered = svg.lower()

    if "<svg" not in lowered:
        frappe.throw("Invalid SVG signature payload.")

    forbidden = [
        "<script",
        "</script",
        "javascript:",
        "<foreignobject",
        "<iframe",
        "<object",
        "<embed",
        "onload=",
        "onclick=",
        "onerror=",
        "onmouseover=",
        "onfocus=",
        "onpointer",
        "onmouseenter",
    ]

    for token in forbidden:
        if token in lowered:
            frappe.throw("Unsafe SVG content was rejected.")

    # Remove XML doctype if any to avoid browser-side external fetch declarations.
    svg = _phase26a_re.sub(r"<!DOCTYPE[^>]*>", "", svg, flags=_phase26a_re.IGNORECASE)
    svg = _phase26a_re.sub(r"<\?xml[^>]*\?>", "", svg, flags=_phase26a_re.IGNORECASE).strip()

    return svg


def _phase26a_validate_vector_json(vector_json):
    if vector_json is None:
        return {}

    if isinstance(vector_json, str):
        if len(vector_json) > 600000:
            frappe.throw("Signature vector JSON is too large.")
        try:
            data = _phase26a_json.loads(vector_json)
        except Exception:
            frappe.throw("Invalid vector JSON.")
    else:
        data = vector_json

    if not isinstance(data, dict):
        frappe.throw("Vector JSON must be an object.")

    strokes = data.get("strokes") or []
    if not isinstance(strokes, list):
        frappe.throw("Vector strokes must be a list.")

    if len(strokes) > 500:
        frappe.throw("Too many strokes in signature.")

    point_count = 0
    for stroke in strokes:
        if not isinstance(stroke, list):
            frappe.throw("Invalid stroke format.")
        point_count += len(stroke)

    if point_count < 3:
        frappe.throw("Signature is too small or empty.")

    if point_count > 20000:
        frappe.throw("Signature contains too many points.")

    return data


def _phase26a_decode_png_data_url(data_url: str):
    data_url = (data_url or "").strip()

    if not data_url:
        return None

    if not data_url.startswith("data:image/png;base64,"):
        frappe.throw("PNG signature must be a PNG data URL.")

    raw_b64 = data_url.split(",", 1)[1]

    if len(raw_b64) > 2500000:
        frappe.throw("PNG signature is too large.")

    try:
        data = _phase26a_base64.b64decode(raw_b64)
    except Exception:
        frappe.throw("Invalid PNG data.")

    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        frappe.throw("Invalid PNG signature file.")

    return data


def _phase26a_profile_name_for_user(user):
    return user


def _phase26a_set_encrypted(doctype, name, fieldname, value):
    from frappe.utils.password import set_encrypted_password
    set_encrypted_password(doctype, name, value or "", fieldname)


def _phase26a_get_encrypted(doctype, name, fieldname):
    from frappe.utils.password import get_decrypted_password
    try:
        return get_decrypted_password(doctype, name, fieldname, raise_exception=False) or ""
    except Exception:
        return ""








@frappe.whitelist()
def revoke_my_signature_profile(reason: str = None):
    _phase26a_require_login()

    user = frappe.session.user
    profile_name = _phase26a_profile_name_for_user(user)

    if not frappe.db.exists(PHASE26A_PROFILE_DT, profile_name):
        frappe.throw("No signature profile found.")

    profile = frappe.get_doc(PHASE26A_PROFILE_DT, profile_name)

    profile.is_active = 0
    profile.revoked_on = now_datetime()
    profile.revoked_by = user
    profile.revocation_reason = reason or "Revoked by owner."
    profile.save(ignore_permissions=True)

    frappe.db.commit()

    try:
        log_audit(
            "employee_signature_profile.revoked",
            {
                "user": user,
                "profile": profile.name,
                "reason": reason,
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "profile": profile.name,
        "is_active": False,
        "message": "Signature profile revoked.",
    }






# Phase 26A-FIX: ensure Signing Module Def exists before creating custom DocTypes.
def _phase26a_fix_ensure_module_def(module_name: str = "Signing"):
    if frappe.db.exists("Module Def", module_name):
        return {
            "ok": True,
            "module": module_name,
            "created": False,
        }

    doc = frappe.new_doc("Module Def")
    doc.module_name = module_name

    meta = frappe.get_meta("Module Def")

    if meta.has_field("app_name"):
        doc.app_name = "surhan_signature"

    if meta.has_field("custom"):
        doc.custom = 1

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {
        "ok": True,
        "module": module_name,
        "created": True,
    }


# Override previous helper so all future custom DocTypes create under a guaranteed module.
def _phase26a_ensure_doctype(doctype_name, fields, permissions, autoname="prompt", title_field=None):
    module_info = _phase26a_fix_ensure_module_def("Signing")

    if frappe.db.exists("DocType", doctype_name):
        dt = frappe.get_doc("DocType", doctype_name)
        existing = {d.fieldname for d in dt.fields if d.fieldname}
        changed = False

        if getattr(dt, "module", None) != "Signing":
            dt.module = "Signing"
            changed = True

        for field in fields:
            if field.get("fieldname") and field["fieldname"] not in existing:
                dt.append("fields", field)
                changed = True

        if changed:
            dt.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.clear_cache(doctype=doctype_name)

        return {
            "doctype": doctype_name,
            "created": False,
            "updated": changed,
            "module": "Signing",
            "module_info": module_info,
        }

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": doctype_name,
        "module": "Signing",
        "custom": 1,
        "autoname": autoname,
        "title_field": title_field,
        "track_changes": 1,
        "fields": fields,
        "permissions": permissions,
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    frappe.clear_cache(doctype=doctype_name)

    return {
        "doctype": doctype_name,
        "created": True,
        "updated": True,
        "module": "Signing",
        "module_info": module_info,
    }


# Override installer to force module creation first.
@frappe.whitelist()
def phase26a_install_signature_profile():
    module_info = _phase26a_fix_ensure_module_def("Signing")

    _phase26a_ensure_role("Internal Signature User")
    _phase26a_ensure_role("Internal Signature Administrator")
    _phase26a_ensure_role("Internal Signature Auditor")
    _phase26a_ensure_role("Internal Signature API User")

    profile_fields = [
        _phase26a_field("User", "user", "Link", "User", reqd=1, unique=1, in_list_view=1),
        _phase26a_field("Employee", "employee", "Link", "Employee", in_list_view=1),
        _phase26a_field("Full Name", "full_name", "Data", in_list_view=1),
        _phase26a_field("Designation", "designation", "Data"),
        _phase26a_field("Department", "department", "Data"),
        _phase26a_field("Signature PNG", "signature_png", "Attach Image"),
        _phase26a_field("Signature SVG Encrypted", "signature_svg_encrypted", "Password", hidden=1),
        _phase26a_field("Signature Vector JSON Encrypted", "signature_vector_json_encrypted", "Password", hidden=1),
        _phase26a_field("Signature Hash", "signature_hash", "Data", read_only=1, in_list_view=1),
        _phase26a_field("Signature Public ID", "signature_public_id", "Data", read_only=1),
        _phase26a_field("Active Version", "active_version", "Int", read_only=1, default=0),
        _phase26a_field("Is Active", "is_active", "Check", default=1, in_list_view=1),
        _phase26a_field("Is Locked", "is_locked", "Check", default=0),
        _phase26a_field("Allow Stored Signature Apply", "allow_stored_signature_apply", "Check", default=1),
        _phase26a_field("Allow Direction Drawing", "allow_direction_drawing", "Check", default=0),
        _phase26a_field("Last Rotated At", "last_rotated_at", "Datetime", read_only=1),
        _phase26a_field("Revoked On", "revoked_on", "Datetime", read_only=1),
        _phase26a_field("Revoked By", "revoked_by", "Link", "User", read_only=1),
        _phase26a_field("Revocation Reason", "revocation_reason", "Small Text"),
        _phase26a_field("Created IP", "created_ip", "Data", read_only=1),
        _phase26a_field("User Agent", "user_agent", "Small Text", read_only=1),
        _phase26a_field("Security Notes", "security_notes", "Small Text", read_only=1),
    ]

    version_fields = [
        _phase26a_field("Profile", "profile", "Link", PHASE26A_PROFILE_DT, reqd=1, in_list_view=1),
        _phase26a_field("User", "user", "Link", "User", reqd=1, in_list_view=1),
        _phase26a_field("Employee", "employee", "Link", "Employee"),
        _phase26a_field("Version", "version", "Int", reqd=1, in_list_view=1),
        _phase26a_field("Signature PNG", "signature_png", "Attach Image"),
        _phase26a_field("Signature SVG Encrypted", "signature_svg_encrypted", "Password", hidden=1),
        _phase26a_field("Signature Vector JSON Encrypted", "signature_vector_json_encrypted", "Password", hidden=1),
        _phase26a_field("Signature Hash", "signature_hash", "Data", read_only=1, in_list_view=1),
        _phase26a_field("Is Active Version", "is_active_version", "Check", default=1, in_list_view=1),
        _phase26a_field("Created IP", "created_ip", "Data", read_only=1),
        _phase26a_field("User Agent", "user_agent", "Small Text", read_only=1),
    ]

    permissions = [
        _phase26a_permission("System Manager", read=1, write=1, create=1, delete=1),
        _phase26a_permission("Internal Signature Administrator", read=1, write=1, create=1, delete=0),
        _phase26a_permission("Internal Signature Auditor", read=1, write=0, create=0, delete=0),
    ]

    profile = _phase26a_ensure_doctype(
        PHASE26A_PROFILE_DT,
        profile_fields,
        permissions,
        autoname="field:user",
        title_field="full_name",
    )

    version = _phase26a_ensure_doctype(
        PHASE26A_VERSION_DT,
        version_fields,
        permissions,
        autoname="prompt",
        title_field="profile",
    )

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26A-FIX",
        "module": module_info,
        "roles": [
            "Internal Signature User",
            "Internal Signature Administrator",
            "Internal Signature Auditor",
            "Internal Signature API User",
        ],
        "doctypes": [profile, version],
        "page": "/signature-profile",
    }


@frappe.whitelist()
def phase26a_signature_profile_health():
    import os

    roles = [
        "Internal Signature User",
        "Internal Signature Administrator",
        "Internal Signature Auditor",
        "Internal Signature API User",
    ]

    app_root = frappe.get_app_path("surhan_signature")
    page_py = os.path.join(app_root, "www", "signature-profile.py")
    page_html = os.path.join(app_root, "www", "signature-profile.html")

    health = {
        "ok": True,
        "phase": "26A-FIX",
        "module_signing": bool(frappe.db.exists("Module Def", "Signing")),
        "doctypes": {
            PHASE26A_PROFILE_DT: bool(frappe.db.exists("DocType", PHASE26A_PROFILE_DT)),
            PHASE26A_VERSION_DT: bool(frappe.db.exists("DocType", PHASE26A_VERSION_DT)),
        },
        "roles": {role: bool(frappe.db.exists("Role", role)) for role in roles},
        "page": "/signature-profile",
        "page_files": {
            "signature-profile.py": os.path.exists(page_py),
            "signature-profile.html": os.path.exists(page_html),
        },
        "current_user": frappe.session.user,
    }

    health["ready"] = (
        health["module_signing"]
        and all(health["doctypes"].values())
        and all(health["roles"].values())
        and all(health["page_files"].values())
    )

    return health


# Phase 26A-FIX2: CSRF helper for standalone signature-profile web page.
@frappe.whitelist()
def phase26a_get_csrf_token():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")

    try:
        token = frappe.sessions.get_csrf_token()
    except Exception:
        token = getattr(frappe.local, "csrf_token", None) or ""

    return {
        "ok": True,
        "csrf_token": token,
        "user": frappe.session.user,
    }


# Phase 26B: Internal Signature Permission Matrix + Ac Footer Policy Foundation.
import json as _phase26b_json


PHASE26B_POLICY_DT = "Internal Signature Policy"
PHASE26B_PERMISSION_DT = "Internal Signature Permission"


def _phase26b_json_dumps(data) -> str:
    return _phase26b_json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    )


def _phase26b_is_admin():
    if frappe.session.user == "Administrator":
        return True
    roles = set(frappe.get_roles() or [])
    return bool(roles.intersection({"System Manager", "Internal Signature Administrator", "Internal Signature Manager"}))


def _phase26b_require_admin():
    if not _phase26b_is_admin():
        frappe.throw("Only Internal Signature Administrator can perform this action.")


def _phase26b_ensure_module():
    if " _phase26a_fix_ensure_module_def" and globals().get("_phase26a_fix_ensure_module_def"):
        return _phase26a_fix_ensure_module_def("Signing")

    if frappe.db.exists("Module Def", "Signing"):
        return {"ok": True, "module": "Signing", "created": False}

    doc = frappe.new_doc("Module Def")
    doc.module_name = "Signing"

    if frappe.get_meta("Module Def").has_field("app_name"):
        doc.app_name = "surhan_signature"

    if frappe.get_meta("Module Def").has_field("custom"):
        doc.custom = 1

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {"ok": True, "module": "Signing", "created": True}


def _phase26b_ensure_role(role_name):
    if globals().get("_phase26a_ensure_role"):
        return _phase26a_ensure_role(role_name)

    if not frappe.db.exists("Role", role_name):
        frappe.get_doc({
            "doctype": "Role",
            "role_name": role_name,
            "desk_access": 1,
        }).insert(ignore_permissions=True)
        frappe.db.commit()

    return role_name


def _phase26b_field(label, fieldname, fieldtype, options=None, reqd=0, hidden=0, read_only=0,
                    unique=0, in_list_view=0, default=None, description=None):
    if globals().get("_phase26a_field"):
        return _phase26a_field(
            label,
            fieldname,
            fieldtype,
            options=options,
            reqd=reqd,
            hidden=hidden,
            read_only=read_only,
            unique=unique,
            in_list_view=in_list_view,
            default=default,
            description=description,
        )

    f = {
        "label": label,
        "fieldname": fieldname,
        "fieldtype": fieldtype,
        "reqd": reqd,
        "hidden": hidden,
        "read_only": read_only,
        "unique": unique,
        "in_list_view": in_list_view,
    }
    if options:
        f["options"] = options
    if default is not None:
        f["default"] = default
    if description:
        f["description"] = description
    return f


def _phase26b_permission(role, read=1, write=0, create=0, delete=0, submit=0, cancel=0, amend=0, if_owner=0):
    if globals().get("_phase26a_permission"):
        return _phase26a_permission(role, read, write, create, delete, submit, cancel, amend, if_owner)

    return {
        "role": role,
        "read": read,
        "write": write,
        "create": create,
        "delete": delete,
        "submit": submit,
        "cancel": cancel,
        "amend": amend,
        "if_owner": if_owner,
    }


def _phase26b_ensure_doctype(doctype_name, fields, permissions, autoname="prompt", title_field=None):
    _phase26b_ensure_module()

    if globals().get("_phase26a_ensure_doctype"):
        return _phase26a_ensure_doctype(
            doctype_name,
            fields,
            permissions,
            autoname=autoname,
            title_field=title_field,
        )

    if frappe.db.exists("DocType", doctype_name):
        dt = frappe.get_doc("DocType", doctype_name)
        existing = {d.fieldname for d in dt.fields if d.fieldname}
        changed = False

        if getattr(dt, "module", None) != "Signing":
            dt.module = "Signing"
            changed = True

        for field in fields:
            if field.get("fieldname") and field["fieldname"] not in existing:
                dt.append("fields", field)
                changed = True

        if changed:
            dt.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.clear_cache(doctype=doctype_name)

        return {"doctype": doctype_name, "created": False, "updated": changed}

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": doctype_name,
        "module": "Signing",
        "custom": 1,
        "autoname": autoname,
        "title_field": title_field,
        "track_changes": 1,
        "fields": fields,
        "permissions": permissions,
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    frappe.clear_cache(doctype=doctype_name)

    return {"doctype": doctype_name, "created": True, "updated": True}


def _phase26b_identity_for_user(user):
    if globals().get("_phase26a_current_employee_for_user"):
        return _phase26a_current_employee_for_user(user)

    full_name = frappe.db.get_value("User", user, "full_name") or user
    employee = None
    designation = None
    department = None

    if frappe.db.exists("DocType", "Employee"):
        employee = frappe.db.get_value("Employee", {"user_id": user}, "name")
        if employee:
            designation, department = frappe.db.get_value("Employee", employee, ["designation", "department"]) or (None, None)

    return {
        "user": user,
        "employee": employee,
        "full_name": full_name,
        "designation": designation,
        "department": department,
    }


@frappe.whitelist()
def phase26b_install_permission_matrix():
    _phase26b_ensure_module()

    roles = [
        "Internal Signature User",
        "Internal Document Signer",
        "Internal Direction Writer",
        "Internal Signature Manager",
        "Internal Signature Administrator",
        "Internal Signature Auditor",
        "Internal Signature API User",
        "Internal Signature Sequence Override",
    ]

    for role in roles:
        _phase26b_ensure_role(role)

    policy_fields = [
        _phase26b_field("Reference DocType", "reference_doctype", "Link", "DocType", reqd=1, unique=1, in_list_view=1),
        _phase26b_field("Is Active", "is_active", "Check", default=1, in_list_view=1),
        _phase26b_field("Ac Footer Fieldname", "ac_footer_fieldname", "Data", default="ac_footer", reqd=1, in_list_view=1),
        _phase26b_field("Workflow Mode", "workflow_mode", "Select", "Sequential\nParallel", default="Sequential", in_list_view=1),
        _phase26b_field("Approval Sequence Mode", "approval_sequence_mode", "Select", "As Listed\nBy Employee Grade\nBy Designation Rank\nManual Sign Order", default="As Listed"),
        _phase26b_field("Allow Saved Signature", "allow_saved_signature", "Check", default=1),
        _phase26b_field("Allow Direction", "allow_direction", "Check", default=1),
        _phase26b_field("Allow Direction Drawing", "allow_direction_drawing", "Check", default=1),
        _phase26b_field("Allow Direction Text", "allow_direction_text", "Check", default=1),
        _phase26b_field("Allow Reject / Return", "allow_reject", "Check", default=1),
        _phase26b_field("Require Signature Profile", "require_signature_profile", "Check", default=1),
        _phase26b_field("Allow External Requests", "allow_external_requests", "Check", default=0),
        _phase26b_field("Allow On Submitted Documents", "allow_on_submitted_docs", "Check", default=0),
        _phase26b_field("Lock After Complete", "lock_after_complete", "Check", default=1),
        _phase26b_field("Direction Print Position", "direction_print_position", "Select", "Top\nFooter\nBoth", default="Top"),
        _phase26b_field("Signature Print Position", "signature_print_position", "Select", "Footer\nTop\nBoth", default="Footer"),
        _phase26b_field("Max Active Requests Per Document", "max_active_requests_per_document", "Int", default=20),
        _phase26b_field("Notes", "notes", "Small Text"),
    ]

    permission_fields = [
        _phase26b_field("User", "user", "Link", "User", reqd=1, unique=1, in_list_view=1),
        _phase26b_field("Employee", "employee", "Link", "Employee", in_list_view=1),
        _phase26b_field("Full Name", "full_name", "Data", in_list_view=1),
        _phase26b_field("Designation", "designation", "Data"),
        _phase26b_field("Department", "department", "Data"),
        _phase26b_field("Is Active", "is_active", "Check", default=1, in_list_view=1),
        _phase26b_field("Can Receive Requests", "can_receive_requests", "Check", default=1),
        _phase26b_field("Can Use Saved Signature", "can_use_saved_signature", "Check", default=1, in_list_view=1),
        _phase26b_field("Can Draw Direction", "can_draw_direction", "Check", default=0, in_list_view=1),
        _phase26b_field("Can Write Direction Text", "can_write_direction_text", "Check", default=0),
        _phase26b_field("Can Reject / Return", "can_reject", "Check", default=0),
        _phase26b_field("Can Override Sequence", "can_override_sequence", "Check", default=0),
        _phase26b_field("Can Manage External Requests", "can_manage_external_requests", "Check", default=0),
        _phase26b_field("Can View Signature Audit", "can_view_signature_audit", "Check", default=0),
        _phase26b_field("Max Sequence Level", "max_sequence_level", "Int", default=99),
        _phase26b_field("Allowed DocTypes JSON", "allowed_doctypes_json", "Code", "JSON"),
        _phase26b_field("Granted By", "granted_by", "Link", "User", read_only=1),
        _phase26b_field("Granted At", "granted_at", "Datetime", read_only=1),
        _phase26b_field("Notes", "notes", "Small Text"),
    ]

    permissions = [
        _phase26b_permission("System Manager", read=1, write=1, create=1, delete=1),
        _phase26b_permission("Internal Signature Administrator", read=1, write=1, create=1, delete=0),
        _phase26b_permission("Internal Signature Manager", read=1, write=1, create=1, delete=0),
        _phase26b_permission("Internal Signature Auditor", read=1, write=0, create=0, delete=0),
    ]

    policy = _phase26b_ensure_doctype(
        PHASE26B_POLICY_DT,
        policy_fields,
        permissions,
        autoname="field:reference_doctype",
        title_field="reference_doctype",
    )

    perm = _phase26b_ensure_doctype(
        PHASE26B_PERMISSION_DT,
        permission_fields,
        permissions,
        autoname="field:user",
        title_field="full_name",
    )

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26B",
        "roles": roles,
        "doctypes": [policy, perm],
    }


@frappe.whitelist()
def admin_upsert_internal_signature_permission(
    user: str,
    can_use_saved_signature: int = 1,
    can_draw_direction: int = 0,
    can_write_direction_text: int = 0,
    can_reject: int = 0,
    can_override_sequence: int = 0,
    can_manage_external_requests: int = 0,
    can_view_signature_audit: int = 0,
    can_receive_requests: int = 1,
    max_sequence_level: int = 99,
    allowed_doctypes_json=None,
    is_active: int = 1,
    notes: str | None = None,
):
    _phase26b_require_admin()

    if not user:
        frappe.throw("User is required.")

    if not frappe.db.exists("DocType", PHASE26B_PERMISSION_DT):
        phase26b_install_permission_matrix()

    identity = _phase26b_identity_for_user(user)

    exists = frappe.db.exists(PHASE26B_PERMISSION_DT, user)

    if exists:
        doc = frappe.get_doc(PHASE26B_PERMISSION_DT, user)
        action = "updated"
    else:
        doc = frappe.new_doc(PHASE26B_PERMISSION_DT)
        doc.name = user
        doc.user = user
        action = "created"

    doc.employee = identity.get("employee")
    doc.full_name = identity.get("full_name")
    doc.designation = identity.get("designation")
    doc.department = identity.get("department")
    doc.is_active = int(is_active or 0)
    doc.can_receive_requests = int(can_receive_requests or 0)
    doc.can_use_saved_signature = int(can_use_saved_signature or 0)
    doc.can_draw_direction = int(can_draw_direction or 0)
    doc.can_write_direction_text = int(can_write_direction_text or 0)
    doc.can_reject = int(can_reject or 0)
    doc.can_override_sequence = int(can_override_sequence or 0)
    doc.can_manage_external_requests = int(can_manage_external_requests or 0)
    doc.can_view_signature_audit = int(can_view_signature_audit or 0)
    doc.max_sequence_level = int(max_sequence_level or 99)
    doc.granted_by = frappe.session.user
    doc.granted_at = now_datetime()
    doc.notes = notes or ""

    if isinstance(allowed_doctypes_json, (list, dict)):
        doc.allowed_doctypes_json = _phase26b_json_dumps(allowed_doctypes_json)
    elif allowed_doctypes_json:
        doc.allowed_doctypes_json = str(allowed_doctypes_json)
    else:
        doc.allowed_doctypes_json = "[]"

    if exists:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()

    try:
        if frappe.db.exists("DocType", PHASE26A_PROFILE_DT) and frappe.db.exists(PHASE26A_PROFILE_DT, user):
            if globals().get("admin_set_signature_profile_permissions"):
                admin_set_signature_profile_permissions(
                    user=user,
                    allow_stored_signature_apply=doc.can_use_saved_signature,
                    allow_direction_drawing=doc.can_draw_direction,
                    is_locked=0,
                    is_active=1,
                )
    except Exception:
        pass

    try:
        log_audit(
            "internal_signature_permission.upserted",
            {
                "user": user,
                "action": action,
                "can_use_saved_signature": bool(doc.can_use_saved_signature),
                "can_draw_direction": bool(doc.can_draw_direction),
                "can_override_sequence": bool(doc.can_override_sequence),
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "action": action,
        "permission": doc.name,
        "user": doc.user,
        "employee": doc.employee,
        "full_name": doc.full_name,
        "is_active": bool(doc.is_active),
        "can_receive_requests": bool(doc.can_receive_requests),
        "can_use_saved_signature": bool(doc.can_use_saved_signature),
        "can_draw_direction": bool(doc.can_draw_direction),
        "can_write_direction_text": bool(doc.can_write_direction_text),
        "can_reject": bool(doc.can_reject),
        "can_override_sequence": bool(doc.can_override_sequence),
        "can_manage_external_requests": bool(doc.can_manage_external_requests),
        "can_view_signature_audit": bool(doc.can_view_signature_audit),
        "max_sequence_level": doc.max_sequence_level,
    }




@frappe.whitelist()
def admin_upsert_internal_signature_policy(
    reference_doctype: str,
    ac_footer_fieldname: str = "ac_footer",
    workflow_mode: str = "Sequential",
    approval_sequence_mode: str = "As Listed",
    allow_saved_signature: int = 1,
    allow_direction: int = 1,
    allow_direction_drawing: int = 1,
    allow_direction_text: int = 1,
    allow_reject: int = 1,
    require_signature_profile: int = 1,
    allow_external_requests: int = 0,
    allow_on_submitted_docs: int = 0,
    lock_after_complete: int = 1,
    direction_print_position: str = "Top",
    signature_print_position: str = "Footer",
    is_active: int = 1,
    notes: str | None = None,
):
    _phase26b_require_admin()

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    if not frappe.db.exists("DocType", PHASE26B_POLICY_DT):
        phase26b_install_permission_matrix()

    exists = frappe.db.exists(PHASE26B_POLICY_DT, reference_doctype)

    if exists:
        doc = frappe.get_doc(PHASE26B_POLICY_DT, reference_doctype)
        action = "updated"
    else:
        doc = frappe.new_doc(PHASE26B_POLICY_DT)
        doc.name = reference_doctype
        doc.reference_doctype = reference_doctype
        action = "created"

    doc.is_active = int(is_active or 0)
    doc.ac_footer_fieldname = ac_footer_fieldname or "ac_footer"
    doc.workflow_mode = workflow_mode if workflow_mode in {"Sequential", "Parallel"} else "Sequential"
    doc.approval_sequence_mode = approval_sequence_mode or "As Listed"
    doc.allow_saved_signature = int(allow_saved_signature or 0)
    doc.allow_direction = int(allow_direction or 0)
    doc.allow_direction_drawing = int(allow_direction_drawing or 0)
    doc.allow_direction_text = int(allow_direction_text or 0)
    doc.allow_reject = int(allow_reject or 0)
    doc.require_signature_profile = int(require_signature_profile or 0)
    doc.allow_external_requests = int(allow_external_requests or 0)
    doc.allow_on_submitted_docs = int(allow_on_submitted_docs or 0)
    doc.lock_after_complete = int(lock_after_complete or 0)
    doc.direction_print_position = direction_print_position or "Top"
    doc.signature_print_position = signature_print_position or "Footer"
    doc.notes = notes or ""

    if exists:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()

    return {
        "ok": True,
        "action": action,
        "policy": doc.name,
        "reference_doctype": doc.reference_doctype,
        "ac_footer_fieldname": doc.ac_footer_fieldname,
        "workflow_mode": doc.workflow_mode,
        "allow_saved_signature": bool(doc.allow_saved_signature),
        "allow_direction": bool(doc.allow_direction),
        "allow_external_requests": bool(doc.allow_external_requests),
        "is_active": bool(doc.is_active),
    }


@frappe.whitelist()
def discover_ac_footer_doctypes(limit: int = 200):
    out = []
    seen = set()

    try:
        rows = frappe.get_all(
            "DocField",
            filters={"fieldname": ["in", ["ac_footer", "Ac Footer"]]},
            fields=["parent", "fieldname", "label", "fieldtype"],
            limit_page_length=int(limit or 200),
        )
        for r in rows:
            if r.parent not in seen:
                seen.add(r.parent)
                out.append({
                    "doctype": r.parent,
                    "fieldname": r.fieldname,
                    "label": r.label,
                    "fieldtype": r.fieldtype,
                    "source": "DocField",
                })
    except Exception:
        pass

    try:
        rows = frappe.get_all(
            "Custom Field",
            filters={"fieldname": ["in", ["ac_footer", "Ac Footer"]]},
            fields=["dt", "fieldname", "label", "fieldtype"],
            limit_page_length=int(limit or 200),
        )
        for r in rows:
            if r.dt not in seen:
                seen.add(r.dt)
                out.append({
                    "doctype": r.dt,
                    "fieldname": r.fieldname,
                    "label": r.label,
                    "fieldtype": r.fieldtype,
                    "source": "Custom Field",
                })
    except Exception:
        pass

    # Secondary discovery by label if fieldname is different.
    try:
        rows = frappe.get_all(
            "Custom Field",
            filters={"label": ["like", "%Ac Footer%"]},
            fields=["dt", "fieldname", "label", "fieldtype"],
            limit_page_length=int(limit or 200),
        )
        for r in rows:
            if r.dt not in seen:
                seen.add(r.dt)
                out.append({
                    "doctype": r.dt,
                    "fieldname": r.fieldname,
                    "label": r.label,
                    "fieldtype": r.fieldtype,
                    "source": "Custom Field Label",
                })
    except Exception:
        pass

    return {
        "ok": True,
        "count": len(out),
        "items": out,
    }


@frappe.whitelist()
def admin_auto_create_policies_for_ac_footer(limit: int = 200):
    _phase26b_require_admin()

    if not frappe.db.exists("DocType", PHASE26B_POLICY_DT):
        phase26b_install_permission_matrix()

    discovered = discover_ac_footer_doctypes(limit=limit)
    results = []

    for item in discovered.get("items") or []:
        res = admin_upsert_internal_signature_policy(
            reference_doctype=item.get("doctype"),
            ac_footer_fieldname=item.get("fieldname") or "ac_footer",
            workflow_mode="Sequential",
            approval_sequence_mode="As Listed",
            allow_saved_signature=1,
            allow_direction=1,
            allow_direction_drawing=1,
            allow_direction_text=1,
            allow_reject=1,
            require_signature_profile=1,
            allow_external_requests=0,
            is_active=1,
            notes=f"Auto-created from {item.get('source')} discovery.",
        )
        results.append(res)

    return {
        "ok": True,
        "discovered_count": discovered.get("count"),
        "created_or_updated_count": len(results),
        "results": results,
    }


@frappe.whitelist()
def phase26b_permission_matrix_health():
    roles = [
        "Internal Signature User",
        "Internal Document Signer",
        "Internal Direction Writer",
        "Internal Signature Manager",
        "Internal Signature Administrator",
        "Internal Signature Auditor",
        "Internal Signature API User",
        "Internal Signature Sequence Override",
    ]

    doctypes = {
        PHASE26B_POLICY_DT: bool(frappe.db.exists("DocType", PHASE26B_POLICY_DT)),
        PHASE26B_PERMISSION_DT: bool(frappe.db.exists("DocType", PHASE26B_PERMISSION_DT)),
        PHASE26A_PROFILE_DT: bool(frappe.db.exists("DocType", PHASE26A_PROFILE_DT)) if "PHASE26A_PROFILE_DT" in globals() else False,
    }

    counts = {}
    for dt in [PHASE26B_POLICY_DT, PHASE26B_PERMISSION_DT]:
        if frappe.db.exists("DocType", dt):
            counts[dt] = frappe.db.count(dt)
        else:
            counts[dt] = 0

    current_caps = None
    try:
        if frappe.session.user != "Guest":
            current_caps = get_my_internal_signature_capabilities()
    except Exception as exc:
        current_caps = {"ok": False, "error": str(exc)}

    health = {
        "ok": True,
        "phase": "26B",
        "module_signing": bool(frappe.db.exists("Module Def", "Signing")),
        "doctypes": doctypes,
        "roles": {role: bool(frappe.db.exists("Role", role)) for role in roles},
        "counts": counts,
        "ac_footer_discovery": discover_ac_footer_doctypes(limit=200),
        "current_user_capabilities": current_caps,
    }

    health["ready"] = (
        health["module_signing"]
        and all(health["doctypes"].values())
        and all(health["roles"].values())
    )

    return health


# Phase 26B-FIX1: avoid Frappe Document.is_locked property conflict.


def _phase26b_fix1_profile_locked(profile):
    try:
        value = profile.get("signature_locked")
        return bool(int(value or 0))
    except Exception:
        return False




@frappe.whitelist()
def get_my_signature_profile(include_svg: int = 0, include_vector: int = 0):
    _phase26a_require_login()
    _phase26b_fix1_ensure_signature_locked_field()

    user = frappe.session.user
    profile_name = _phase26a_profile_name_for_user(user)

    if not frappe.db.exists(PHASE26A_PROFILE_DT, profile_name):
        identity = _phase26a_current_employee_for_user(user)
        return {
            "ok": True,
            "exists": False,
            "user": user,
            "employee": identity.get("employee"),
            "full_name": identity.get("full_name"),
            "message": "No signature profile found.",
        }

    profile = frappe.get_doc(PHASE26A_PROFILE_DT, profile_name)

    out = {
        "ok": True,
        "exists": True,
        "profile": profile.name,
        "user": profile.user,
        "employee": profile.employee,
        "full_name": profile.full_name,
        "designation": profile.designation,
        "department": profile.department,
        "signature_png": profile.signature_png,
        "signature_hash": profile.signature_hash,
        "signature_public_id": profile.signature_public_id,
        "active_version": profile.active_version,
        "is_active": bool(profile.is_active),
        "signature_locked": bool(profile.get("signature_locked")),
        "is_locked": bool(profile.get("signature_locked")),
        "allow_stored_signature_apply": bool(getattr(profile, "allow_stored_signature_apply", 0)),
        "allow_direction_drawing": bool(getattr(profile, "allow_direction_drawing", 0)),
        "last_rotated_at": str(profile.last_rotated_at or ""),
    }

    if int(include_svg or 0):
        out["signature_svg"] = _phase26a_get_encrypted(PHASE26A_PROFILE_DT, profile.name, "signature_svg_encrypted")

    if int(include_vector or 0):
        raw = _phase26a_get_encrypted(PHASE26A_PROFILE_DT, profile.name, "signature_vector_json_encrypted")
        try:
            out["vector_json"] = _phase26a_json.loads(raw) if raw else {}
        except Exception:
            out["vector_json"] = {}

    return out


@frappe.whitelist()
def save_my_signature_profile(signature_svg: str, signature_png_data_url: str = None, vector_json=None):
    _phase26a_require_login()
    _phase26b_fix1_ensure_signature_locked_field()

    if not frappe.db.exists("DocType", PHASE26A_PROFILE_DT):
        phase26a_install_signature_profile()

    user = frappe.session.user
    identity = _phase26a_current_employee_for_user(user)

    svg = _phase26a_sanitize_svg(signature_svg)
    vector = _phase26a_validate_vector_json(vector_json)
    png_bytes = _phase26a_decode_png_data_url(signature_png_data_url)

    signature_hash_payload = {
        "user": user,
        "employee": identity.get("employee"),
        "svg_sha256": _phase26a_sha256_text(svg),
        "vector_sha256": _phase26a_sha256_text(_phase26a_json_dumps(vector)),
        "png_sha256": _phase26a_sha256_bytes(png_bytes or b""),
    }
    signature_hash = _phase26a_sha256_text(_phase26a_json_dumps(signature_hash_payload))

    profile_name = _phase26a_profile_name_for_user(user)
    exists = frappe.db.exists(PHASE26A_PROFILE_DT, profile_name)

    if exists:
        profile = frappe.get_doc(PHASE26A_PROFILE_DT, profile_name)

        if _phase26b_fix1_profile_locked(profile) and not _phase26a_has_role("System Manager", "Internal Signature Administrator"):
            frappe.throw("Signature profile is locked. Contact signature administrator.")

        current_version = int(getattr(profile, "active_version", 0) or 0) + 1
        action = "updated"
    else:
        profile = frappe.new_doc(PHASE26A_PROFILE_DT)
        profile.name = profile_name
        profile.user = user
        current_version = 1
        action = "created"

    profile.employee = identity.get("employee")
    profile.full_name = identity.get("full_name")
    profile.designation = identity.get("designation")
    profile.department = identity.get("department")
    profile.signature_hash = signature_hash
    profile.signature_public_id = _phase26a_sha256_text(f"{user}:{signature_hash}")[:24]
    profile.active_version = current_version
    profile.is_active = 1
    profile.last_rotated_at = now_datetime()
    profile.created_ip = _phase26a_request_ip()
    profile.user_agent = _phase26a_user_agent()
    profile.security_notes = "Signature SVG and vector data are stored encrypted. PNG is stored as a private file for rendering."

    if not exists:
        profile.insert(ignore_permissions=True)
    else:
        profile.save(ignore_permissions=True)

    if png_bytes:
        from frappe.utils.file_manager import save_file

        file_doc = save_file(
            fname=f"{frappe.scrub(user)}-signature-v{current_version}-{signature_hash[:10]}.png",
            content=png_bytes,
            dt=PHASE26A_PROFILE_DT,
            dn=profile.name,
            is_private=1,
        )
        profile.signature_png = file_doc.file_url
        profile.save(ignore_permissions=True)

    _phase26a_set_encrypted(PHASE26A_PROFILE_DT, profile.name, "signature_svg_encrypted", svg)
    _phase26a_set_encrypted(PHASE26A_PROFILE_DT, profile.name, "signature_vector_json_encrypted", _phase26a_json_dumps(vector))

    version_name = f"ESIG-SIGVER-{frappe.generate_hash(length=12)}"
    version_doc = frappe.new_doc(PHASE26A_VERSION_DT)
    version_doc.name = version_name
    version_doc.profile = profile.name
    version_doc.user = user
    version_doc.employee = identity.get("employee")
    version_doc.version = current_version
    version_doc.signature_png = profile.signature_png
    version_doc.signature_hash = signature_hash
    version_doc.is_active_version = 1
    version_doc.created_ip = _phase26a_request_ip()
    version_doc.user_agent = _phase26a_user_agent()
    version_doc.insert(ignore_permissions=True)

    _phase26a_set_encrypted(PHASE26A_VERSION_DT, version_doc.name, "signature_svg_encrypted", svg)
    _phase26a_set_encrypted(PHASE26A_VERSION_DT, version_doc.name, "signature_vector_json_encrypted", _phase26a_json_dumps(vector))

    older = frappe.get_all(
        PHASE26A_VERSION_DT,
        filters={
            "profile": profile.name,
            "name": ["!=", version_doc.name],
        },
        pluck="name",
    )

    for old in older:
        frappe.db.set_value(PHASE26A_VERSION_DT, old, "is_active_version", 0, update_modified=False)

    frappe.db.commit()

    try:
        log_audit(
            "employee_signature_profile.saved",
            {
                "user": user,
                "profile": profile.name,
                "version": current_version,
                "signature_hash": signature_hash,
                "action": action,
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "phase_fix": "26B-FIX1",
        "action": action,
        "profile": profile.name,
        "user": user,
        "employee": identity.get("employee"),
        "full_name": identity.get("full_name"),
        "active_version": current_version,
        "signature_hash": signature_hash,
        "signature_public_id": profile.signature_public_id,
        "signature_png": profile.signature_png,
        "is_active": bool(profile.is_active),
        "signature_locked": bool(profile.get("signature_locked")),
        "message": "Signature profile saved securely.",
    }


@frappe.whitelist()
def phase26b_fix1_resume_after_profile_lock_fix():
    install = phase26b_install_permission_matrix()

    sync = admin_set_signature_profile_permissions(
        user="Administrator",
        allow_stored_signature_apply=1,
        allow_direction_drawing=1,
        is_locked=0,
        is_active=1,
    )

    discovered = discover_ac_footer_doctypes(limit=200)
    auto_policies = admin_auto_create_policies_for_ac_footer(limit=200)
    caps = get_my_internal_signature_capabilities()
    health = phase26b_permission_matrix_health()

    return {
        "ok": True,
        "phase_fix": "26B-FIX1",
        "install": install,
        "profile_sync": sync,
        "discovered": discovered,
        "auto_policies": auto_policies,
        "current_user_capabilities": caps,
        "health": health,
    }


# Phase 26B-FIX2: DB-level repair for conflicting DocField fieldname `is_locked`.
def _phase26b_fix2_column_exists(table_name: str, column_name: str) -> bool:
    try:
        rows = frappe.db.sql(f"SHOW COLUMNS FROM `{table_name}` LIKE %s", (column_name,), as_dict=True)
        return bool(rows)
    except Exception:
        return False


def _phase26b_fix2_table_exists(table_name: str) -> bool:
    try:
        frappe.db.sql(f"SELECT 1 FROM `{table_name}` LIMIT 1")
        return True
    except Exception:
        return False


@frappe.whitelist()
def phase26b_fix2_repair_is_locked_field_conflict():
    dt = "Employee Signature Profile"
    table_name = "tabEmployee Signature Profile"

    if not frappe.db.exists("DocType", dt):
        return {
            "ok": False,
            "reason": f"{dt} does not exist.",
        }

    # 1) Repair DocField metadata directly, because saving DocType is blocked while is_locked exists.
    old_rows = frappe.db.sql(
        """
        SELECT name, fieldname, label
        FROM `tabDocField`
        WHERE parent=%s AND fieldname='is_locked'
        """,
        (dt,),
        as_dict=True,
    )

    new_rows = frappe.db.sql(
        """
        SELECT name, fieldname, label
        FROM `tabDocField`
        WHERE parent=%s AND fieldname='signature_locked'
        """,
        (dt,),
        as_dict=True,
    )

    metadata_action = None

    if old_rows and not new_rows:
        frappe.db.sql(
            """
            UPDATE `tabDocField`
            SET fieldname='signature_locked',
                label='Signature Locked',
                fieldtype='Check',
                `default`='0',
                description='Safe lock flag for signature profile. Replaces old is_locked field to avoid Frappe Document property conflict.'
            WHERE parent=%s AND fieldname='is_locked'
            """,
            (dt,),
        )
        metadata_action = "renamed_is_locked_to_signature_locked"

    elif old_rows and new_rows:
        frappe.db.sql(
            """
            DELETE FROM `tabDocField`
            WHERE parent=%s AND fieldname='is_locked'
            """,
            (dt,),
        )
        metadata_action = "deleted_duplicate_is_locked"

    elif not old_rows and not new_rows:
        # Now it is safe to save DocType because no conflicting field exists.
        doc = frappe.get_doc("DocType", dt)
        doc.append("fields", {
            "label": "Signature Locked",
            "fieldname": "signature_locked",
            "fieldtype": "Check",
            "default": "0",
            "description": "Safe lock flag for signature profile.",
        })
        doc.save(ignore_permissions=True)
        metadata_action = "added_signature_locked"

    else:
        metadata_action = "signature_locked_already_exists"

    frappe.db.commit()

    # 2) Repair physical table column.
    table_action = None

    if _phase26b_fix2_table_exists(table_name):
        has_old = _phase26b_fix2_column_exists(table_name, "is_locked")
        has_new = _phase26b_fix2_column_exists(table_name, "signature_locked")

        if has_old and not has_new:
            frappe.db.sql(
                f"""
                ALTER TABLE `{table_name}`
                CHANGE COLUMN `is_locked` `signature_locked` int(1) NOT NULL DEFAULT 0
                """
            )
            table_action = "renamed_column_is_locked_to_signature_locked"

        elif has_old and has_new:
            frappe.db.sql(
                f"""
                UPDATE `{table_name}`
                SET `signature_locked` = COALESCE(`signature_locked`, `is_locked`, 0)
                """
            )
            frappe.db.sql(
                f"""
                ALTER TABLE `{table_name}`
                DROP COLUMN `is_locked`
                """
            )
            table_action = "merged_and_dropped_old_is_locked_column"

        elif not has_old and not has_new:
            frappe.db.sql(
                f"""
                ALTER TABLE `{table_name}`
                ADD COLUMN `signature_locked` int(1) NOT NULL DEFAULT 0
                """
            )
            table_action = "added_signature_locked_column"

        else:
            table_action = "signature_locked_column_already_exists"
    else:
        table_action = "profile_table_not_found"

    frappe.db.commit()
    frappe.clear_cache(doctype=dt)

    try:
        frappe.db.updatedb(dt)
    except Exception:
        pass

    frappe.clear_cache(doctype=dt)

    return {
        "ok": True,
        "phase_fix": "26B-FIX2",
        "doctype": dt,
        "metadata_action": metadata_action,
        "table_action": table_action,
        "old_docfield_count_before": len(old_rows),
        "signature_locked_docfield_count_before": len(new_rows),
        "has_signature_locked_column": _phase26b_fix2_column_exists(table_name, "signature_locked") if _phase26b_fix2_table_exists(table_name) else False,
        "has_old_is_locked_column": _phase26b_fix2_column_exists(table_name, "is_locked") if _phase26b_fix2_table_exists(table_name) else False,
    }


# Override FIX1 helper so it no longer tries to save a conflicted DocType.
def _phase26b_fix1_ensure_signature_locked_field():
    return phase26b_fix2_repair_is_locked_field_conflict()


@frappe.whitelist()
def admin_set_signature_profile_permissions(
    user: str,
    allow_stored_signature_apply: int = 1,
    allow_direction_drawing: int = 0,
    is_locked: int = 0,
    is_active: int = 1,
):
    if not _phase26a_has_role("System Manager", "Internal Signature Administrator"):
        frappe.throw("Only Signature Administrator can update signature profile permissions.")

    phase26b_fix2_repair_is_locked_field_conflict()

    if not user:
        frappe.throw("User is required.")

    profile_name = _phase26a_profile_name_for_user(user)

    if not frappe.db.exists(PHASE26A_PROFILE_DT, profile_name):
        frappe.throw("Signature profile does not exist for this user.")

    frappe.db.set_value(
        PHASE26A_PROFILE_DT,
        profile_name,
        {
            "allow_stored_signature_apply": int(allow_stored_signature_apply or 0),
            "allow_direction_drawing": int(allow_direction_drawing or 0),
            "signature_locked": int(is_locked or 0),
            "is_active": int(is_active or 0),
        },
        update_modified=True,
    )

    frappe.db.commit()

    profile = frappe.get_doc(PHASE26A_PROFILE_DT, profile_name)

    return {
        "ok": True,
        "phase_fix": "26B-FIX2",
        "profile": profile.name,
        "user": user,
        "allow_stored_signature_apply": bool(profile.get("allow_stored_signature_apply")),
        "allow_direction_drawing": bool(profile.get("allow_direction_drawing")),
        "signature_locked": bool(profile.get("signature_locked")),
        "is_locked": bool(profile.get("signature_locked")),
        "is_active": bool(profile.get("is_active")),
    }


@frappe.whitelist()
def get_my_internal_signature_capabilities(reference_doctype: str | None = None):
    user = frappe.session.user

    if user == "Guest":
        frappe.throw("Login is required.")

    identity = _phase26b_identity_for_user(user)

    is_admin = _phase26b_is_admin()
    roles = set(frappe.get_roles(user) or [])

    permission_exists = frappe.db.exists(PHASE26B_PERMISSION_DT, user) if frappe.db.exists("DocType", PHASE26B_PERMISSION_DT) else None

    if permission_exists:
        perm = frappe.get_doc(PHASE26B_PERMISSION_DT, user)
        capabilities = {
            "is_active": bool(perm.is_active),
            "can_receive_requests": bool(perm.can_receive_requests),
            "can_use_saved_signature": bool(perm.can_use_saved_signature),
            "can_draw_direction": bool(perm.can_draw_direction),
            "can_write_direction_text": bool(perm.can_write_direction_text),
            "can_reject": bool(perm.can_reject),
            "can_override_sequence": bool(perm.can_override_sequence),
            "can_manage_external_requests": bool(perm.can_manage_external_requests),
            "can_view_signature_audit": bool(perm.can_view_signature_audit),
            "max_sequence_level": perm.max_sequence_level,
            "source": "Internal Signature Permission",
        }
    else:
        capabilities = {
            "is_active": True,
            "can_receive_requests": bool(is_admin or "Internal Document Signer" in roles or "Internal Signature User" in roles),
            "can_use_saved_signature": bool(is_admin or "Internal Document Signer" in roles or "Internal Signature User" in roles),
            "can_draw_direction": bool(is_admin or "Internal Direction Writer" in roles),
            "can_write_direction_text": bool(is_admin or "Internal Direction Writer" in roles),
            "can_reject": bool(is_admin or "Internal Signature Manager" in roles),
            "can_override_sequence": bool(is_admin or "Internal Signature Sequence Override" in roles),
            "can_manage_external_requests": bool(is_admin or "Internal Signature API User" in roles),
            "can_view_signature_audit": bool(is_admin or "Internal Signature Auditor" in roles),
            "max_sequence_level": 99,
            "source": "Roles fallback",
        }

    profile = {}
    if frappe.db.exists("DocType", PHASE26A_PROFILE_DT) and frappe.db.exists(PHASE26A_PROFILE_DT, user):
        p = frappe.get_doc(PHASE26A_PROFILE_DT, user)
        profile = {
            "exists": True,
            "is_active": bool(p.get("is_active")),
            "signature_locked": bool(p.get("signature_locked")),
            "is_locked": bool(p.get("signature_locked")),
            "signature_hash": p.get("signature_hash"),
            "signature_public_id": p.get("signature_public_id"),
            "active_version": p.get("active_version"),
            "signature_png": p.get("signature_png"),
            "allow_stored_signature_apply": bool(p.get("allow_stored_signature_apply")),
            "allow_direction_drawing": bool(p.get("allow_direction_drawing")),
        }
    else:
        profile = {"exists": False}

    policy = None
    if reference_doctype and frappe.db.exists("DocType", PHASE26B_POLICY_DT):
        if frappe.db.exists(PHASE26B_POLICY_DT, reference_doctype):
            pol = frappe.get_doc(PHASE26B_POLICY_DT, reference_doctype)
            policy = {
                "exists": True,
                "reference_doctype": pol.reference_doctype,
                "is_active": bool(pol.is_active),
                "ac_footer_fieldname": pol.ac_footer_fieldname,
                "workflow_mode": pol.workflow_mode,
                "allow_saved_signature": bool(pol.allow_saved_signature),
                "allow_direction": bool(pol.allow_direction),
                "allow_direction_drawing": bool(pol.allow_direction_drawing),
                "allow_direction_text": bool(pol.allow_direction_text),
                "allow_reject": bool(pol.allow_reject),
                "require_signature_profile": bool(pol.require_signature_profile),
                "allow_external_requests": bool(pol.allow_external_requests),
            }
        else:
            policy = {"exists": False, "reference_doctype": reference_doctype}

    effective = dict(capabilities)

    if profile.get("exists"):
        effective["can_use_saved_signature"] = bool(
            effective.get("can_use_saved_signature")
            and profile.get("is_active")
            and profile.get("allow_stored_signature_apply")
        )
        effective["can_draw_direction"] = bool(
            effective.get("can_draw_direction")
            and profile.get("is_active")
            and profile.get("allow_direction_drawing")
        )
    else:
        effective["can_use_saved_signature"] = False
        effective["can_draw_direction"] = False

    if policy and policy.get("exists"):
        effective["can_use_saved_signature"] = bool(
            effective.get("can_use_saved_signature")
            and policy.get("is_active")
            and policy.get("allow_saved_signature")
        )
        effective["can_draw_direction"] = bool(
            effective.get("can_draw_direction")
            and policy.get("is_active")
            and policy.get("allow_direction")
            and policy.get("allow_direction_drawing")
        )
        effective["can_write_direction_text"] = bool(
            effective.get("can_write_direction_text")
            and policy.get("is_active")
            and policy.get("allow_direction")
            and policy.get("allow_direction_text")
        )
        effective["can_reject"] = bool(effective.get("can_reject") and policy.get("allow_reject"))

    return {
        "ok": True,
        "phase_fix": "26B-FIX2",
        "user": user,
        "identity": identity,
        "roles": sorted(list(roles)),
        "is_admin": is_admin,
        "permission_exists": bool(permission_exists),
        "profile": profile,
        "policy": policy,
        "capabilities": capabilities,
        "effective_capabilities": effective,
    }


@frappe.whitelist()
def phase26b_fix2_resume_after_is_locked_repair():
    repair = phase26b_fix2_repair_is_locked_field_conflict()

    install = phase26b_install_permission_matrix()

    admin_perm = admin_upsert_internal_signature_permission(
        user="Administrator",
        can_use_saved_signature=1,
        can_draw_direction=1,
        can_write_direction_text=1,
        can_reject=1,
        can_override_sequence=1,
        can_manage_external_requests=1,
        can_view_signature_audit=1,
        can_receive_requests=1,
        max_sequence_level=99,
        allowed_doctypes_json=[],
        is_active=1,
        notes="Bootstrap full internal signature capabilities for Administrator after FIX2.",
    )

    sync = admin_set_signature_profile_permissions(
        user="Administrator",
        allow_stored_signature_apply=1,
        allow_direction_drawing=1,
        is_locked=0,
        is_active=1,
    )

    discovered = discover_ac_footer_doctypes(limit=200)
    auto_policies = admin_auto_create_policies_for_ac_footer(limit=200)
    caps = get_my_internal_signature_capabilities()
    health = phase26b_permission_matrix_health()

    return {
        "ok": True,
        "phase_fix": "26B-FIX2",
        "repair": repair,
        "install": install,
        "administrator_permission": admin_perm,
        "profile_sync": sync,
        "discovered": discovered,
        "auto_policies": auto_policies,
        "current_user_capabilities": caps,
        "health": health,
    }


# Phase 26C: Ac Footer Watcher + Document Signature Request.
import json as _phase26c_json
import hashlib as _phase26c_hashlib


PHASE26C_REQUEST_DT = "Document Signature Request"
PHASE26C_AC_FOOTER_CHILD_DT = "AC Footer Signer"
PHASE26C_DEMO_DT = "Internal Signature Demo Document"


def _phase26c_json_dumps(data) -> str:
    return _phase26c_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _phase26c_hash_doc(doc) -> str:
    payload = {}

    try:
        meta = frappe.get_meta(doc.doctype)
        for df in meta.fields:
            if df.fieldtype in {"Section Break", "Column Break", "Tab Break", "HTML", "Button"}:
                continue
            if df.fieldname in {"modified", "modified_by", "creation", "owner"}:
                continue
            try:
                value = doc.get(df.fieldname)
                if df.fieldtype == "Table":
                    rows = []
                    for r in value or []:
                        rows.append({
                            k: v for k, v in r.as_dict().items()
                            if k not in {"doctype", "parent", "parenttype", "parentfield", "idx", "modified", "modified_by", "creation", "owner"}
                        })
                    value = rows
                payload[df.fieldname] = value
            except Exception:
                pass
    except Exception:
        payload = doc.as_dict()

    return _phase26c_hashlib.sha256(_phase26c_json_dumps(payload).encode("utf-8")).hexdigest()


def _phase26c_next_name(prefix: str) -> str:
    year = str(frappe.utils.nowdate())[:4]
    stem = f"{prefix}-{year}-"

    rows = frappe.db.sql(
        """
        SELECT name
        FROM `tabDocument Signature Request`
        WHERE name LIKE %s
        ORDER BY name DESC
        LIMIT 1
        """,
        (stem + "%",),
        as_dict=True,
    ) if frappe.db.exists("DocType", PHASE26C_REQUEST_DT) else []

    if rows:
        try:
            n = int(str(rows[0].name).split("-")[-1]) + 1
        except Exception:
            n = 1
    else:
        n = 1

    return f"{stem}{n:05d}"




def _phase26c_ensure_module():
    if globals().get("_phase26b_ensure_module"):
        return _phase26b_ensure_module()
    if globals().get("_phase26a_fix_ensure_module_def"):
        return _phase26a_fix_ensure_module_def("Signing")

    if frappe.db.exists("Module Def", "Signing"):
        return {"ok": True, "module": "Signing", "created": False}

    doc = frappe.new_doc("Module Def")
    doc.module_name = "Signing"

    if frappe.get_meta("Module Def").has_field("app_name"):
        doc.app_name = "surhan_signature"

    if frappe.get_meta("Module Def").has_field("custom"):
        doc.custom = 1

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {"ok": True, "module": "Signing", "created": True}


def _phase26c_field(label, fieldname, fieldtype, options=None, reqd=0, hidden=0, read_only=0,
                    unique=0, in_list_view=0, default=None, description=None):
    return {
        "label": label,
        "fieldname": fieldname,
        "fieldtype": fieldtype,
        "options": options,
        "reqd": reqd,
        "hidden": hidden,
        "read_only": read_only,
        "unique": unique,
        "in_list_view": in_list_view,
        "default": default,
        "description": description,
    }


def _phase26c_permission(role, read=1, write=0, create=0, delete=0, submit=0, cancel=0, amend=0):
    return {
        "role": role,
        "read": read,
        "write": write,
        "create": create,
        "delete": delete,
        "submit": submit,
        "cancel": cancel,
        "amend": amend,
    }


def _phase26c_ensure_doctype(doctype_name, fields, permissions=None, autoname="prompt", title_field=None, istable=0):
    _phase26c_ensure_module()

    permissions = permissions or []

    clean_fields = []
    for f in fields:
        clean = {k: v for k, v in f.items() if v is not None}
        clean_fields.append(clean)

    if frappe.db.exists("DocType", doctype_name):
        dt = frappe.get_doc("DocType", doctype_name)
        existing = {d.fieldname for d in dt.fields if d.fieldname}
        changed = False

        if getattr(dt, "module", None) != "Signing":
            dt.module = "Signing"
            changed = True

        if int(getattr(dt, "istable", 0) or 0) != int(istable or 0):
            dt.istable = int(istable or 0)
            changed = True

        for field in clean_fields:
            if field.get("fieldname") and field["fieldname"] not in existing:
                dt.append("fields", field)
                changed = True

        if changed:
            dt.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.clear_cache(doctype=doctype_name)
            try:
                frappe.db.updatedb(doctype_name)
            except Exception:
                pass

        return {
            "doctype": doctype_name,
            "created": False,
            "updated": changed,
            "istable": bool(istable),
        }

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": doctype_name,
        "module": "Signing",
        "custom": 1,
        "istable": int(istable or 0),
        "autoname": autoname,
        "title_field": title_field,
        "track_changes": 1,
        "fields": clean_fields,
        "permissions": permissions,
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    frappe.clear_cache(doctype=doctype_name)

    try:
        frappe.db.updatedb(doctype_name)
    except Exception:
        pass

    return {
        "doctype": doctype_name,
        "created": True,
        "updated": True,
        "istable": bool(istable),
    }


def _phase26c_identity_from_employee_or_user(employee=None, user=None):
    identity = {
        "employee": employee,
        "user": user,
        "full_name": None,
        "designation": None,
        "department": None,
    }

    if employee and frappe.db.exists("DocType", "Employee") and frappe.db.exists("Employee", employee):
        vals = frappe.db.get_value(
            "Employee",
            employee,
            ["user_id", "employee_name", "designation", "department"],
        )
        if vals:
            user_id, employee_name, designation, department = vals
            identity.update({
                "user": user or user_id,
                "full_name": employee_name,
                "designation": designation,
                "department": department,
            })

    if user and not identity.get("employee") and frappe.db.exists("DocType", "Employee"):
        emp = frappe.db.get_value("Employee", {"user_id": user}, "name")
        if emp:
            return _phase26c_identity_from_employee_or_user(employee=emp, user=user)

    if identity.get("user") and not identity.get("full_name"):
        identity["full_name"] = frappe.db.get_value("User", identity["user"], "full_name") or identity["user"]

    return identity


def _phase26c_get_policy(reference_doctype: str):
    if frappe.db.exists("DocType", "Internal Signature Policy") and frappe.db.exists("Internal Signature Policy", reference_doctype):
        return frappe.get_doc("Internal Signature Policy", reference_doctype)

    return frappe._dict({
        "name": None,
        "reference_doctype": reference_doctype,
        "is_active": 1,
        "ac_footer_fieldname": "ac_footer",
        "workflow_mode": "Sequential",
        "approval_sequence_mode": "As Listed",
        "allow_saved_signature": 1,
        "allow_direction": 1,
        "allow_direction_drawing": 1,
        "allow_direction_text": 1,
        "allow_reject": 1,
        "require_signature_profile": 1,
        "allow_external_requests": 0,
        "allow_on_submitted_docs": 0,
        "lock_after_complete": 1,
    })


def _phase26c_parse_ac_footer(doc, policy):
    fieldname = policy.ac_footer_fieldname or "ac_footer"
    meta = frappe.get_meta(doc.doctype)

    if not meta.has_field(fieldname):
        return []

    df = meta.get_field(fieldname)
    value = doc.get(fieldname)
    rows = []

    if df.fieldtype == "Table":
        for idx, row in enumerate(value or [], start=1):
            employee = row.get("employee")
            user = row.get("user")
            identity = _phase26c_identity_from_employee_or_user(employee=employee, user=user)

            if not identity.get("user"):
                continue

            sign_order = int(row.get("sign_order") or idx)
            action_required = row.get("action_required") or "Saved Signature"

            rows.append({
                "ac_footer_row_name": row.name,
                "idx": idx,
                "employee": identity.get("employee"),
                "user": identity.get("user"),
                "full_name": identity.get("full_name"),
                "designation": identity.get("designation"),
                "department": identity.get("department"),
                "sign_order": sign_order,
                "action_required": action_required,
                "can_use_saved_signature": int(row.get("can_use_saved_signature") if row.get("can_use_saved_signature") is not None else 1),
                "can_draw_direction": int(row.get("can_draw_direction") or 0),
                "can_write_direction_text": int(row.get("can_write_direction_text") or 0),
                "can_reject": int(row.get("can_reject") or 0),
            })

    elif df.fieldtype in {"Link", "Data", "Small Text", "Text"}:
        raw = value
        if not raw:
            return []

        tokens = []
        if isinstance(raw, str):
            for part in raw.replace(",", "\n").splitlines():
                part = part.strip()
                if part:
                    tokens.append(part)
        else:
            tokens = [raw]

        for idx, token in enumerate(tokens, start=1):
            employee = token if frappe.db.exists("DocType", "Employee") and frappe.db.exists("Employee", token) else None
            user = token if frappe.db.exists("User", token) else None
            identity = _phase26c_identity_from_employee_or_user(employee=employee, user=user)

            if not identity.get("user"):
                continue

            rows.append({
                "ac_footer_row_name": f"text-{idx}",
                "idx": idx,
                "employee": identity.get("employee"),
                "user": identity.get("user"),
                "full_name": identity.get("full_name"),
                "designation": identity.get("designation"),
                "department": identity.get("department"),
                "sign_order": idx,
                "action_required": "Saved Signature",
                "can_use_saved_signature": 1,
                "can_draw_direction": 0,
                "can_write_direction_text": 0,
                "can_reject": 0,
            })

    return rows


def _phase26c_request_exists(reference_doctype, reference_name, user, ac_footer_row_name):
    rows = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
            "requested_user": user,
            "ac_footer_row_name": ac_footer_row_name,
        },
        pluck="name",
        limit=1,
    )
    return rows[0] if rows else None


def _phase26c_notify_request(req):
    subject = f"Document waiting for your signature: {req.reference_doctype} {req.reference_name}"

    try:
        frappe.get_doc({
            "doctype": "Notification Log",
            "subject": subject,
            "type": "Alert",
            "for_user": req.requested_user,
            "document_type": req.reference_doctype,
            "document_name": req.reference_name,
            "email_content": subject,
        }).insert(ignore_permissions=True)
    except Exception:
        pass

    try:
        exists = frappe.get_all(
            "ToDo",
            filters={
                "allocated_to": req.requested_user,
                "reference_type": req.reference_doctype,
                "reference_name": req.reference_name,
                "status": "Open",
            },
            pluck="name",
            limit=1,
        )

        if not exists:
            frappe.get_doc({
                "doctype": "ToDo",
                "allocated_to": req.requested_user,
                "reference_type": req.reference_doctype,
                "reference_name": req.reference_name,
                "description": subject,
                "priority": "Medium",
                "status": "Open",
            }).insert(ignore_permissions=True)
    except Exception:
        pass


def _phase26c_recalculate_sequence(reference_doctype, reference_name):
    requests = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
            "status": ["!=", "Cancelled"],
        },
        fields=["name", "sequence_order", "status", "workflow_mode", "ac_footer_row_name"],
        order_by="sequence_order asc, creation asc",
        limit_page_length=500,
    )

    if not requests:
        return {"updated": 0, "pending": []}

    workflow_mode = requests[0].workflow_mode or "Sequential"
    done = {"Signed", "Directed", "Rejected"}
    updated = 0
    pending = []

    if workflow_mode == "Parallel":
        for r in requests:
            if r.status not in done and r.status != "Pending":
                frappe.db.set_value(PHASE26C_REQUEST_DT, r.name, "status", "Pending", update_modified=False)
                updated += 1
            if r.status not in done:
                pending.append(r.name)
    else:
        min_order = None
        for r in requests:
            if r.status not in done:
                seq = r.sequence_order or 1
                if min_order is None or seq < min_order:
                    min_order = seq

        for r in requests:
            if r.status in done:
                continue

            seq = r.sequence_order or 1
            if min_order is not None and seq <= min_order:
                if r.status != "Pending":
                    frappe.db.set_value(PHASE26C_REQUEST_DT, r.name, "status", "Pending", update_modified=False)
                    frappe.db.set_value(PHASE26C_REQUEST_DT, r.name, "activated_at", now_datetime(), update_modified=False)
                    updated += 1
                pending.append(r.name)
            else:
                if r.status != "Waiting":
                    frappe.db.set_value(PHASE26C_REQUEST_DT, r.name, "status", "Waiting", update_modified=False)
                    updated += 1

    for r in requests:
        if getattr(r, "ac_footer_row_name", None) and frappe.db.exists(PHASE26C_AC_FOOTER_CHILD_DT, r.ac_footer_row_name):
            curr_status = frappe.db.get_value(PHASE26C_REQUEST_DT, r.name, "status")
            frappe.db.set_value(PHASE26C_AC_FOOTER_CHILD_DT, r.ac_footer_row_name, "status", curr_status, update_modified=False)

    frappe.db.commit()

    for name in pending:
        try:
            req = frappe.get_doc(PHASE26C_REQUEST_DT, name)
            _phase26c_notify_request(req)
        except Exception:
            pass

    return {
        "updated": updated,
        "pending": pending,
        "workflow_mode": workflow_mode,
    }


@frappe.whitelist()
def phase26c_install_document_signature_requests():
    _phase26c_ensure_module()

    request_fields = [
        _phase26c_field("Reference DocType", "reference_doctype", "Link", "DocType", reqd=1, in_list_view=1),
        _phase26c_field("Reference Name", "reference_name", "Dynamic Link", "reference_doctype", reqd=1, in_list_view=1),
        _phase26c_field("Reference Title", "reference_title", "Data", read_only=1),
        _phase26c_field("Policy", "policy", "Link", "Internal Signature Policy"),
        _phase26c_field("Ac Footer Row Name", "ac_footer_row_name", "Data", read_only=1),
        _phase26c_field("Requested User", "requested_user", "Link", "User", reqd=1, in_list_view=1),
        _phase26c_field("Requested Employee", "requested_employee", "Link", "Employee", in_list_view=1),
        _phase26c_field("Full Name", "full_name", "Data", in_list_view=1),
        _phase26c_field("Designation", "designation", "Data"),
        _phase26c_field("Department", "department", "Data"),
        _phase26c_field("Sequence Order", "sequence_order", "Int", default=1, in_list_view=1),
        _phase26c_field("Workflow Mode", "workflow_mode", "Select", "Sequential\nParallel", default="Sequential"),
        _phase26c_field("Action Required", "action_required", "Select", "Saved Signature\nDirection\nBoth", default="Saved Signature", in_list_view=1),
        _phase26c_field("Status", "status", "Select", "Waiting\nPending\nSigned\nDirected\nRejected\nCancelled", default="Waiting", in_list_view=1),
        _phase26c_field("Can Use Saved Signature", "can_use_saved_signature", "Check", default=1),
        _phase26c_field("Can Draw Direction", "can_draw_direction", "Check", default=0),
        _phase26c_field("Can Write Direction Text", "can_write_direction_text", "Check", default=0),
        _phase26c_field("Can Reject", "can_reject", "Check", default=0),
        _phase26c_field("Requested By", "requested_by", "Link", "User", read_only=1),
        _phase26c_field("Requested At", "requested_at", "Datetime", read_only=1),
        _phase26c_field("Activated At", "activated_at", "Datetime", read_only=1),
        _phase26c_field("Completed At", "completed_at", "Datetime", read_only=1),
        _phase26c_field("Signature Profile", "signature_profile", "Link", "Employee Signature Profile"),
        _phase26c_field("Signature Hash", "signature_hash", "Data", read_only=1),
        _phase26c_field("Signature PNG", "signature_png", "Data", read_only=1),
        _phase26c_field("Direction Text", "direction_text", "Small Text"),
        _phase26c_field("Direction SVG Encrypted", "direction_svg_encrypted", "Password", hidden=1),
        _phase26c_field("Signed IP", "signed_ip", "Data", read_only=1),
        _phase26c_field("User Agent", "user_agent", "Small Text", read_only=1),
        _phase26c_field("Document Hash Before", "doc_hash_before", "Data", read_only=1),
        _phase26c_field("Document Hash After", "doc_hash_after", "Data", read_only=1),
        _phase26c_field("Source", "source", "Select", "Ac Footer\nManual\nExternal API", default="Ac Footer"),
        _phase26c_field("External System", "external_system", "Data"),
        _phase26c_field("External Reference", "external_reference", "Data"),
    ]

    ac_footer_fields = [
        _phase26c_field("Employee", "employee", "Link", "Employee", in_list_view=1),
        _phase26c_field("User", "user", "Link", "User", in_list_view=1),
        _phase26c_field("Full Name", "full_name", "Data", read_only=1),
        _phase26c_field("Designation", "designation", "Data", read_only=1),
        _phase26c_field("Department", "department", "Data", read_only=1),
        _phase26c_field("Sign Order", "sign_order", "Int", default=1, in_list_view=1),
        _phase26c_field("Action Required", "action_required", "Select", "Saved Signature\nDirection\nBoth", default="Saved Signature", in_list_view=1),
        _phase26c_field("Can Use Saved Signature", "can_use_saved_signature", "Check", default=1),
        _phase26c_field("Can Draw Direction", "can_draw_direction", "Check", default=0),
        _phase26c_field("Can Write Direction Text", "can_write_direction_text", "Check", default=0),
        _phase26c_field("Can Reject", "can_reject", "Check", default=0),
        _phase26c_field("Status", "status", "Select", "Draft\nWaiting\nPending\nSigned\nDirected\nRejected", default="Draft", in_list_view=1),
        _phase26c_field("Signature Request", "signature_request", "Link", PHASE26C_REQUEST_DT, read_only=1),
        _phase26c_field("Notes", "notes", "Small Text"),
    ]

    demo_fields = [
        _phase26c_field("Title", "title", "Data", reqd=1, in_list_view=1),
        _phase26c_field("Content", "content", "Text Editor"),
        _phase26c_field("Ac Footer", "ac_footer", "Table", PHASE26C_AC_FOOTER_CHILD_DT),
        _phase26c_field("Internal Signature Status", "internal_signature_status", "Data", read_only=1),
    ]

    perms = [
        _phase26c_permission("System Manager", read=1, write=1, create=1, delete=1),
        _phase26c_permission("Internal Signature Administrator", read=1, write=1, create=1, delete=0),
        _phase26c_permission("Internal Signature Manager", read=1, write=1, create=1, delete=0),
        _phase26c_permission("Internal Signature Auditor", read=1, write=0, create=0, delete=0),
    ]

    request_dt = _phase26c_ensure_doctype(
        PHASE26C_REQUEST_DT,
        request_fields,
        perms,
        autoname="prompt",
        title_field="reference_name",
        istable=0,
    )

    child_dt = _phase26c_ensure_doctype(
        PHASE26C_AC_FOOTER_CHILD_DT,
        ac_footer_fields,
        [],
        autoname="hash",
        title_field="full_name",
        istable=1,
    )

    demo_dt = _phase26c_ensure_doctype(
        PHASE26C_DEMO_DT,
        demo_fields,
        [
            _phase26c_permission("System Manager", read=1, write=1, create=1, delete=1),
            _phase26c_permission("Internal Signature Administrator", read=1, write=1, create=1, delete=1),
            _phase26c_permission("Internal Signature User", read=1, write=1, create=1, delete=0),
        ],
        autoname="format:ISD-.YYYY.-.#####",
        title_field="title",
        istable=0,
    )

    if globals().get("admin_upsert_internal_signature_policy"):
        try:
            admin_upsert_internal_signature_policy(
                reference_doctype=PHASE26C_DEMO_DT,
                ac_footer_fieldname="ac_footer",
                workflow_mode="Sequential",
                approval_sequence_mode="As Listed",
                allow_saved_signature=1,
                allow_direction=1,
                allow_direction_drawing=1,
                allow_direction_text=1,
                allow_reject=1,
                require_signature_profile=1,
                allow_external_requests=1,
                is_active=1,
                notes="Phase 26C demo policy.",
            )
        except Exception:
            pass

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26C",
        "doctypes": [request_dt, child_dt, demo_dt],
    }


@frappe.whitelist()
def install_ac_footer_on_doctype(reference_doctype: str, fieldname: str = "ac_footer", insert_after: str | None = None):
    if not globals().get("_phase26b_is_admin") or not _phase26b_is_admin():
        frappe.throw("Only Internal Signature Administrator can install Ac Footer on a DocType.")

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    phase26c_install_document_signature_requests()

    meta = frappe.get_meta(reference_doctype)

    if meta.has_field(fieldname):
        action = "already_exists"
    else:
        cf_name = f"{reference_doctype}-{fieldname}"

        if frappe.db.exists("Custom Field", cf_name):
            action = "custom_field_already_exists"
        else:
            cf = frappe.new_doc("Custom Field")
            cf.dt = reference_doctype
            cf.fieldname = fieldname
            cf.label = "Ac Footer"
            cf.fieldtype = "Table"
            cf.options = PHASE26C_AC_FOOTER_CHILD_DT
            cf.insert_after = insert_after or None
            cf.description = "Internal signature Ac Footer signers. Created by Surhan Signature."
            cf.insert(ignore_permissions=True)
            action = "created_custom_field"

        frappe.db.commit()
        frappe.clear_cache(doctype=reference_doctype)

    if globals().get("admin_upsert_internal_signature_policy"):
        policy = admin_upsert_internal_signature_policy(
            reference_doctype=reference_doctype,
            ac_footer_fieldname=fieldname,
            workflow_mode="Sequential",
            approval_sequence_mode="As Listed",
            allow_saved_signature=1,
            allow_direction=1,
            allow_direction_drawing=1,
            allow_direction_text=1,
            allow_reject=1,
            require_signature_profile=1,
            allow_external_requests=0,
            is_active=1,
            notes="Policy created by install_ac_footer_on_doctype.",
        )
    else:
        policy = None

    return {
        "ok": True,
        "reference_doctype": reference_doctype,
        "fieldname": fieldname,
        "action": action,
        "policy": policy,
    }


@frappe.whitelist()
def sync_ac_footer_requests(reference_doctype: str, reference_name: str):
    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    if reference_doctype in _phase26c_internal_doctypes():
        return {"ok": True, "skipped": True, "reason": "Internal signature doctype."}

    if not frappe.db.exists(reference_doctype, reference_name):
        frappe.throw(f"Document not found: {reference_doctype} {reference_name}")

    doc = frappe.get_doc(reference_doctype, reference_name)
    policy = _phase26c_get_policy(reference_doctype)

    if not int(policy.is_active or 0):
        return {"ok": True, "skipped": True, "reason": "Policy inactive."}

    rows = _phase26c_parse_ac_footer(doc, policy)

    created = []
    updated = []
    skipped = []

    doc_hash_before = _phase26c_hash_doc(doc)
    title = getattr(doc, "title", None) or getattr(doc, "subject", None) or getattr(doc, "name", None)

    for row in rows:
        existing = _phase26c_request_exists(
            reference_doctype,
            reference_name,
            row["user"],
            row["ac_footer_row_name"],
        )

        if existing:
            req = frappe.get_doc(PHASE26C_REQUEST_DT, existing)

            if req.status in {"Signed", "Directed", "Rejected", "Cancelled"}:
                skipped.append({"request": req.name, "reason": f"Already {req.status}"})
                continue

            req.sequence_order = row["sign_order"]
            req.action_required = row["action_required"]
            req.can_use_saved_signature = int(row["can_use_saved_signature"] or 0)
            req.can_draw_direction = int(row["can_draw_direction"] or 0)
            req.can_write_direction_text = int(row["can_write_direction_text"] or 0)
            req.can_reject = int(row["can_reject"] or 0)
            req.save(ignore_permissions=True)
            updated.append(req.name)
        else:
            req = frappe.new_doc(PHASE26C_REQUEST_DT)
            req.name = _phase26c_next_name("DSR")
            req.reference_doctype = reference_doctype
            req.reference_name = reference_name
            req.reference_title = title
            req.policy = policy.name if getattr(policy, "name", None) else None
            req.ac_footer_row_name = row["ac_footer_row_name"]
            req.requested_user = row["user"]
            req.requested_employee = row["employee"]
            req.full_name = row["full_name"]
            req.designation = row["designation"]
            req.department = row["department"]
            req.sequence_order = row["sign_order"]
            req.workflow_mode = policy.workflow_mode or "Sequential"
            req.action_required = row["action_required"]
            req.status = "Waiting"
            req.can_use_saved_signature = int(row["can_use_saved_signature"] or 0)
            req.can_draw_direction = int(row["can_draw_direction"] or 0)
            req.can_write_direction_text = int(row["can_write_direction_text"] or 0)
            req.can_reject = int(row["can_reject"] or 0)
            req.requested_by = frappe.session.user
            req.requested_at = now_datetime()
            req.doc_hash_before = doc_hash_before
            req.source = "Ac Footer"
            req.insert(ignore_permissions=True)
            created.append(req.name)

        # Best-effort sync child row fields.
        try:
            if row["ac_footer_row_name"] and not str(row["ac_footer_row_name"]).startswith("text-"):
                frappe.db.set_value(
                    PHASE26C_AC_FOOTER_CHILD_DT,
                    row["ac_footer_row_name"],
                    {
                        "full_name": row["full_name"],
                        "designation": row["designation"],
                        "department": row["department"],
                        "status": "Waiting",
                        "signature_request": req.name,
                    },
                    update_modified=False,
                )
        except Exception:
            pass

    seq = _phase26c_recalculate_sequence(reference_doctype, reference_name)

    # Best-effort update child row statuses from request statuses.
    try:
        requests = frappe.get_all(
            PHASE26C_REQUEST_DT,
            filters={"reference_doctype": reference_doctype, "reference_name": reference_name},
            fields=["name", "ac_footer_row_name", "status"],
        )
        for r in requests:
            if r.ac_footer_row_name and not str(r.ac_footer_row_name).startswith("text-"):
                frappe.db.set_value(
                    PHASE26C_AC_FOOTER_CHILD_DT,
                    r.ac_footer_row_name,
                    {
                        "status": r.status,
                        "signature_request": r.name,
                    },
                    update_modified=False,
                )
    except Exception:
        pass

    frappe.db.commit()

    try:
        log_audit(
            "internal_document_signature.ac_footer_synced",
            {
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "sequence": seq,
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "parsed_signers": len(rows),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "sequence": seq,
    }


def phase26c_on_document_update(doc, method=None):
    try:
        if not doc or getattr(doc, "doctype", None) in _phase26c_internal_doctypes():
            return

        if getattr(frappe.local, "phase26c_syncing", False):
            return

        meta = frappe.get_meta(doc.doctype)
        if not meta.has_field("ac_footer"):
            return

        frappe.local.phase26c_syncing = True
        sync_ac_footer_requests(doc.doctype, doc.name)
    except Exception:
        try:
            frappe.log_error(frappe.get_traceback(), "Phase 26C Ac Footer Watcher Error")
        except Exception:
            pass
    finally:
        frappe.local.phase26c_syncing = False


@frappe.whitelist()
def get_document_signature_state(reference_doctype: str, reference_name: str):
    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    requests = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
        },
        fields=[
            "name",
            "requested_user",
            "requested_employee",
            "full_name",
            "designation",
            "department",
            "sequence_order",
            "workflow_mode",
            "action_required",
            "status",
            "can_use_saved_signature",
            "can_draw_direction",
            "can_write_direction_text",
            "can_reject",
            "signature_hash",
            "completed_at",
            "source",
        ],
        order_by="sequence_order asc, creation asc",
        limit_page_length=500,
    )

    status_counts = {}
    for r in requests:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    complete = bool(requests) and all(r.status in {"Signed", "Directed", "Rejected", "Cancelled"} for r in requests)

    return {
        "ok": True,
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "count": len(requests),
        "complete": complete,
        "status_counts": status_counts,
        "requests": requests,
    }






@frappe.whitelist()
def phase26c_document_signature_request_health():
    doctypes = {
        PHASE26C_REQUEST_DT: bool(frappe.db.exists("DocType", PHASE26C_REQUEST_DT)),
        PHASE26C_AC_FOOTER_CHILD_DT: bool(frappe.db.exists("DocType", PHASE26C_AC_FOOTER_CHILD_DT)),
        PHASE26C_DEMO_DT: bool(frappe.db.exists("DocType", PHASE26C_DEMO_DT)),
        "Internal Signature Policy": bool(frappe.db.exists("DocType", "Internal Signature Policy")),
        "Internal Signature Permission": bool(frappe.db.exists("DocType", "Internal Signature Permission")),
        "Employee Signature Profile": bool(frappe.db.exists("DocType", "Employee Signature Profile")),
    }

    counts = {}
    for dt in [PHASE26C_REQUEST_DT, PHASE26C_DEMO_DT]:
        counts[dt] = frappe.db.count(dt) if frappe.db.exists("DocType", dt) else 0

    pending = 0
    if frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        pending = frappe.db.count(PHASE26C_REQUEST_DT, {"status": "Pending"})

    health = {
        "ok": True,
        "phase": "26C",
        "module_signing": bool(frappe.db.exists("Module Def", "Signing")),
        "doctypes": doctypes,
        "counts": counts,
        "pending_count": pending,
        "ready": all(doctypes.values()),
    }

    return health


# Phase 26C-FIX2: allow demo doctype to be signable and repair bad demo naming.
def _phase26c_internal_doctypes():
    # Important: do NOT include Internal Signature Demo Document here.
    # The demo document is intentionally signable for testing Ac Footer.
    return {
        PHASE26C_REQUEST_DT,
        PHASE26C_AC_FOOTER_CHILD_DT,
        "Employee Signature Profile",
        "Employee Signature Profile Version",
        "Internal Signature Permission",
        "Internal Signature Policy",
        "E-Sign Envelope",
        "E-Sign Recipient",
        "E-Sign Signature Field",
        "E-Sign Audit Log",
        "E-Sign Certificate",
        "E-Sign Security Event",
        "E-Sign Settings",
        "E-Sign Webhook Endpoint",
        "E-Sign Webhook Delivery",
        "E-Sign Risk Assessment",
        "E-Sign Test Run",
    }


def _phase26c_next_demo_name():
    year = str(frappe.utils.nowdate())[:4]
    stem = f"ISD-{year}-"
    table = f"tab{PHASE26C_DEMO_DT}"

    try:
        rows = frappe.db.sql(
            f"""
            SELECT name
            FROM `{table}`
            WHERE name LIKE %s
            ORDER BY name DESC
            LIMIT 1
            """,
            (stem + "%",),
            as_dict=True,
        )
    except Exception:
        rows = []

    if rows:
        try:
            n = int(str(rows[0].name).split("-")[-1]) + 1
        except Exception:
            n = 1
    else:
        n = 1

    return f"{stem}{n:05d}"


def _phase26c_ensure_demo_policy():
    if globals().get("admin_upsert_internal_signature_policy"):
        return admin_upsert_internal_signature_policy(
            reference_doctype=PHASE26C_DEMO_DT,
            ac_footer_fieldname="ac_footer",
            workflow_mode="Sequential",
            approval_sequence_mode="As Listed",
            allow_saved_signature=1,
            allow_direction=1,
            allow_direction_drawing=1,
            allow_direction_text=1,
            allow_reject=1,
            require_signature_profile=1,
            allow_external_requests=1,
            is_active=1,
            notes="Phase 26C-FIX2 demo policy.",
        )

    return None


def _phase26c_add_current_user_to_demo_if_missing(doc):
    identity = _phase26c_identity_from_employee_or_user(user=frappe.session.user)

    if not identity.get("user"):
        frappe.throw("Current user has no valid User identity.")

    existing = False

    for row in doc.get("ac_footer") or []:
        if row.get("user") == identity.get("user") or row.get("employee") == identity.get("employee"):
            existing = True

            row.full_name = identity.get("full_name")
            row.designation = identity.get("designation")
            row.department = identity.get("department")

            if not row.sign_order:
                row.sign_order = 1

            if not row.action_required:
                row.action_required = "Both"

            row.can_use_saved_signature = 1
            row.can_draw_direction = 1
            row.can_write_direction_text = 1
            row.can_reject = 1

    if not existing:
        row = doc.append("ac_footer", {})
        row.employee = identity.get("employee")
        row.user = identity.get("user")
        row.full_name = identity.get("full_name")
        row.designation = identity.get("designation")
        row.department = identity.get("department")
        row.sign_order = 1
        row.action_required = "Both"
        row.can_use_saved_signature = 1
        row.can_draw_direction = 1
        row.can_write_direction_text = 1
        row.can_reject = 1
        row.status = "Draft"

    return doc




@frappe.whitelist()
def phase26c_fix2_repair_demo_documents_and_sync():
    phase26c_install_document_signature_requests()
    policy = _phase26c_ensure_demo_policy()

    repaired_names = []
    synced = []
    created_demo = None

    bad_name = "ISD-.YYYY.-.#####"

    if frappe.db.exists(PHASE26C_DEMO_DT, bad_name):
        new_name = _phase26c_next_demo_name()

        try:
            frappe.rename_doc(
                PHASE26C_DEMO_DT,
                bad_name,
                new_name,
                force=True,
                ignore_permissions=True,
            )
            frappe.db.commit()
            repaired_names.append({
                "old": bad_name,
                "new": new_name,
                "action": "renamed",
            })
        except Exception as exc:
            repaired_names.append({
                "old": bad_name,
                "new": None,
                "action": "rename_failed",
                "error": str(exc),
            })

    demos = frappe.get_all(
        PHASE26C_DEMO_DT,
        fields=["name"],
        order_by="creation asc",
        limit_page_length=50,
    )

    if not demos:
        created_demo = create_internal_signature_demo_document()
        demos = [{"name": created_demo.get("name")}]

    for d in demos:
        if not d.get("name"):
            continue

        doc = frappe.get_doc(PHASE26C_DEMO_DT, d.name)
        _phase26c_add_current_user_to_demo_if_missing(doc)
        doc.save(ignore_permissions=True)
        frappe.db.commit()

        result = sync_ac_footer_requests(PHASE26C_DEMO_DT, doc.name)
        state = get_document_signature_state(PHASE26C_DEMO_DT, doc.name)

        synced.append({
            "name": doc.name,
            "sync": result,
            "state": state,
        })

    pending = get_my_pending_document_signature_requests(limit=50)
    health = phase26c_document_signature_request_health()

    return {
        "ok": True,
        "phase_fix": "26C-FIX2",
        "policy": policy,
        "repaired_names": repaired_names,
        "created_demo": created_demo,
        "synced": synced,
        "pending": pending,
        "health": health,
    }


# Phase 26C-FIX3: final repair for demo document naming and linked request references.
def _phase26c_fix3_table_exists(table_name: str) -> bool:
    try:
        frappe.db.sql(f"SELECT 1 FROM `{table_name}` LIMIT 1")
        return True
    except Exception:
        return False


def _phase26c_fix3_name_exists(doctype: str, name: str) -> bool:
    try:
        return bool(frappe.db.exists(doctype, name))
    except Exception:
        return False


def _phase26c_fix3_next_demo_name():
    year = str(frappe.utils.nowdate())[:4]
    stem = f"ISD-{year}-"

    rows = []
    try:
        rows = frappe.db.sql(
            f"""
            SELECT name
            FROM `tab{PHASE26C_DEMO_DT}`
            WHERE name LIKE %s
            ORDER BY name DESC
            LIMIT 1
            """,
            (stem + "%",),
            as_dict=True,
        )
    except Exception:
        rows = []

    if rows:
        try:
            n = int(str(rows[0].name).split("-")[-1]) + 1
        except Exception:
            n = 1
    else:
        n = 1

    while True:
        candidate = f"{stem}{n:05d}"
        if not _phase26c_fix3_name_exists(PHASE26C_DEMO_DT, candidate):
            return candidate
        n += 1


def _phase26c_fix3_repair_demo_autoname():
    if not frappe.db.exists("DocType", PHASE26C_DEMO_DT):
        return {
            "ok": False,
            "reason": f"{PHASE26C_DEMO_DT} does not exist.",
        }

    dt = frappe.get_doc("DocType", PHASE26C_DEMO_DT)
    old_autoname = dt.autoname

    if dt.autoname != "prompt":
        dt.autoname = "prompt"
        dt.save(ignore_permissions=True)
        frappe.db.commit()
        frappe.clear_cache(doctype=PHASE26C_DEMO_DT)

    return {
        "ok": True,
        "doctype": PHASE26C_DEMO_DT,
        "old_autoname": old_autoname,
        "new_autoname": "prompt",
    }


def _phase26c_fix3_repoint_signature_requests(old_name: str, new_name: str):
    changed = 0

    if frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        rows = frappe.get_all(
            PHASE26C_REQUEST_DT,
            filters={
                "reference_doctype": PHASE26C_DEMO_DT,
                "reference_name": old_name,
            },
            pluck="name",
            limit_page_length=500,
        )

        for r in rows:
            frappe.db.set_value(
                PHASE26C_REQUEST_DT,
                r,
                "reference_name",
                new_name,
                update_modified=False,
            )
            changed += 1

    try:
        rows = frappe.get_all(
            "ToDo",
            filters={
                "reference_type": PHASE26C_DEMO_DT,
                "reference_name": old_name,
            },
            pluck="name",
            limit_page_length=500,
        )
        for r in rows:
            frappe.db.set_value("ToDo", r, "reference_name", new_name, update_modified=False)
    except Exception:
        pass

    try:
        rows = frappe.get_all(
            "Notification Log",
            filters={
                "document_type": PHASE26C_DEMO_DT,
                "document_name": old_name,
            },
            pluck="name",
            limit_page_length=500,
        )
        for r in rows:
            frappe.db.set_value("Notification Log", r, "document_name", new_name, update_modified=False)
    except Exception:
        pass

    frappe.db.commit()

    return {
        "ok": True,
        "requests_repointed": changed,
        "old_name": old_name,
        "new_name": new_name,
    }


@frappe.whitelist()
def phase26c_fix3_repair_bad_demo_name():
    _phase26c_fix3_repair_demo_autoname()

    bad_name = "ISD-.YYYY.-.#####"
    new_name = None
    action = "not_needed"
    error = None

    if frappe.db.exists(PHASE26C_DEMO_DT, bad_name):
        new_name = _phase26c_fix3_next_demo_name()

        # First try Frappe rename properly for this version.
        try:
            frappe.rename_doc(
                PHASE26C_DEMO_DT,
                bad_name,
                new_name,
                force=True,
            )
            frappe.db.commit()
            action = "renamed_with_frappe"
        except Exception as exc:
            error = str(exc)

            # Safe DB-level fallback for custom demo doctype.
            table = f"tab{PHASE26C_DEMO_DT}"

            if _phase26c_fix3_table_exists(table):
                frappe.db.sql(
                    f"""
                    UPDATE `{table}`
                    SET name=%s
                    WHERE name=%s
                    """,
                    (new_name, bad_name),
                )

                # Fix child table parent references.
                child_table = f"tab{PHASE26C_AC_FOOTER_CHILD_DT}"
                if _phase26c_fix3_table_exists(child_table):
                    frappe.db.sql(
                        f"""
                        UPDATE `{child_table}`
                        SET parent=%s
                        WHERE parent=%s AND parenttype=%s
                        """,
                        (new_name, bad_name, PHASE26C_DEMO_DT),
                    )

                frappe.db.commit()
                action = "renamed_with_db_fallback"
            else:
                action = "rename_failed"

        if new_name:
            _phase26c_fix3_repoint_signature_requests(bad_name, new_name)

    return {
        "ok": True,
        "phase_fix": "26C-FIX3",
        "bad_name": bad_name,
        "new_name": new_name,
        "action": action,
        "error": error,
    }


@frappe.whitelist()
def create_internal_signature_demo_document():
    phase26c_install_document_signature_requests()
    _phase26c_fix3_repair_demo_autoname()
    _phase26c_ensure_demo_policy()

    doc = frappe.new_doc(PHASE26C_DEMO_DT)
    doc.name = _phase26c_fix3_next_demo_name()
    doc.title = "Phase 26C Ac Footer Signature Demo"
    doc.content = """
        <h2>Internal Signature Demo</h2>
        <p>This document is created to test Ac Footer internal signature workflow.</p>
        <p>The current user is inserted into Ac Footer as the first signer.</p>
    """

    _phase26c_add_current_user_to_demo_if_missing(doc)

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    sync = sync_ac_footer_requests(PHASE26C_DEMO_DT, doc.name)
    state = get_document_signature_state(PHASE26C_DEMO_DT, doc.name)

    return {
        "ok": True,
        "phase_fix": "26C-FIX3",
        "doctype": PHASE26C_DEMO_DT,
        "name": doc.name,
        "sync": sync,
        "state": state,
        "url": f"/app/{frappe.scrub(PHASE26C_DEMO_DT).replace('_', '-')}/{doc.name}",
    }


@frappe.whitelist()
def phase26c_fix3_finalize_demo_sync():
    autoname = _phase26c_fix3_repair_demo_autoname()
    rename = phase26c_fix3_repair_bad_demo_name()

    demos = frappe.get_all(
        PHASE26C_DEMO_DT,
        fields=["name"],
        order_by="creation asc",
        limit_page_length=50,
    )

    synced = []

    for d in demos:
        doc = frappe.get_doc(PHASE26C_DEMO_DT, d.name)

        _phase26c_add_current_user_to_demo_if_missing(doc)
        doc.save(ignore_permissions=True)
        frappe.db.commit()

        sync = sync_ac_footer_requests(PHASE26C_DEMO_DT, doc.name)
        state = get_document_signature_state(PHASE26C_DEMO_DT, doc.name)

        synced.append({
            "name": doc.name,
            "sync": sync,
            "state": state,
        })

    if not demos:
        created = create_internal_signature_demo_document()
    else:
        created = None

    pending = get_my_pending_document_signature_requests(limit=50)
    health = phase26c_document_signature_request_health()

    return {
        "ok": True,
        "phase_fix": "26C-FIX3",
        "autoname": autoname,
        "rename": rename,
        "synced": synced,
        "created_if_missing": created,
        "pending": pending,
        "health": health,
    }


# Phase 26D: Saved Signature / Direction / Reject actions.
import json as _phase26d_json
import hashlib as _phase26d_hashlib


def _phase26d_now():
    return str(now_datetime())


def _phase26d_request_ip():
    try:
        return frappe.local.request_ip or frappe.get_request_header("X-Forwarded-For") or ""
    except Exception:
        return ""


def _phase26d_user_agent():
    try:
        return frappe.get_request_header("User-Agent") or ""
    except Exception:
        return ""


def _phase26d_sha256(data) -> str:
    if not isinstance(data, str):
        data = _phase26d_json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    return _phase26d_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26d_require_login():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")


def _phase26d_is_admin_or_override():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])
    return bool(
        roles.intersection({
            "System Manager",
            "Internal Signature Administrator",
            "Internal Signature Manager",
            "Internal Signature Sequence Override",
        })
    )


def _phase26d_get_request(request_name: str):
    if not request_name:
        frappe.throw("request_name is required.")

    if not frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        frappe.throw("Document Signature Request DocType is not installed.")

    if not frappe.db.exists(PHASE26C_REQUEST_DT, request_name):
        frappe.throw(f"Document Signature Request not found: {request_name}")

    return frappe.get_doc(PHASE26C_REQUEST_DT, request_name)


def _phase26d_validate_actor(req, action: str):
    _phase26d_require_login()

    current_user = frappe.session.user
    is_override = _phase26d_is_admin_or_override()

    if req.requested_user != current_user and not is_override:
        frappe.throw("You are not the requested signer for this document.")

    if req.status in {"Signed", "Directed", "Rejected", "Cancelled"}:
        frappe.throw(f"This signature request has already been finalized ({req.status}).")

    caps = get_my_internal_signature_capabilities(reference_doctype=req.reference_doctype)

    effective = caps.get("effective_capabilities") or {}

    if action == "saved_signature" and not effective.get("can_use_saved_signature"):
        frappe.throw("You do not have permission to use saved signature.")

    if action == "direction":
        if not effective.get("can_draw_direction") and not effective.get("can_write_direction_text"):
            frappe.throw("You do not have permission to write or draw direction.")

    if action == "reject" and not effective.get("can_reject"):
        frappe.throw("You do not have permission to reject or return this request.")

    return {
        "current_user": current_user,
        "is_override": is_override,
        "capabilities": caps,
    }


def _phase26d_get_reference_doc(req):
    if not frappe.db.exists(req.reference_doctype, req.reference_name):
        frappe.throw(f"Reference document not found: {req.reference_doctype} {req.reference_name}")

    return frappe.get_doc(req.reference_doctype, req.reference_name)


def _phase26d_get_active_signature_profile(user: str):
    if not frappe.db.exists("DocType", PHASE26A_PROFILE_DT):
        frappe.throw("Employee Signature Profile DocType is not installed.")

    if not frappe.db.exists(PHASE26A_PROFILE_DT, user):
        frappe.throw("No saved signature profile found for this user.")

    profile = frappe.get_doc(PHASE26A_PROFILE_DT, user)

    if not int(profile.get("is_active") or 0):
        frappe.throw("Saved signature profile is inactive.")

    if not profile.get("signature_hash"):
        frappe.throw("Saved signature profile has no hash.")

    if not profile.get("signature_png"):
        frappe.throw("Saved signature profile has no private PNG signature.")

    if not int(profile.get("allow_stored_signature_apply") or 0):
        frappe.throw("Saved signature application is not allowed for this profile.")

    return profile


def _phase26d_close_todos(req):
    try:
        rows = frappe.get_all(
            "ToDo",
            filters={
                "allocated_to": req.requested_user,
                "reference_type": req.reference_doctype,
                "reference_name": req.reference_name,
                "status": "Open",
            },
            pluck="name",
            limit_page_length=50,
        )

        for name in rows:
            frappe.db.set_value("ToDo", name, "status", "Closed", update_modified=True)
    except Exception:
        pass


def _phase26d_update_ac_footer_row(req, status: str):
    try:
        if not req.ac_footer_row_name or str(req.ac_footer_row_name).startswith("text-"):
            return

        if not frappe.db.exists(PHASE26C_AC_FOOTER_CHILD_DT, req.ac_footer_row_name):
            return

        frappe.db.set_value(
            PHASE26C_AC_FOOTER_CHILD_DT,
            req.ac_footer_row_name,
            {
                "status": status,
                "signature_request": req.name,
            },
            update_modified=False,
        )
    except Exception:
        pass


def _phase26d_update_reference_signature_status(req):
    try:
        doc = frappe.get_doc(req.reference_doctype, req.reference_name)
        meta = frappe.get_meta(doc.doctype)

        if not meta.has_field("internal_signature_status"):
            return

        state = get_document_signature_state(req.reference_doctype, req.reference_name)
        counts = state.get("status_counts") or {}

        if state.get("complete"):
            status = "Completed"
        elif counts.get("Rejected"):
            status = "Rejected"
        elif counts.get("Pending"):
            status = "Pending Signature"
        elif counts.get("Waiting"):
            status = "Waiting"
        else:
            status = "Draft"

        frappe.db.set_value(doc.doctype, doc.name, "internal_signature_status", status, update_modified=False)
    except Exception:
        pass


def _phase26d_cancel_waiting_after_rejection(req):
    cancelled = []

    rows = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "reference_doctype": req.reference_doctype,
            "reference_name": req.reference_name,
            "status": ["in", ["Waiting", "Pending"]],
            "name": ["!=", req.name],
        },
        fields=["name", "sequence_order"],
        order_by="sequence_order asc",
        limit_page_length=500,
    )

    for r in rows:
        frappe.db.set_value(PHASE26C_REQUEST_DT, r.name, "status", "Cancelled", update_modified=True)
        cancelled.append(r.name)

    return cancelled


def _phase26d_finalize_request(req, status: str, payload: dict):
    ref_doc = _phase26d_get_reference_doc(req)

    try:
        doc_hash_after = _phase26c_hash_doc(ref_doc)
    except Exception:
        doc_hash_after = None

    req.status = status
    req.completed_at = now_datetime()
    req.signed_ip = _phase26d_request_ip()
    req.user_agent = _phase26d_user_agent()

    if doc_hash_after:
        req.doc_hash_after = doc_hash_after

    for k, v in (payload or {}).items():
        if k == "direction_svg":
            continue
        if hasattr(req, k):
            setattr(req, k, v)

    req.save(ignore_permissions=True)

    if payload and payload.get("direction_svg"):
        if globals().get("_phase26a_sanitize_svg"):
            direction_svg = _phase26a_sanitize_svg(payload.get("direction_svg"))
        else:
            direction_svg = payload.get("direction_svg")

        _phase26a_set_encrypted(PHASE26C_REQUEST_DT, req.name, "direction_svg_encrypted", direction_svg)

    _phase26d_update_ac_footer_row(req, status)
    _phase26d_close_todos(req)

    cancelled = []

    if status == "Rejected":
        cancelled = _phase26d_cancel_waiting_after_rejection(req)
    else:
        _phase26c_recalculate_sequence(req.reference_doctype, req.reference_name)

    _phase26d_update_reference_signature_status(req)

    frappe.db.commit()

    try:
        log_audit(
            "internal_document_signature.request_completed",
            {
                "request": req.name,
                "reference_doctype": req.reference_doctype,
                "reference_name": req.reference_name,
                "requested_user": req.requested_user,
                "status": status,
                "cancelled_after_rejection": cancelled,
                "signature_hash": getattr(req, "signature_hash", None),
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "request": req.name,
        "status": status,
        "reference_doctype": req.reference_doctype,
        "reference_name": req.reference_name,
        "cancelled_after_rejection": cancelled,
        "state": get_document_signature_state(req.reference_doctype, req.reference_name),
        "next_pending": get_my_pending_document_signature_requests(limit=50),
    }


@frappe.whitelist()
def get_document_signature_request_action_context(request_name: str):
    _phase26d_require_login()

    req = _phase26d_get_request(request_name)
    actor = _phase26d_validate_actor(req, "saved_signature") if req.status == "Pending" else {
        "current_user": frappe.session.user,
        "is_override": _phase26d_is_admin_or_override(),
        "capabilities": get_my_internal_signature_capabilities(reference_doctype=req.reference_doctype),
    }

    profile = None
    if frappe.db.exists("DocType", PHASE26A_PROFILE_DT) and frappe.db.exists(PHASE26A_PROFILE_DT, frappe.session.user):
        p = frappe.get_doc(PHASE26A_PROFILE_DT, frappe.session.user)
        profile = {
            "exists": True,
            "is_active": bool(p.get("is_active")),
            "signature_locked": bool(p.get("signature_locked")),
            "signature_hash": p.get("signature_hash"),
            "signature_public_id": p.get("signature_public_id"),
            "active_version": p.get("active_version"),
            "signature_png": p.get("signature_png"),
            "allow_stored_signature_apply": bool(p.get("allow_stored_signature_apply")),
            "allow_direction_drawing": bool(p.get("allow_direction_drawing")),
        }
    else:
        profile = {"exists": False}

    request = {
        "name": req.name,
        "reference_doctype": req.reference_doctype,
        "reference_name": req.reference_name,
        "reference_title": req.reference_title,
        "requested_user": req.requested_user,
        "requested_employee": req.requested_employee,
        "full_name": req.full_name,
        "designation": req.designation,
        "department": req.department,
        "sequence_order": req.sequence_order,
        "workflow_mode": req.workflow_mode,
        "action_required": req.action_required,
        "status": req.status,
        "can_use_saved_signature": bool(req.can_use_saved_signature),
        "can_draw_direction": bool(req.can_draw_direction),
        "can_write_direction_text": bool(req.can_write_direction_text),
        "can_reject": bool(req.can_reject),
        "signature_hash": req.signature_hash,
        "completed_at": str(req.completed_at or ""),
    }

    effective = actor.get("capabilities", {}).get("effective_capabilities", {})

    allowed_actions = {
        "saved_signature": bool(
            req.status == "Pending"
            and req.can_use_saved_signature
            and effective.get("can_use_saved_signature")
            and profile.get("exists")
            and profile.get("is_active")
        ),
        "direction": bool(
            req.status == "Pending"
            and (req.can_draw_direction or req.can_write_direction_text)
            and (effective.get("can_draw_direction") or effective.get("can_write_direction_text"))
        ),
        "reject": bool(
            req.status == "Pending"
            and req.can_reject
            and effective.get("can_reject")
        ),
    }

    return {
        "ok": True,
        "request": request,
        "profile": profile,
        "actor": actor,
        "allowed_actions": allowed_actions,
        "document_state": get_document_signature_state(req.reference_doctype, req.reference_name),
        "document_url": f"/app/{frappe.scrub(req.reference_doctype).replace('_', '-')}/{req.reference_name}",
    }


@frappe.whitelist()
def apply_saved_signature_request(request_name: str):
    req = _phase26d_get_request(request_name)
    actor = _phase26d_validate_actor(req, "saved_signature")

    if not int(req.can_use_saved_signature or 0):
        frappe.throw("This request does not allow saved signature.")

    signer_user = req.requested_user
    if actor.get("is_override") and (not signer_user or not frappe.db.exists(PHASE26A_PROFILE_DT, signer_user)):
        signer_user = frappe.session.user
    profile = _phase26d_get_active_signature_profile(signer_user)

    if not int(profile.get("allow_stored_signature_apply") or 0):
        frappe.throw("This profile is not allowed to apply saved signature.")

    payload = {
        "signature_profile": profile.name,
        "signature_hash": profile.signature_hash,
        "signature_png": profile.signature_png,
        "direction_text": req.direction_text,
    }

    result = _phase26d_finalize_request(req, "Signed", payload)

    result["applied_signature"] = {
        "signature_profile": profile.name,
        "signature_hash": profile.signature_hash,
        "signature_png": profile.signature_png,
        "signature_public_id": profile.signature_public_id,
    }

    return result


@frappe.whitelist()
def apply_direction_signature_request(request_name: str, direction_text: str = None, direction_svg: str = None):
    req = _phase26d_get_request(request_name)
    actor = _phase26d_validate_actor(req, "direction")

    if not int(req.can_draw_direction or 0) and not int(req.can_write_direction_text or 0):
        frappe.throw("This request does not allow direction.")

    direction_text = (direction_text or "").strip()
    direction_svg = (direction_svg or "").strip()

    if not direction_text and not direction_svg:
        frappe.throw("Direction text or drawing is required.")

    direction_hash = _phase26d_sha256({
        "request": req.name,
        "user": frappe.session.user,
        "direction_text": direction_text,
        "direction_svg_sha256": _phase26d_sha256(direction_svg) if direction_svg else None,
        "at": _phase26d_now(),
    })

    profile = None
    signature_png = None

    if frappe.db.exists("DocType", PHASE26A_PROFILE_DT) and frappe.db.exists(PHASE26A_PROFILE_DT, req.requested_user):
        profile = frappe.get_doc(PHASE26A_PROFILE_DT, req.requested_user)
        signature_png = profile.get("signature_png")

    payload = {
        "signature_profile": profile.name if profile else None,
        "signature_hash": direction_hash,
        "signature_png": signature_png,
        "direction_text": direction_text,
        "direction_svg": direction_svg,
    }

    result = _phase26d_finalize_request(req, "Directed", payload)
    result["direction_hash"] = direction_hash

    return result


@frappe.whitelist()
def reject_document_signature_request(request_name: str, reason: str = None):
    req = _phase26d_get_request(request_name)
    actor = _phase26d_validate_actor(req, "reject")

    reason = (reason or "").strip()
    if not reason:
        frappe.throw("Reject / return reason is required.")

    rejection_hash = _phase26d_sha256({
        "request": req.name,
        "user": frappe.session.user,
        "reason": reason,
        "at": _phase26d_now(),
    })

    payload = {
        "direction_text": f"Rejected / Returned: {reason}",
        "signature_hash": rejection_hash,
    }

    result = _phase26d_finalize_request(req, "Rejected", payload)
    result["rejection_hash"] = rejection_hash

    return result


@frappe.whitelist()
def get_my_pending_document_signature_requests(limit: int = 50):
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")

    if not frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        return {"ok": True, "count": 0, "items": []}

    rows = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "requested_user": frappe.session.user,
            "status": "Pending",
        },
        fields=[
            "name",
            "reference_doctype",
            "reference_name",
            "reference_title",
            "requested_employee",
            "full_name",
            "sequence_order",
            "workflow_mode",
            "action_required",
            "status",
            "can_use_saved_signature",
            "can_draw_direction",
            "can_write_direction_text",
            "can_reject",
            "requested_at",
            "activated_at",
        ],
        order_by="activated_at desc, requested_at desc",
        limit_page_length=int(limit or 50),
    )

    for r in rows:
        r["action_url"] = f"/document-sign-action?request={r.name}"
        r["document_url"] = f"/app/{frappe.scrub(r.reference_doctype).replace('_', '-')}/{r.reference_name}"

    return {
        "ok": True,
        "user": frappe.session.user,
        "count": len(rows),
        "items": rows,
    }


@frappe.whitelist()
def phase26d_action_health():
    pending = get_my_pending_document_signature_requests(limit=20)

    first_context = None
    if pending.get("items"):
        try:
            first_context = get_document_signature_request_action_context(pending["items"][0]["name"])
        except Exception as exc:
            first_context = {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "phase": "26D",
        "pending_count": pending.get("count"),
        "pending": pending,
        "first_context": first_context,
        "page": "/document-sign-action?request=<request_name>",
        "ready": bool(frappe.db.exists("DocType", PHASE26C_REQUEST_DT)),
    }


# Phase 26E: Desk Form Buttons Integration for any DocType with Ac Footer.
def _phase26e_require_login():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")


def _phase26e_has_ac_footer(reference_doctype: str):
    try:
        meta = frappe.get_meta(reference_doctype)
        if meta.has_field("ac_footer"):
            return {
                "has_ac_footer": True,
                "fieldname": "ac_footer",
                "source": "meta_fieldname",
            }

        for df in meta.fields:
            if (df.label or "").strip().lower() == "ac footer":
                return {
                    "has_ac_footer": True,
                    "fieldname": df.fieldname,
                    "source": "meta_label",
                }

    except Exception:
        pass

    return {
        "has_ac_footer": False,
        "fieldname": None,
        "source": None,
    }


def _phase26e_request_allowed_actions(row, caps, profile):
    effective = (caps or {}).get("effective_capabilities") or {}

    return {
        "saved_signature": bool(
            row.get("status") == "Pending"
            and int(row.get("can_use_saved_signature") or 0)
            and effective.get("can_use_saved_signature")
            and profile.get("exists")
            and profile.get("is_active")
        ),
        "direction": bool(
            row.get("status") == "Pending"
            and (int(row.get("can_draw_direction") or 0) or int(row.get("can_write_direction_text") or 0))
            and (effective.get("can_draw_direction") or effective.get("can_write_direction_text"))
        ),
        "reject": bool(
            row.get("status") == "Pending"
            and int(row.get("can_reject") or 0)
            and effective.get("can_reject")
        ),
    }


@frappe.whitelist()
def get_document_signature_form_context(reference_doctype: str, reference_name: str, auto_sync: int = 0):
    _phase26e_require_login()

    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    if not frappe.db.exists(reference_doctype, reference_name):
        frappe.throw(f"Document not found: {reference_doctype} {reference_name}")

    ac_footer = _phase26e_has_ac_footer(reference_doctype)

    sync_result = None
    if int(auto_sync or 0) and ac_footer.get("has_ac_footer"):
        try:
            sync_result = sync_ac_footer_requests(reference_doctype, reference_name)
        except Exception as exc:
            sync_result = {
                "ok": False,
                "error": str(exc),
            }

    state = get_document_signature_state(reference_doctype, reference_name)

    caps = get_my_internal_signature_capabilities(reference_doctype=reference_doctype)

    profile = caps.get("profile") or {"exists": False}

    is_admin = _phase26d_is_admin_or_override()

    all_requests = []
    if frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        all_requests = frappe.get_all(
            PHASE26C_REQUEST_DT,
            filters={
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "status": ["!=", "Cancelled"],
            },
            fields=[
                "name",
                "reference_doctype",
                "reference_name",
                "reference_title",
                "requested_user",
                "requested_employee",
                "full_name",
                "designation",
                "department",
                "sequence_order",
                "workflow_mode",
                "action_required",
                "status",
                "can_use_saved_signature",
                "can_draw_direction",
                "can_write_direction_text",
                "can_reject",
                "signature_hash",
                "completed_at",
                "source",
            ],
            order_by="sequence_order asc, creation asc",
            limit_page_length=50,
        )

    complete = bool(all_requests) and all(r.status in {"Signed", "Directed", "Rejected"} for r in all_requests)

    signable_requests = []
    for r in all_requests:
        if r.status in {"Signed", "Directed", "Rejected"}:
            continue
        if is_admin or r.requested_user == frappe.session.user:
            signable_requests.append(r)
        else:
            try:
                if frappe.db.exists("DocType", "Signature Delegation Rule"):
                    delegated = frappe.db.exists(
                        "Signature Delegation Rule",
                        {
                            "delegator_user": r.requested_user,
                            "delegate_user": frappe.session.user,
                            "is_active": 1,
                        },
                    )
                    if delegated:
                        signable_requests.append(r)
            except Exception:
                pass

    for row in signable_requests:
        row["action_url"] = f"/document-sign-action?request={row.name}"
        row["allowed_actions"] = {
            "saved_signature": bool(profile.get("signature_png") or is_admin),
            "direction": True,
            "reject": True,
        }

    first_pending = signable_requests[0] if signable_requests else None

    return {
        "ok": True,
        "phase": "26E",
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "ac_footer": ac_footer,
        "sync_result": sync_result,
        "state": state,
        "capabilities": caps,
        "profile": profile,
        "my_pending_count": len(signable_requests),
        "my_pending_requests": signable_requests,
        "first_pending": first_pending,
        "has_action": bool(first_pending) and not complete,
        "can_sign": bool(signable_requests) and not complete,
        "complete": complete,
        "is_admin": is_admin,
    }


@frappe.whitelist()
def apply_document_signature_unified(
    reference_doctype: str,
    reference_name: str,
    request_name: str = None,
    signature_type: str = "saved",
    direction_text: str = None,
    direction_svg: str = None,
    attach_saved_signature: int = 1,
    reason: str = None,
):
    _phase26d_require_login()
    is_admin = _phase26d_is_admin_or_override()

    if not request_name:
        candidates = frappe.get_all(
            PHASE26C_REQUEST_DT,
            filters={
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "status": ["not in", ["Signed", "Directed", "Rejected", "Cancelled"]],
            },
            fields=["name", "requested_user", "status"],
            order_by="sequence_order asc, creation asc",
        )
        for c in candidates:
            if c.requested_user == frappe.session.user:
                request_name = c.name
                break
        if not request_name and is_admin and candidates:
            request_name = candidates[0].name

    if not request_name:
        frappe.throw("No pending signature request found for this document.")

    req = frappe.get_doc(PHASE26C_REQUEST_DT, request_name)

    if not is_admin and req.requested_user != frappe.session.user:
        delegated = False
        try:
            if frappe.db.exists("DocType", "Signature Delegation Rule"):
                delegated = bool(frappe.db.exists(
                    "Signature Delegation Rule",
                    {
                        "delegator_user": req.requested_user,
                        "delegate_user": frappe.session.user,
                        "is_active": 1,
                    },
                ))
        except Exception:
            pass
        if not delegated:
            frappe.throw("You are not authorized to sign for this request.")

    if signature_type == "saved":
        profile_user = req.requested_user if not is_admin else frappe.session.user
        profile_doc = None
        if frappe.db.exists(PHASE26A_PROFILE_DT, profile_user):
            profile_doc = frappe.get_doc(PHASE26A_PROFILE_DT, profile_user)
        elif frappe.db.exists(PHASE26A_PROFILE_DT, frappe.session.user):
            profile_doc = frappe.get_doc(PHASE26A_PROFILE_DT, frappe.session.user)

        if not profile_doc or not profile_doc.get("signature_png"):
            frappe.throw("No saved signature found for this user. Please register your signature first.")

        return apply_saved_signature_request(req.name)

    elif signature_type == "direction":
        direction_text = (direction_text or "").strip()
        direction_svg = (direction_svg or "").strip()

        if not direction_text and not direction_svg:
            frappe.throw("Please draw a direction or type a guidance note.")

        direction_hash = _phase26d_sha256({
            "request": req.name,
            "user": frappe.session.user,
            "direction_text": direction_text,
            "direction_svg_sha256": _phase26d_sha256(direction_svg) if direction_svg else None,
            "at": _phase26d_now(),
        })

        signature_png = None
        profile_name = None
        # Live direction/signature invokes and attaches the pre-saved profile signature without modifying the profile itself
        if attach_saved_signature is None or str(attach_saved_signature).strip().lower() not in ("0", "false"):
            profile_user = req.requested_user if not is_admin else frappe.session.user
            if frappe.db.exists(PHASE26A_PROFILE_DT, profile_user):
                p = frappe.get_doc(PHASE26A_PROFILE_DT, profile_user)
                signature_png = p.get("signature_png")
                profile_name = p.name
            elif frappe.db.exists(PHASE26A_PROFILE_DT, frappe.session.user):
                p = frappe.get_doc(PHASE26A_PROFILE_DT, frappe.session.user)
                signature_png = p.get("signature_png")
                profile_name = p.name

        payload = {
            "signature_profile": profile_name,
            "signature_hash": direction_hash,
            "signature_png": signature_png,
            "direction_text": direction_text,
            "direction_svg": direction_svg,
        }

        result = _phase26d_finalize_request(req, "Directed", payload)
        result["direction_hash"] = direction_hash
        return result

    elif signature_type == "reject":
        reason = (reason or "").strip()
        if not reason:
            frappe.throw("Reject reason is required.")
        return reject_document_signature_request(req.name, reason)

    else:
        frappe.throw(f"Unknown signature type: {signature_type}")


@frappe.whitelist()
def apply_first_pending_saved_signature_for_document(reference_doctype: str, reference_name: str):
    _phase26e_require_login()

    ctx = get_document_signature_form_context(reference_doctype, reference_name, auto_sync=0)
    first = ctx.get("first_pending")

    if not first:
        frappe.throw("No pending signature request for current user on this document.")

    allowed = first.get("allowed_actions") or {}

    if not allowed.get("saved_signature"):
        frappe.throw("Saved signature action is not allowed for this request.")

    return apply_saved_signature_request(first.get("name"))


@frappe.whitelist()
def reject_first_pending_signature_for_document(reference_doctype: str, reference_name: str, reason: str):
    _phase26e_require_login()

    reason = (reason or "").strip()
    if not reason:
        frappe.throw("Reason is required.")

    ctx = get_document_signature_form_context(reference_doctype, reference_name, auto_sync=0)
    first = ctx.get("first_pending")

    if not first:
        frappe.throw("No pending signature request for current user on this document.")

    allowed = first.get("allowed_actions") or {}

    if not allowed.get("reject"):
        frappe.throw("Reject action is not allowed for this request.")

    return reject_document_signature_request(first.get("name"), reason)


@frappe.whitelist()
def phase26e_form_integration_health():
    js_expected = "/assets/surhan_signature/js/internal_document_signature.js"

    hooks_ok = False
    try:
        hooks = frappe.get_hooks("app_include_js") or []
        if isinstance(hooks, str):
            hooks = [hooks]
        hooks_ok = js_expected in hooks or any("internal_document_signature.js" in str(x) for x in hooks)
    except Exception:
        hooks_ok = False

    demo_context = None
    try:
        if frappe.db.exists(PHASE26C_DEMO_DT, "ISD-2026-00001"):
            demo_context = get_document_signature_form_context(PHASE26C_DEMO_DT, "ISD-2026-00001", auto_sync=0)
    except Exception as exc:
        demo_context = {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "phase": "26E",
        "desk_js": js_expected,
        "hooks_include_js": hooks_ok,
        "document_signature_request_doctype": bool(frappe.db.exists("DocType", PHASE26C_REQUEST_DT)),
        "demo_context": demo_context,
        "ready": bool(hooks_ok and frappe.db.exists("DocType", PHASE26C_REQUEST_DT)),
    }


# Phase 26E-FIX1: reliable per-DocType Client Script for Desk buttons.
import json as _phase26e_fix1_json


def _phase26e_fix1_json_dumps(value):
    return _phase26e_fix1_json.dumps(value, ensure_ascii=False)


def _phase26e_fix1_client_script_code(reference_doctype: str) -> str:
    doctype_json = _phase26e_fix1_json_dumps(reference_doctype)

    code = r'''
// Surhan Signature Phase 26E-FIX1
// Reliable Desk buttons for internal document signature workflow.

frappe.ui.form.on(__DOCTYPE_JSON__, {
  refresh: function(frm) {
    surhan_signature_phase26e_fix1_load(frm);
  }
});

function surhan_signature_phase26e_fix1_show_json(title, data) {
  const d = new frappe.ui.Dialog({
    title: title,
    size: "large",
    fields: [
      {
        fieldtype: "Code",
        fieldname: "json",
        label: __("Result"),
        options: "JSON",
        read_only: 1
      }
    ],
    primary_action_label: __("Close"),
    primary_action: function() {
      d.hide();
    }
  });

  d.set_value("json", JSON.stringify(data || {}, null, 2));
  d.show();
}

function surhan_signature_phase26e_fix1_call(method, args, callback) {
  frappe.call({
    method: method,
    args: args || {},
    freeze: true,
    freeze_message: __("Checking internal signature..."),
    callback: function(r) {
      callback && callback(r.message || r);
    },
    error: function(r) {
      console.error("Surhan Signature error", r);
    }
  });
}

function surhan_signature_phase26e_fix1_add_indicator(frm, ctx) {
  if (!frm.dashboard || !ctx || !ctx.state) return;

  const state = ctx.state || {};
  const counts = state.status_counts || {};

  if ((ctx.my_pending_count || 0) > 0) {
    frm.dashboard.add_indicator(
      __("Internal Signature Pending: {0}", [ctx.my_pending_count]),
      "orange"
    );
  } else if (state.complete) {
    frm.dashboard.add_indicator(__("Internal Signature Completed"), "green");
  } else if ((state.count || 0) > 0) {
    frm.dashboard.add_indicator(
      __("Internal Signature: {0} request(s)", [state.count]),
      counts.Rejected ? "red" : "blue"
    );
  }
}

function surhan_signature_phase26e_fix1_add_buttons(frm, ctx) {
  const GROUP = __("Internal Signature");

  frm.add_custom_button(__("Sync Ac Footer"), function() {
    surhan_signature_phase26e_fix1_call(
      "surhan_signature.api.sync_ac_footer_requests",
      {
        reference_doctype: frm.doc.doctype,
        reference_name: frm.doc.name
      },
      function(data) {
        surhan_signature_phase26e_fix1_show_json(__("Ac Footer Sync Result"), data);
        frm.reload_doc();
      }
    );
  }, GROUP);

  frm.add_custom_button(__("Signature State"), function() {
    surhan_signature_phase26e_fix1_call(
      "surhan_signature.api.get_document_signature_form_context",
      {
        reference_doctype: frm.doc.doctype,
        reference_name: frm.doc.name,
        auto_sync: 0
      },
      function(data) {
        surhan_signature_phase26e_fix1_show_json(__("Signature State"), data);
      }
    );
  }, GROUP);

  const first = ctx.first_pending;

  if (!first) {
    if (ctx.complete) {
      frm.add_custom_button(__("View Completed Signature State"), function() {
        surhan_signature_phase26e_fix1_show_json(__("Completed Signature State"), ctx);
      }, GROUP);
    }

    return;
  }

  const actions = first.allowed_actions || {};

  frm.add_custom_button(__("Open Signature Action"), function() {
    window.open(first.action_url, "_blank");
  }, GROUP);

  if (actions.saved_signature) {
    frm.add_custom_button(__("اعتماد بالتوقيع المحفوظ"), function() {
      frappe.confirm(
        __("Apply your saved signature to this document?"),
        function() {
          surhan_signature_phase26e_fix1_call(
            "surhan_signature.api.apply_first_pending_saved_signature_for_document",
            {
              reference_doctype: frm.doc.doctype,
              reference_name: frm.doc.name
            },
            function(data) {
              frappe.show_alert({
                message: __("Saved signature applied successfully."),
                indicator: "green"
              });
              surhan_signature_phase26e_fix1_show_json(__("Saved Signature Result"), data);
              frm.reload_doc();
            }
          );
        }
      );
    }, GROUP);
  }

  if (actions.direction) {
    frm.add_custom_button(__("توجيه ورسم مباشر"), function() {
      window.open(first.action_url, "_blank");
    }, GROUP);
  }

  if (actions.reject) {
    frm.add_custom_button(__("رفض / إرجاع"), function() {
      frappe.prompt(
        [
          {
            fieldname: "reason",
            label: __("Reason"),
            fieldtype: "Small Text",
            reqd: 1
          }
        ],
        function(values) {
          surhan_signature_phase26e_fix1_call(
            "surhan_signature.api.reject_first_pending_signature_for_document",
            {
              reference_doctype: frm.doc.doctype,
              reference_name: frm.doc.name,
              reason: values.reason
            },
            function(data) {
              frappe.show_alert({
                message: __("Signature request rejected / returned."),
                indicator: "red"
              });
              surhan_signature_phase26e_fix1_show_json(__("Reject Result"), data);
              frm.reload_doc();
            }
          );
        },
        __("Reject / Return Signature Request"),
        __("Reject / Return")
      );
    }, GROUP);
  }
}

function surhan_signature_phase26e_fix1_load(frm) {
  if (!frm || !frm.doc || frm.is_new()) return;

  // Reset is intentional; Frappe clears custom buttons on refresh.
  frm.__surhan_signature_phase26e_fix1_loaded_at = Date.now();
  const token = frm.__surhan_signature_phase26e_fix1_loaded_at;

  surhan_signature_phase26e_fix1_call(
    "surhan_signature.api.get_document_signature_form_context",
    {
      reference_doctype: frm.doc.doctype,
      reference_name: frm.doc.name,
      auto_sync: 0
    },
    function(ctx) {
      if (frm.__surhan_signature_phase26e_fix1_loaded_at !== token) return;
      if (!ctx || !ctx.ok) return;

      frm.__surhan_signature_context = ctx;

      surhan_signature_phase26e_fix1_add_indicator(frm, ctx);
      surhan_signature_phase26e_fix1_add_buttons(frm, ctx);
    }
  );
}
'''
    return code.replace("__DOCTYPE_JSON__", doctype_json)


@frappe.whitelist()
def install_internal_signature_client_script(reference_doctype: str):
    if not globals().get("_phase26b_is_admin") or not _phase26b_is_admin():
        frappe.throw("Only Internal Signature Administrator can install signature client scripts.")

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    if not frappe.db.exists("DocType", "Client Script"):
        frappe.throw("Client Script DocType is not available.")

    script_code = _phase26e_fix1_client_script_code(reference_doctype)
    script_name = f"Surhan Internal Signature Buttons - {reference_doctype}"

    existing = frappe.db.exists("Client Script", script_name)

    if existing:
        doc = frappe.get_doc("Client Script", existing)
        action = "updated"
    else:
        doc = frappe.new_doc("Client Script")
        doc.name = script_name
        action = "created"

    doc.dt = reference_doctype
    doc.script = script_code
    doc.enabled = 1

    meta = frappe.get_meta("Client Script")
    if meta.has_field("view"):
        doc.view = "Form"

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache(doctype=reference_doctype)

    return {
        "ok": True,
        "phase_fix": "26E-FIX1",
        "action": action,
        "client_script": doc.name,
        "reference_doctype": reference_doctype,
        "enabled": bool(doc.enabled),
    }


@frappe.whitelist()
def install_internal_signature_client_scripts_for_policies():
    if not globals().get("_phase26b_is_admin") or not _phase26b_is_admin():
        frappe.throw("Only Internal Signature Administrator can install signature client scripts.")

    doctypes = set()

    # Always install for demo.
    if "PHASE26C_DEMO_DT" in globals() and frappe.db.exists("DocType", PHASE26C_DEMO_DT):
        doctypes.add(PHASE26C_DEMO_DT)

    # Install for policies.
    if frappe.db.exists("DocType", "Internal Signature Policy"):
        for r in frappe.get_all(
            "Internal Signature Policy",
            filters={"is_active": 1},
            fields=["reference_doctype"],
            limit_page_length=500,
        ):
            if r.reference_doctype and frappe.db.exists("DocType", r.reference_doctype):
                doctypes.add(r.reference_doctype)

    # Install for discovered Ac Footer doctypes.
    try:
        discovered = discover_ac_footer_doctypes(limit=500)
        for item in discovered.get("items") or []:
            dt = item.get("doctype")
            if dt and frappe.db.exists("DocType", dt):
                doctypes.add(dt)
    except Exception:
        pass

    results = []
    for dt in sorted(doctypes):
        results.append(install_internal_signature_client_script(dt))

    return {
        "ok": True,
        "phase_fix": "26E-FIX1",
        "count": len(results),
        "results": results,
    }


@frappe.whitelist()
def phase26e_fix1_client_script_health(reference_doctype: str = None):
    reference_doctype = reference_doctype or PHASE26C_DEMO_DT

    exists = None
    enabled = False

    if frappe.db.exists("DocType", "Client Script"):
        script_name = f"Surhan Internal Signature Buttons - {reference_doctype}"
        exists = frappe.db.exists("Client Script", script_name)
        if exists:
            enabled = bool(frappe.db.get_value("Client Script", exists, "enabled"))

    context = None
    try:
        if reference_doctype == PHASE26C_DEMO_DT and frappe.db.exists(PHASE26C_DEMO_DT, "ISD-2026-00001"):
            context = get_document_signature_form_context(reference_doctype, "ISD-2026-00001", auto_sync=0)
    except Exception as exc:
        context = {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "phase_fix": "26E-FIX1",
        "reference_doctype": reference_doctype,
        "client_script_exists": bool(exists),
        "client_script_name": exists,
        "enabled": enabled,
        "context": context,
        "ready": bool(exists and enabled),
    }


# Phase 26F: Signed Print Renderer.
import json as _phase26f_json
import hashlib as _phase26f_hashlib


def _phase26f_json_dumps(data) -> str:
    return _phase26f_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _phase26f_sha256(data) -> str:
    if not isinstance(data, str):
        data = _phase26f_json_dumps(data)
    return _phase26f_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26f_require_login():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")


def _phase26f_doc_url(reference_doctype, reference_name):
    return f"/app/{frappe.scrub(reference_doctype).replace('_', '-')}/{reference_name}"


def _phase26f_read_direction_svg(request_name):
    try:
        if globals().get("_phase26a_get_encrypted"):
            return _phase26a_get_encrypted(PHASE26C_REQUEST_DT, request_name, "direction_svg_encrypted")
    except Exception:
        pass
    return ""


def _phase26f_get_document_payload(doc):
    meta = frappe.get_meta(doc.doctype)

    title = None
    try:
        title = doc.get_title()
    except Exception:
        title = doc.get("title") or doc.get("subject") or doc.name

    fields = []
    content_html = None

    skip_fieldtypes = {
        "Section Break",
        "Column Break",
        "Tab Break",
        "HTML",
        "Button",
        "Table",
        "Fold",
    }

    skip_fieldnames = {
        "amended_from",
        "naming_series",
        "idx",
        "docstatus",
    }

    for df in meta.fields:
        if not df.fieldname:
            continue

        if df.fieldtype in skip_fieldtypes:
            continue

        if df.fieldname in skip_fieldnames:
            continue

        if df.fieldname == "ac_footer":
            continue

        try:
            value = doc.get(df.fieldname)
        except Exception:
            value = None

        if value in [None, ""]:
            continue

        label = df.label or df.fieldname

        if df.fieldtype == "Text Editor" or df.fieldname in {"content", "description"}:
            if not content_html:
                content_html = str(value or "")
            continue

        if isinstance(value, (dict, list)):
            value = _phase26f_json_dumps(value)

        fields.append({
            "label": label,
            "fieldname": df.fieldname,
            "fieldtype": df.fieldtype,
            "value": str(value),
        })

    if not content_html:
        content_html = ""

    return {
        "doctype": doc.doctype,
        "name": doc.name,
        "title": title,
        "content_html": content_html,
        "fields": fields,
        "document_url": _phase26f_doc_url(doc.doctype, doc.name),
    }


def _phase26f_request_payload(reference_doctype, reference_name):
    rows = []

    if not frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        return rows

    requests = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
        },
        fields=[
            "name",
            "requested_user",
            "requested_employee",
            "full_name",
            "designation",
            "department",
            "sequence_order",
            "workflow_mode",
            "action_required",
            "status",
            "signature_profile",
            "signature_hash",
            "signature_png",
            "direction_text",
            "completed_at",
            "requested_at",
            "activated_at",
            "source",
            "signed_ip",
            "doc_hash_before",
            "doc_hash_after",
        ],
        order_by="sequence_order asc, creation asc",
        limit_page_length=500,
    )

    for r in requests:
        direction_svg = ""
        if r.status in {"Directed", "Rejected", "Signed"}:
            direction_svg = _phase26f_read_direction_svg(r.name)

        rows.append({
            "name": r.name,
            "requested_user": r.requested_user,
            "requested_employee": r.requested_employee,
            "full_name": r.full_name,
            "designation": r.designation,
            "department": r.department,
            "sequence_order": r.sequence_order,
            "workflow_mode": r.workflow_mode,
            "action_required": r.action_required,
            "status": r.status,
            "signature_profile": r.signature_profile,
            "signature_hash": r.signature_hash,
            "signature_png": r.signature_png,
            "direction_text": r.direction_text,
            "direction_svg": direction_svg,
            "completed_at": str(r.completed_at or ""),
            "requested_at": str(r.requested_at or ""),
            "activated_at": str(r.activated_at or ""),
            "source": r.source,
            "signed_ip": r.signed_ip,
            "doc_hash_before": r.doc_hash_before,
            "doc_hash_after": r.doc_hash_after,
            "is_completed": r.status in {"Signed", "Directed", "Rejected"},
            "is_signed": r.status == "Signed",
            "is_directed": r.status == "Directed",
            "is_rejected": r.status == "Rejected",
        })

    return rows


@frappe.whitelist()
def get_signed_document_print_context(reference_doctype: str, reference_name: str):
    _phase26f_require_login()

    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    if not frappe.db.exists(reference_doctype, reference_name):
        frappe.throw(f"Document not found: {reference_doctype} {reference_name}")

    doc = frappe.get_doc(reference_doctype, reference_name)
    document = _phase26f_get_document_payload(doc)
    requests = _phase26f_request_payload(reference_doctype, reference_name)

    status_counts = {}
    for r in requests:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

    directions = [
        r for r in requests
        if r.get("direction_text") or r.get("direction_svg") or r.get("is_rejected")
    ]

    signatures = [
        r for r in requests
        if r.get("is_completed") and (r.get("signature_png") or r.get("signature_hash") or r.get("direction_text"))
    ]

    complete = bool(requests) and all(
        r["status"] in {"Signed", "Directed", "Rejected", "Cancelled"}
        for r in requests
    )

    print_payload = {
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "document": document,
        "requests": requests,
        "status_counts": status_counts,
        "directions": directions,
        "signatures": signatures,
        "complete": complete,
    }

    print_hash = _phase26f_sha256(print_payload)

    return {
        "ok": True,
        "phase": "26F",
        "generated_at": str(now_datetime()),
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "document": document,
        "requests": requests,
        "status_counts": status_counts,
        "directions": directions,
        "signatures": signatures,
        "complete": complete,
        "print_hash": print_hash,
        "document_url": document.get("document_url"),
        "print_url": f"/signed-print?doctype={frappe.utils.quote(reference_doctype)}&name={frappe.utils.quote(reference_name)}",
    }


@frappe.whitelist()
def phase26f_signed_print_health(reference_doctype: str = None, reference_name: str = None):
    reference_doctype = reference_doctype or "Internal Signature Demo Document"
    reference_name = reference_name or "ISD-2026-00002"

    context = None

    try:
        if frappe.db.exists(reference_doctype, reference_name):
            context = get_signed_document_print_context(reference_doctype, reference_name)
        else:
            context = {
                "ok": False,
                "reason": f"Document not found: {reference_doctype} {reference_name}",
            }
    except Exception as exc:
        context = {
            "ok": False,
            "error": str(exc),
        }

    return {
        "ok": True,
        "phase": "26F",
        "page": "/signed-print?doctype=<DocType>&name=<Name>",
        "context_ok": bool(context and context.get("ok")),
        "context": context,
        "ready": bool(frappe.db.exists("DocType", PHASE26C_REQUEST_DT)),
    }


def _phase26f_print_client_script_code(reference_doctype: str) -> str:
    import json
    doctype_json = json.dumps(reference_doctype)

    return f"""
// Surhan Signature Phase 26F - Signed Print View Button
frappe.ui.form.on({doctype_json}, {{
  refresh: function(frm) {{
    if (!frm || !frm.doc || frm.is_new()) return;

    frm.add_custom_button(__('Signed Print View'), function() {{
      const url = '/signed-print?doctype=' + encodeURIComponent(frm.doc.doctype) + '&name=' + encodeURIComponent(frm.doc.name);
      window.open(url, '_blank');
    }}, __('Internal Signature'));
  }}
}});
"""


@frappe.whitelist()
def install_signed_print_client_script(reference_doctype: str):
    if not globals().get("_phase26b_is_admin") or not _phase26b_is_admin():
        frappe.throw("Only Internal Signature Administrator can install signed print client scripts.")

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    if not frappe.db.exists("DocType", "Client Script"):
        frappe.throw("Client Script DocType is not available.")

    script_name = f"Surhan Signed Print View - {reference_doctype}"
    script_code = _phase26f_print_client_script_code(reference_doctype)

    existing = frappe.db.exists("Client Script", script_name)

    if existing:
        doc = frappe.get_doc("Client Script", existing)
        action = "updated"
    else:
        doc = frappe.new_doc("Client Script")
        doc.name = script_name
        action = "created"

    doc.dt = reference_doctype
    doc.script = script_code
    doc.enabled = 1

    meta = frappe.get_meta("Client Script")
    if meta.has_field("view"):
        doc.view = "Form"

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache(doctype=reference_doctype)

    return {
        "ok": True,
        "phase": "26F",
        "action": action,
        "client_script": doc.name,
        "reference_doctype": reference_doctype,
        "enabled": bool(doc.enabled),
    }


@frappe.whitelist()
def install_signed_print_client_scripts_for_policies():
    if not globals().get("_phase26b_is_admin") or not _phase26b_is_admin():
        frappe.throw("Only Internal Signature Administrator can install signed print client scripts.")

    doctypes = set()

    if "PHASE26C_DEMO_DT" in globals() and frappe.db.exists("DocType", PHASE26C_DEMO_DT):
        doctypes.add(PHASE26C_DEMO_DT)

    if frappe.db.exists("DocType", "Internal Signature Policy"):
        for r in frappe.get_all(
            "Internal Signature Policy",
            filters={"is_active": 1},
            fields=["reference_doctype"],
            limit_page_length=500,
        ):
            if r.reference_doctype and frappe.db.exists("DocType", r.reference_doctype):
                doctypes.add(r.reference_doctype)

    results = []
    for dt in sorted(doctypes):
        results.append(install_signed_print_client_script(dt))

    return {
        "ok": True,
        "phase": "26F",
        "count": len(results),
        "results": results,
    }


# Phase 26G: Internal Signature Certificate + QR + Signed PDF Export.
import base64 as _phase26g_base64
import hashlib as _phase26g_hashlib
import json as _phase26g_json
import os as _phase26g_os
import re as _phase26g_re
from urllib.parse import quote as _phase26g_quote


PHASE26G_CERT_DT = "Internal Signature Certificate"


def _phase26g_json_dumps(data) -> str:
    return _phase26g_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _phase26g_sha256_text(text: str) -> str:
    return _phase26g_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase26g_sha256_bytes(data: bytes) -> str:
    return _phase26g_hashlib.sha256(data or b"").hexdigest()


def _phase26g_require_login():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")


def _phase26g_is_admin():
    if frappe.session.user == "Administrator":
        return True
    roles = set(frappe.get_roles() or [])
    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
    }))


def _phase26g_base_url():
    base = ""

    try:
        if frappe.db.exists("DocType", "E-Sign Settings"):
            base = frappe.db.get_single_value("E-Sign Settings", "signing_base_url") or ""
    except Exception:
        base = ""

    if not base:
        try:
            base = frappe.utils.get_url()
        except Exception:
            base = "http://ysmo"

    return str(base).rstrip("/")


def _phase26g_ensure_module():
    if globals().get("_phase26c_ensure_module"):
        return _phase26c_ensure_module()
    if globals().get("_phase26b_ensure_module"):
        return _phase26b_ensure_module()
    if frappe.db.exists("Module Def", "Signing"):
        return {"ok": True, "module": "Signing", "created": False}

    doc = frappe.new_doc("Module Def")
    doc.module_name = "Signing"
    if frappe.get_meta("Module Def").has_field("app_name"):
        doc.app_name = "surhan_signature"
    if frappe.get_meta("Module Def").has_field("custom"):
        doc.custom = 1
    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    return {"ok": True, "module": "Signing", "created": True}


def _phase26g_field(label, fieldname, fieldtype, options=None, reqd=0, hidden=0, read_only=0,
                    unique=0, in_list_view=0, default=None, description=None):
    f = {
        "label": label,
        "fieldname": fieldname,
        "fieldtype": fieldtype,
        "reqd": reqd,
        "hidden": hidden,
        "read_only": read_only,
        "unique": unique,
        "in_list_view": in_list_view,
    }
    if options:
        f["options"] = options
    if default is not None:
        f["default"] = default
    if description:
        f["description"] = description
    return f


def _phase26g_permission(role, read=1, write=0, create=0, delete=0):
    return {
        "role": role,
        "read": read,
        "write": write,
        "create": create,
        "delete": delete,
    }


def _phase26g_ensure_doctype(doctype_name, fields, permissions, autoname="prompt", title_field=None):
    _phase26g_ensure_module()

    clean_fields = []
    for f in fields:
        clean_fields.append({k: v for k, v in f.items() if v is not None})

    if frappe.db.exists("DocType", doctype_name):
        dt = frappe.get_doc("DocType", doctype_name)
        existing = {d.fieldname for d in dt.fields if d.fieldname}
        changed = False

        if getattr(dt, "module", None) != "Signing":
            dt.module = "Signing"
            changed = True

        for field in clean_fields:
            if field.get("fieldname") and field["fieldname"] not in existing:
                dt.append("fields", field)
                changed = True

        if changed:
            dt.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.clear_cache(doctype=doctype_name)
            try:
                frappe.db.updatedb(doctype_name)
            except Exception:
                pass

        return {"doctype": doctype_name, "created": False, "updated": changed}

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": doctype_name,
        "module": "Signing",
        "custom": 1,
        "autoname": autoname,
        "title_field": title_field,
        "track_changes": 1,
        "fields": clean_fields,
        "permissions": permissions,
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    frappe.clear_cache(doctype=doctype_name)

    try:
        frappe.db.updatedb(doctype_name)
    except Exception:
        pass

    return {"doctype": doctype_name, "created": True, "updated": True}


@frappe.whitelist()
def phase26g_install_internal_certificate():
    fields = [
        _phase26g_field("Verification Code", "verification_code", "Data", reqd=1, unique=1, in_list_view=1),
        _phase26g_field("Reference DocType", "reference_doctype", "Link", "DocType", reqd=1, in_list_view=1),
        _phase26g_field("Reference Name", "reference_name", "Dynamic Link", "reference_doctype", reqd=1, in_list_view=1),
        _phase26g_field("Document Title", "document_title", "Data", in_list_view=1),
        _phase26g_field("Certificate Status", "certificate_status", "Select", "Valid\nInvalid\nRevoked", default="Valid", in_list_view=1),
        _phase26g_field("Complete", "complete", "Check", default=0, in_list_view=1),
        _phase26g_field("Status Counts JSON", "status_counts_json", "Code", "JSON"),
        _phase26g_field("Print Hash", "print_hash", "Data", read_only=1, in_list_view=1),
        _phase26g_field("Signed PDF", "signed_pdf", "Attach"),
        _phase26g_field("Signed PDF SHA256", "signed_pdf_sha256", "Data", read_only=1),
        _phase26g_field("Verification URL", "verification_url", "Data", read_only=1),
        _phase26g_field("QR SVG", "qr_svg", "Long Text", read_only=1),
        _phase26g_field("Generated By", "generated_by", "Link", "User", read_only=1),
        _phase26g_field("Generated At", "generated_at", "Datetime", read_only=1),
        _phase26g_field("Revoked", "revoked", "Check", default=0),
        _phase26g_field("Revoked By", "revoked_by", "Link", "User", read_only=1),
        _phase26g_field("Revoked At", "revoked_at", "Datetime", read_only=1),
        _phase26g_field("Revocation Reason", "revocation_reason", "Small Text"),
        _phase26g_field("Notes", "notes", "Small Text"),
    ]

    permissions = [
        _phase26g_permission("System Manager", read=1, write=1, create=1, delete=1),
        _phase26g_permission("Internal Signature Administrator", read=1, write=1, create=1, delete=0),
        _phase26g_permission("Internal Signature Manager", read=1, write=1, create=1, delete=0),
        _phase26g_permission("Internal Signature Auditor", read=1, write=0, create=0, delete=0),
    ]

    dt = _phase26g_ensure_doctype(
        PHASE26G_CERT_DT,
        fields,
        permissions,
        autoname="field:verification_code",
        title_field="document_title",
    )

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26G",
        "doctype": dt,
    }


def _phase26g_private_file_to_data_url(file_url: str):
    if not file_url:
        return ""

    file_url = str(file_url)

    path = None
    mime = "image/png"

    if file_url.startswith("/private/files/"):
        fname = file_url.split("/private/files/", 1)[1]
        path = frappe.get_site_path("private", "files", fname)
    elif file_url.startswith("/files/"):
        fname = file_url.split("/files/", 1)[1]
        path = frappe.get_site_path("public", "files", fname)
    else:
        try:
            file_doc = frappe.get_doc("File", {"file_url": file_url})
            if file_doc.is_private:
                fname = file_doc.file_url.split("/private/files/", 1)[1]
                path = frappe.get_site_path("private", "files", fname)
            else:
                fname = file_doc.file_url.split("/files/", 1)[1]
                path = frappe.get_site_path("public", "files", fname)
        except Exception:
            return ""

    if not path or not _phase26g_os.path.exists(path):
        return ""

    ext = _phase26g_os.path.splitext(path)[1].lower()
    if ext in {".jpg", ".jpeg"}:
        mime = "image/jpeg"
    elif ext == ".svg":
        mime = "image/svg+xml"
    elif ext == ".webp":
        mime = "image/webp"

    with open(path, "rb") as f:
        raw = f.read()

    return f"data:{mime};base64,{_phase26g_base64.b64encode(raw).decode('ascii')}"


def _phase26g_file_sha256(file_url: str):
    if not file_url:
        return None

    path = None

    if file_url.startswith("/private/files/"):
        fname = file_url.split("/private/files/", 1)[1]
        path = frappe.get_site_path("private", "files", fname)
    elif file_url.startswith("/files/"):
        fname = file_url.split("/files/", 1)[1]
        path = frappe.get_site_path("public", "files", fname)

    if not path or not _phase26g_os.path.exists(path):
        return None

    with open(path, "rb") as f:
        return _phase26g_sha256_bytes(f.read())


def _phase26g_qr_svg(text: str):
    try:
        from reportlab.graphics.barcode import qr
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics import renderSVG

        widget = qr.QrCodeWidget(text)
        bounds = widget.getBounds()
        width = bounds[2] - bounds[0]
        height = bounds[3] - bounds[1]
        size = 120

        drawing = Drawing(size, size, transform=[size / width, 0, 0, size / height, 0, 0])
        drawing.add(widget)

        svg = renderSVG.drawToString(drawing)
        if isinstance(svg, bytes):
            svg = svg.decode("utf-8")
        return svg
    except Exception:
        return ""


def _phase26g_sanitize_html(html: str):
    html = html or ""
    html = _phase26g_re.sub(r"<script[\s\S]*?</script>", "", html, flags=_phase26g_re.IGNORECASE)
    html = _phase26g_re.sub(r"\son[a-zA-Z]+\s*=\s*(['\"]).*?\1", "", html)
    return html


def _phase26g_html_for_pdf(ctx, qr_svg):
    doc = ctx.get("document") or {}
    requests = ctx.get("requests") or []
    signatures = ctx.get("signatures") or []

    for r in signatures:
        r["signature_data_url"] = _phase26g_private_file_to_data_url(r.get("signature_png"))

    content_html = _phase26g_sanitize_html(doc.get("content_html") or "")

    signature_cards = ""
    for r in signatures:
        img = ""
        if r.get("signature_data_url"):
            img = f'<img src="{r["signature_data_url"]}" style="max-height:70px;max-width:220px;object-fit:contain;">'

        signature_cards += f"""
        <div class="sig-card">
          <div class="sig-box">{img}</div>
          <div class="sig-name">{frappe.utils.escape_html(r.get("full_name") or r.get("requested_user") or "")}</div>
          <div class="sig-small">
            {frappe.utils.escape_html(r.get("designation") or "")} / {frappe.utils.escape_html(r.get("department") or "")}<br>
            Employee: {frappe.utils.escape_html(r.get("requested_employee") or "-")}<br>
            Status: <b>{frappe.utils.escape_html(r.get("status") or "")}</b><br>
            Completed: {frappe.utils.escape_html(r.get("completed_at") or "-")}<br>
            Request: {frappe.utils.escape_html(r.get("name") or "-")}<br>
            Hash: {frappe.utils.escape_html(r.get("signature_hash") or "-")}
          </div>
        </div>
        """

    if not signature_cards:
        signature_cards = "<p>No completed signatures.</p>"

    status_badges = ""
    for k, v in (ctx.get("status_counts") or {}).items():
        status_badges += f"<span class='badge'>{frappe.utils.escape_html(k)}: {frappe.utils.escape_html(str(v))}</span>"

    fields_html = ""
    for f in doc.get("fields") or []:
        fields_html += f"""
        <div class="meta">
          <div class="key">{frappe.utils.escape_html(f.get("label") or "")}</div>
          <div class="value">{frappe.utils.escape_html(f.get("value") or "")}</div>
        </div>
        """

    return f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{
    font-family: Arial, sans-serif;
    color: #111827;
    font-size: 12px;
    margin: 0;
    padding: 0;
  }}
  .header {{
    display: table;
    width: 100%;
    border-bottom: 3px solid #111827;
    padding-bottom: 14px;
    margin-bottom: 18px;
  }}
  .left {{ display: table-cell; width: 65%; vertical-align: top; }}
  .right {{ display: table-cell; width: 35%; text-align: right; vertical-align: top; }}
  h1 {{ margin: 0 0 6px; font-size: 24px; }}
  h2 {{ font-size: 17px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; margin-top: 22px; }}
  .meta-grid {{ display: table; width: 100%; }}
  .meta {{ display: table; width: 100%; border-bottom: 1px dashed #e5e7eb; padding: 5px 0; }}
  .key {{ display: table-cell; width: 180px; color: #6b7280; }}
  .value {{ display: table-cell; }}
  .content {{ border: 1px solid #e5e7eb; padding: 14px; border-radius: 8px; min-height: 180px; }}
  .sig-grid {{ display: table; width: 100%; border-spacing: 10px; }}
  .sig-card {{
    display: inline-block;
    width: 45%;
    vertical-align: top;
    border: 1px solid #10b981;
    border-radius: 10px;
    padding: 12px;
    min-height: 165px;
    margin: 6px;
  }}
  .sig-box {{
    height: 76px;
    border-bottom: 1px solid #e5e7eb;
    text-align: center;
    margin-bottom: 8px;
  }}
  .sig-name {{ font-weight: bold; margin-bottom: 4px; }}
  .sig-small {{ color: #374151; font-size: 11px; line-height: 1.5; word-break: break-all; }}
  .audit {{
    background: #f3f4f6;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 10px;
    font-family: monospace;
    font-size: 10px;
    word-break: break-all;
  }}
  .badge {{
    display: inline-block;
    border: 1px solid #10b981;
    color: #047857;
    padding: 4px 8px;
    border-radius: 999px;
    margin: 2px;
    font-weight: bold;
    font-size: 10px;
  }}
  .qr {{ margin-top: 8px; }}
  .footer {{
    border-top: 2px solid #111827;
    margin-top: 28px;
    padding-top: 10px;
    font-size: 10px;
    color: #4b5563;
  }}
</style>
</head>
<body>
  <div class="header">
    <div class="left">
      <h1>Signed Document</h1>
      <div>Surhan Internal Signature Workflow</div>
    </div>
    <div class="right">
      <b>{'SIGNED / COMPLETED' if ctx.get('complete') else 'IN PROGRESS'}</b><br>
      {frappe.utils.escape_html(ctx.get('reference_doctype') or '')}<br>
      {frappe.utils.escape_html(ctx.get('reference_name') or '')}<br>
      {frappe.utils.escape_html(ctx.get('generated_at') or '')}
      <div class="qr">{qr_svg or ''}</div>
    </div>
  </div>

  <h2>{frappe.utils.escape_html(doc.get('title') or ctx.get('reference_name') or '')}</h2>
  <div class="meta-grid">
    <div class="meta"><div class="key">DocType</div><div class="value">{frappe.utils.escape_html(ctx.get('reference_doctype') or '')}</div></div>
    <div class="meta"><div class="key">Document Name</div><div class="value">{frappe.utils.escape_html(ctx.get('reference_name') or '')}</div></div>
    <div class="meta"><div class="key">Status</div><div class="value">{'Completed' if ctx.get('complete') else 'In Progress'}</div></div>
    <div class="meta"><div class="key">Requests</div><div class="value">{len(requests)}</div></div>
  </div>

  <h2>Document Content</h2>
  <div class="content">{content_html or '<p>No rich content found.</p>'}</div>

  <h2>Document Fields</h2>
  {fields_html or '<p>No additional fields.</p>'}

  <h2>Signatures</h2>
  <div class="sig-grid">{signature_cards}</div>

  <h2>Verification Summary</h2>
  <div>{status_badges}</div>
  <div class="audit">
    Reference: {frappe.utils.escape_html(ctx.get('reference_doctype') or '')} / {frappe.utils.escape_html(ctx.get('reference_name') or '')}<br>
    Generated At: {frappe.utils.escape_html(ctx.get('generated_at') or '')}<br>
    Complete: {frappe.utils.escape_html(str(ctx.get('complete')))}<br>
    Print Hash: {frappe.utils.escape_html(ctx.get('print_hash') or '')}
  </div>

  <div class="footer">
    Generated by Surhan Signature — Print Hash: {frappe.utils.escape_html(ctx.get('print_hash') or '')}
  </div>
</body>
</html>
"""


def _phase26g_generate_pdf_bytes(ctx, qr_svg):
    html = _phase26g_html_for_pdf(ctx, qr_svg)

    try:
        from frappe.utils.pdf import get_pdf
        return get_pdf(html)
    except Exception:
        # Fallback minimal PDF if wkhtmltopdf is unavailable.
        from io import BytesIO
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        y = height - 50
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, y, "Signed Document")
        y -= 25

        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"{ctx.get('reference_doctype')} / {ctx.get('reference_name')}")
        y -= 18
        c.drawString(40, y, f"Complete: {ctx.get('complete')}")
        y -= 18
        c.drawString(40, y, f"Print Hash: {ctx.get('print_hash')}")
        y -= 35

        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Signatures")
        y -= 18

        c.setFont("Helvetica", 9)
        for r in ctx.get("signatures") or []:
            c.drawString(40, y, f"{r.get('full_name')} - {r.get('status')} - {r.get('completed_at')}")
            y -= 14
            c.drawString(40, y, f"Hash: {r.get('signature_hash')}")
            y -= 20

        c.showPage()
        c.save()
        return buffer.getvalue()


def _phase26g_existing_certificate(reference_doctype, reference_name):
    if not frappe.db.exists("DocType", PHASE26G_CERT_DT):
        return None

    rows = frappe.get_all(
        PHASE26G_CERT_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
            "revoked": 0,
        },
        pluck="name",
        limit=1,
        order_by="modified desc",
    )
    return rows[0] if rows else None


@frappe.whitelist()
def generate_internal_signature_certificate(reference_doctype: str, reference_name: str, force: int = 0):
    _phase26g_require_login()
    phase26g_install_internal_certificate()

    ctx = get_signed_document_print_context(reference_doctype, reference_name)

    if not ctx.get("complete") and not int(force or 0):
        frappe.throw("Cannot generate final certificate/PDF before the document signature workflow is complete.")

    existing = _phase26g_existing_certificate(reference_doctype, reference_name)

    if existing:
        cert = frappe.get_doc(PHASE26G_CERT_DT, existing)
        action = "updated"
        verification_code = cert.verification_code
    else:
        verification_code = frappe.generate_hash(length=24)
        cert = frappe.new_doc(PHASE26G_CERT_DT)
        cert.name = verification_code
        cert.verification_code = verification_code
        action = "created"

    verification_url = f"{_phase26g_base_url()}/internal-sign-verify?code={_phase26g_quote(verification_code)}"
    qr_svg = _phase26g_qr_svg(verification_url)

    cert.reference_doctype = reference_doctype
    cert.reference_name = reference_name
    cert.document_title = (ctx.get("document") or {}).get("title")
    cert.certificate_status = "Valid"
    cert.complete = 1 if ctx.get("complete") else 0
    cert.status_counts_json = _phase26g_json_dumps(ctx.get("status_counts") or {})
    cert.print_hash = ctx.get("print_hash")
    cert.verification_url = verification_url
    cert.qr_svg = qr_svg
    cert.generated_by = frappe.session.user
    cert.generated_at = now_datetime()
    cert.revoked = 0

    if existing:
        cert.save(ignore_permissions=True)
    else:
        cert.insert(ignore_permissions=True)

    frappe.db.commit()

    pdf_bytes = _phase26g_generate_pdf_bytes(ctx, qr_svg)

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"{frappe.scrub(reference_doctype)}-{reference_name}-signed-{verification_code[:10]}.pdf",
        content=pdf_bytes,
        dt=PHASE26G_CERT_DT,
        dn=cert.name,
        is_private=1,
    )

    cert.signed_pdf = file_doc.file_url
    cert.signed_pdf_sha256 = _phase26g_file_sha256(file_doc.file_url) or _phase26g_sha256_bytes(pdf_bytes)
    cert.save(ignore_permissions=True)

    frappe.db.commit()

    try:
        log_audit(
            "internal_document_signature.certificate_generated",
            {
                "certificate": cert.name,
                "verification_code": verification_code,
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "print_hash": cert.print_hash,
                "signed_pdf_sha256": cert.signed_pdf_sha256,
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "26G",
        "action": action,
        "certificate": cert.name,
        "verification_code": cert.verification_code,
        "reference_doctype": cert.reference_doctype,
        "reference_name": cert.reference_name,
        "document_title": cert.document_title,
        "certificate_status": cert.certificate_status,
        "complete": bool(cert.complete),
        "print_hash": cert.print_hash,
        "signed_pdf": cert.signed_pdf,
        "signed_pdf_sha256": cert.signed_pdf_sha256,
        "verification_url": cert.verification_url,
        "has_qr_svg": bool(cert.qr_svg),
    }


@frappe.whitelist(allow_guest=True)
def verify_internal_signature_certificate(verification_code: str):
    from surhan_signature.security.file_security import assert_public_payload_safe

    if not verification_code:
        frappe.throw("verification_code is required.")

    if not frappe.db.exists("DocType", PHASE26G_CERT_DT):
        return {
            "ok": False,
            "valid": False,
            "reason": "Internal Signature Certificate is not installed.",
        }

    if not frappe.db.exists(PHASE26G_CERT_DT, verification_code):
        return {
            "ok": True,
            "valid": False,
            "reason": "Certificate not found.",
            "verification_code": verification_code,
        }

    cert = frappe.get_doc(PHASE26G_CERT_DT, verification_code)

    pdf_sha_actual = _phase26g_file_sha256(cert.signed_pdf) if cert.signed_pdf else None
    pdf_sha_matches = bool(pdf_sha_actual and cert.signed_pdf_sha256 and pdf_sha_actual == cert.signed_pdf_sha256)

    valid = bool(
        cert.certificate_status == "Valid"
        and not int(cert.revoked or 0)
        and int(cert.complete or 0)
        and cert.print_hash
        and pdf_sha_matches
    )

    out = {
        "ok": True,
        "valid": valid,
        "verification_code": cert.verification_code,
        "certificate": cert.name,
        "certificate_status": cert.certificate_status,
        "revoked": bool(cert.revoked),
        "reference_doctype": cert.reference_doctype,
        "reference_name": cert.reference_name,
        "document_title": cert.document_title,
        "complete": bool(cert.complete),
        "status_counts": _phase26g_json.loads(cert.status_counts_json or "{}"),
        "print_hash": cert.print_hash,
        "signed_pdf_sha256": cert.signed_pdf_sha256,
        "signed_pdf_sha256_actual": pdf_sha_actual,
        "signed_pdf_sha256_matches": pdf_sha_matches,
        "verification_url": cert.verification_url,
        "generated_by": cert.generated_by,
        "generated_at": str(cert.generated_at or ""),
    }

    if frappe.session.user != "Guest":
        out["signed_pdf"] = cert.signed_pdf
        out["qr_svg"] = cert.qr_svg
    else:
        assert_public_payload_safe(out)

    return out


@frappe.whitelist()
def phase26g_internal_certificate_health(reference_doctype: str = None, reference_name: str = None):
    phase26g_install_internal_certificate()

    reference_doctype = reference_doctype or "Internal Signature Demo Document"
    reference_name = reference_name or "ISD-2026-00002"

    generated = None
    verified = None

    try:
        if frappe.db.exists(reference_doctype, reference_name):
            generated = generate_internal_signature_certificate(reference_doctype, reference_name, force=0)
            verified = verify_internal_signature_certificate(generated.get("verification_code"))
        else:
            generated = {
                "ok": False,
                "reason": f"Document not found: {reference_doctype} {reference_name}",
            }
    except Exception as exc:
        generated = {
            "ok": False,
            "error": str(exc),
        }

    return {
        "ok": True,
        "phase": "26G",
        "doctype_exists": bool(frappe.db.exists("DocType", PHASE26G_CERT_DT)),
        "generated": generated,
        "verified": verified,
        "ready": bool(generated and generated.get("ok") and verified and verified.get("valid")),
    }


def _phase26g_certificate_client_script_code(reference_doctype: str) -> str:
    import json
    doctype_json = json.dumps(reference_doctype)

    return f"""
// Surhan Signature Phase 26G - Generate Signed Certificate / PDF
frappe.ui.form.on({doctype_json}, {{
  refresh: function(frm) {{
    if (!frm || !frm.doc || frm.is_new()) return;

    frm.add_custom_button(__('Generate Signed Certificate / PDF'), function() {{
      frappe.call({{
        method: 'surhan_signature.api.generate_internal_signature_certificate',
        args: {{
          reference_doctype: frm.doc.doctype,
          reference_name: frm.doc.name
        }},
        freeze: true,
        freeze_message: __('Generating signed certificate and PDF...'),
        callback: function(r) {{
          const data = r.message || r;
          frappe.msgprint({{
            title: __('Signed Certificate Generated'),
            indicator: data.ok ? 'green' : 'red',
            message: '<p><b>Certificate:</b> ' + frappe.utils.escape_html(data.certificate || '') + '</p>' +
                     '<p><b>Verification URL:</b><br><a href=\"' + frappe.utils.escape_html(data.verification_url || '#') + '\" target=\"_blank\">' + frappe.utils.escape_html(data.verification_url || '') + '</a></p>' +
                     '<p><b>PDF:</b><br><a href=\"' + frappe.utils.escape_html(data.signed_pdf || '#') + '\" target=\"_blank\">Open signed PDF</a></p>'
          }});
        }}
      }});
    }}, __('Internal Signature'));

    frm.add_custom_button(__('Open Internal Verification'), function() {{
      frappe.call({{
        method: 'surhan_signature.api.generate_internal_signature_certificate',
        args: {{
          reference_doctype: frm.doc.doctype,
          reference_name: frm.doc.name
        }},
        freeze: true,
        freeze_message: __('Preparing verification...'),
        callback: function(r) {{
          const data = r.message || r;
          if (data.verification_url) {{
            window.open(data.verification_url, '_blank');
          }}
        }}
      }});
    }}, __('Internal Signature'));
  }}
}});
"""


@frappe.whitelist()
def install_internal_certificate_client_script(reference_doctype: str):
    if not _phase26g_is_admin():
        frappe.throw("Only Internal Signature Administrator can install certificate client scripts.")

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    if not frappe.db.exists("DocType", "Client Script"):
        frappe.throw("Client Script DocType is not available.")

    script_name = f"Surhan Internal Certificate PDF - {reference_doctype}"
    script_code = _phase26g_certificate_client_script_code(reference_doctype)

    existing = frappe.db.exists("Client Script", script_name)

    if existing:
        doc = frappe.get_doc("Client Script", existing)
        action = "updated"
    else:
        doc = frappe.new_doc("Client Script")
        doc.name = script_name
        action = "created"

    doc.dt = reference_doctype
    doc.script = script_code
    doc.enabled = 1

    meta = frappe.get_meta("Client Script")
    if meta.has_field("view"):
        doc.view = "Form"

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache(doctype=reference_doctype)

    return {
        "ok": True,
        "phase": "26G",
        "action": action,
        "client_script": doc.name,
        "reference_doctype": reference_doctype,
        "enabled": bool(doc.enabled),
    }


@frappe.whitelist()
def install_internal_certificate_client_scripts_for_policies():
    if not _phase26g_is_admin():
        frappe.throw("Only Internal Signature Administrator can install certificate client scripts.")

    doctypes = set()

    if "PHASE26C_DEMO_DT" in globals() and frappe.db.exists("DocType", PHASE26C_DEMO_DT):
        doctypes.add(PHASE26C_DEMO_DT)

    if frappe.db.exists("DocType", "Internal Signature Policy"):
        for r in frappe.get_all(
            "Internal Signature Policy",
            filters={"is_active": 1},
            fields=["reference_doctype"],
            limit_page_length=500,
        ):
            if r.reference_doctype and frappe.db.exists("DocType", r.reference_doctype):
                doctypes.add(r.reference_doctype)

    results = []
    for dt in sorted(doctypes):
        results.append(install_internal_certificate_client_script(dt))

    return {
        "ok": True,
        "phase": "26G",
        "count": len(results),
        "results": results,
    }


# Phase 26H: External Signature Gateway API.
import hashlib as _phase26h_hashlib
import hmac as _phase26h_hmac
import json as _phase26h_json
import time as _phase26h_time
import urllib.request as _phase26h_urllib_request
import urllib.error as _phase26h_urllib_error


PHASE26H_SYSTEM_DT = "Internal Signature External System"
PHASE26H_REQUEST_DT = "Internal Signature External Request"


def _phase26h_json_dumps(data) -> str:
    return _phase26h_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _phase26h_parse_json(value, default=None):
    if default is None:
        default = {}

    if value is None or value == "":
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        return _phase26h_json.loads(value)
    except Exception:
        return default


def _phase26h_sha256_text(text: str) -> str:
    return _phase26h_hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _phase26h_hmac_sha256(secret: str, payload: str) -> str:
    return _phase26h_hmac.new(
        (secret or "").encode("utf-8"),
        (payload or "").encode("utf-8"),
        _phase26h_hashlib.sha256,
    ).hexdigest()


def _phase26h_now_ts() -> str:
    return str(int(_phase26h_time.time()))


def _phase26h_request_ip():
    try:
        return frappe.local.request_ip or frappe.get_request_header("X-Forwarded-For") or ""
    except Exception:
        return ""


def _phase26h_user_agent():
    try:
        return frappe.get_request_header("User-Agent") or ""
    except Exception:
        return ""


def _phase26h_raw_body():
    try:
        return frappe.local.request.get_data(as_text=True) or ""
    except Exception:
        return ""


def _phase26h_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature API User",
    }))


def _phase26h_require_admin():
    if not _phase26h_is_admin():
        frappe.throw("Only Internal Signature Administrator can manage external signature gateway.")


def _phase26h_ensure_module():
    if globals().get("_phase26c_ensure_module"):
        return _phase26c_ensure_module()
    if globals().get("_phase26g_ensure_module"):
        return _phase26g_ensure_module()

    if frappe.db.exists("Module Def", "Signing"):
        return {"ok": True, "module": "Signing", "created": False}

    doc = frappe.new_doc("Module Def")
    doc.module_name = "Signing"

    if frappe.get_meta("Module Def").has_field("app_name"):
        doc.app_name = "surhan_signature"

    if frappe.get_meta("Module Def").has_field("custom"):
        doc.custom = 1

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {"ok": True, "module": "Signing", "created": True}


def _phase26h_field(label, fieldname, fieldtype, options=None, reqd=0, hidden=0, read_only=0,
                    unique=0, in_list_view=0, default=None, description=None):
    f = {
        "label": label,
        "fieldname": fieldname,
        "fieldtype": fieldtype,
        "reqd": reqd,
        "hidden": hidden,
        "read_only": read_only,
        "unique": unique,
        "in_list_view": in_list_view,
    }
    if options:
        f["options"] = options
    if default is not None:
        f["default"] = default
    if description:
        f["description"] = description
    return f


def _phase26h_permission(role, read=1, write=0, create=0, delete=0):
    return {
        "role": role,
        "read": read,
        "write": write,
        "create": create,
        "delete": delete,
    }


def _phase26h_ensure_doctype(doctype_name, fields, permissions, autoname="prompt", title_field=None):
    _phase26h_ensure_module()

    clean_fields = []
    for f in fields:
        clean_fields.append({k: v for k, v in f.items() if v is not None})

    if frappe.db.exists("DocType", doctype_name):
        dt = frappe.get_doc("DocType", doctype_name)
        existing = {d.fieldname for d in dt.fields if d.fieldname}
        changed = False

        if getattr(dt, "module", None) != "Signing":
            dt.module = "Signing"
            changed = True

        for field in clean_fields:
            if field.get("fieldname") and field["fieldname"] not in existing:
                dt.append("fields", field)
                changed = True

        if changed:
            dt.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.clear_cache(doctype=doctype_name)
            try:
                frappe.db.updatedb(doctype_name)
            except Exception:
                pass

        return {"doctype": doctype_name, "created": False, "updated": changed}

    doc = frappe.get_doc({
        "doctype": "DocType",
        "name": doctype_name,
        "module": "Signing",
        "custom": 1,
        "autoname": autoname,
        "title_field": title_field,
        "track_changes": 1,
        "fields": clean_fields,
        "permissions": permissions,
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()
    frappe.clear_cache(doctype=doctype_name)

    try:
        frappe.db.updatedb(doctype_name)
    except Exception:
        pass

    return {"doctype": doctype_name, "created": True, "updated": True}


@frappe.whitelist()
def phase26h_install_external_gateway():
    _phase26h_ensure_module()

    system_fields = [
        _phase26h_field("System ID", "system_id", "Data", reqd=1, unique=1, in_list_view=1),
        _phase26h_field("System Name", "system_name", "Data", reqd=1, in_list_view=1),
        _phase26h_field("Is Active", "is_active", "Check", default=1, in_list_view=1),
        _phase26h_field("Gateway API Key", "gateway_api_key", "Data", unique=1, read_only=1, in_list_view=1),
        _phase26h_field("API Secret Hash", "api_secret_hash", "Data", read_only=1),
        _phase26h_field("HMAC Secret Encrypted", "hmac_secret_encrypted", "Password", hidden=1),
        _phase26h_field("Require HMAC", "require_hmac", "Check", default=1),
        _phase26h_field("Allowed DocTypes JSON", "allowed_doctypes_json", "Code", "JSON"),
        _phase26h_field("Default Callback URL", "default_callback_url", "Data"),
        _phase26h_field("Allow Create Requests", "allow_create_requests", "Check", default=1),
        _phase26h_field("Allow Status Lookup", "allow_status_lookup", "Check", default=1),
        _phase26h_field("Allow Callback Delivery", "allow_callback_delivery", "Check", default=1),
        _phase26h_field("Last Used At", "last_used_at", "Datetime", read_only=1),
        _phase26h_field("Last Used IP", "last_used_ip", "Data", read_only=1),
        _phase26h_field("Created By", "created_by", "Link", "User", read_only=1),
        _phase26h_field("Created At", "created_at", "Datetime", read_only=1),
        _phase26h_field("Notes", "notes", "Small Text"),
    ]

    request_fields = [
        _phase26h_field("External Request ID", "external_request_id", "Data", reqd=1, unique=1, in_list_view=1),
        _phase26h_field("External System", "external_system", "Link", PHASE26H_SYSTEM_DT, reqd=1, in_list_view=1),
        _phase26h_field("External Reference", "external_reference", "Data", reqd=1, in_list_view=1),
        _phase26h_field("Reference DocType", "reference_doctype", "Link", "DocType", reqd=1, in_list_view=1),
        _phase26h_field("Reference Name", "reference_name", "Dynamic Link", "reference_doctype", reqd=1, in_list_view=1),
        _phase26h_field("Gateway Status", "gateway_status", "Select", "Pending\nIn Progress\nCompleted\nRejected\nCancelled\nError", default="Pending", in_list_view=1),
        _phase26h_field("Signers JSON", "signers_json", "Code", "JSON"),
        _phase26h_field("Document Signature Requests JSON", "document_signature_requests_json", "Code", "JSON"),
        _phase26h_field("Callback URL", "callback_url", "Data"),
        _phase26h_field("Callback Status", "callback_status", "Select", "Not Sent\nDry Run\nSent\nFailed", default="Not Sent"),
        _phase26h_field("Callback Attempts", "callback_attempts", "Int", default=0),
        _phase26h_field("Callback Response", "callback_response", "Small Text"),
        _phase26h_field("Last Callback At", "last_callback_at", "Datetime", read_only=1),
        _phase26h_field("Request Hash", "request_hash", "Data", read_only=1),
        _phase26h_field("Verification Code", "verification_code", "Data", read_only=1),
        _phase26h_field("Verification URL", "verification_url", "Data", read_only=1),
        _phase26h_field("Signed PDF", "signed_pdf", "Attach"),
        _phase26h_field("Signed PDF SHA256", "signed_pdf_sha256", "Data", read_only=1),
        _phase26h_field("Created Via", "created_via", "Select", "External API\nAdmin\nDemo", default="External API"),
        _phase26h_field("Created IP", "created_ip", "Data", read_only=1),
        _phase26h_field("User Agent", "user_agent", "Small Text", read_only=1),
        _phase26h_field("Created At", "created_at", "Datetime", read_only=1),
        _phase26h_field("Updated At", "updated_at", "Datetime", read_only=1),
        _phase26h_field("Metadata JSON", "metadata_json", "Code", "JSON"),
        _phase26h_field("Error Message", "error_message", "Small Text"),
    ]

    permissions = [
        _phase26h_permission("System Manager", read=1, write=1, create=1, delete=1),
        _phase26h_permission("Internal Signature Administrator", read=1, write=1, create=1, delete=0),
        _phase26h_permission("Internal Signature Manager", read=1, write=1, create=1, delete=0),
        _phase26h_permission("Internal Signature Auditor", read=1, write=0, create=0, delete=0),
        _phase26h_permission("Internal Signature API User", read=1, write=1, create=1, delete=0),
    ]

    system_dt = _phase26h_ensure_doctype(
        PHASE26H_SYSTEM_DT,
        system_fields,
        permissions,
        autoname="field:system_id",
        title_field="system_name",
    )

    request_dt = _phase26h_ensure_doctype(
        PHASE26H_REQUEST_DT,
        request_fields,
        permissions,
        autoname="field:external_request_id",
        title_field="external_reference",
    )

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26H",
        "doctypes": [system_dt, request_dt],
    }


def _phase26h_get_encrypted_secret(system_name):
    if globals().get("_phase26a_get_encrypted"):
        return _phase26a_get_encrypted(PHASE26H_SYSTEM_DT, system_name, "hmac_secret_encrypted")

    from frappe.utils.password import get_decrypted_password
    return get_decrypted_password(PHASE26H_SYSTEM_DT, system_name, "hmac_secret_encrypted", raise_exception=False) or ""


def _phase26h_set_encrypted_secret(system_name, secret):
    if globals().get("_phase26a_set_encrypted"):
        return _phase26a_set_encrypted(PHASE26H_SYSTEM_DT, system_name, "hmac_secret_encrypted", secret)

    from frappe.utils.password import set_encrypted_password
    return set_encrypted_password(PHASE26H_SYSTEM_DT, system_name, secret or "", "hmac_secret_encrypted")


@frappe.whitelist()
def admin_upsert_external_signature_system(
    system_id: str,
    system_name: str = None,
    allowed_doctypes_json=None,
    default_callback_url: str = None,
    require_hmac: int = 1,
    is_active: int = 1,
    regenerate_secret: int = 0,
    notes: str = None,
):
    _phase26h_require_admin()
    phase26h_install_external_gateway()

    if not system_id:
        frappe.throw("system_id is required.")

    system_id = str(system_id).strip()
    system_name = system_name or system_id

    if default_callback_url:
        try:
            default_callback_url = validate_outbound_url(default_callback_url)
        except ValueError as exc:
            frappe.throw(str(exc))

    existing = frappe.db.exists(PHASE26H_SYSTEM_DT, system_id)

    secret_plain = None

    if existing:
        doc = frappe.get_doc(PHASE26H_SYSTEM_DT, existing)
        action = "updated"
    else:
        doc = frappe.new_doc(PHASE26H_SYSTEM_DT)
        doc.name = system_id
        doc.system_id = system_id
        doc.gateway_api_key = "sgw_" + frappe.generate_hash(length=28)
        doc.created_by = frappe.session.user
        doc.created_at = now_datetime()
        action = "created"
        regenerate_secret = 1

    doc.system_name = system_name
    doc.is_active = int(is_active or 0)
    doc.require_hmac = int(require_hmac or 0)
    doc.allowed_doctypes_json = _phase26h_json_dumps(_phase26h_parse_json(allowed_doctypes_json, []))
    doc.default_callback_url = default_callback_url or ""
    doc.allow_create_requests = 1
    doc.allow_status_lookup = 1
    doc.allow_callback_delivery = 1
    doc.notes = notes or ""

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    if int(regenerate_secret or 0):
        secret_plain = "ssec_" + frappe.generate_hash(length=40)
        doc.api_secret_hash = _phase26h_sha256_text(secret_plain)
        doc.save(ignore_permissions=True)
        _phase26h_set_encrypted_secret(doc.name, secret_plain)

    frappe.db.commit()

    out = {
        "ok": True,
        "phase": "26H",
        "action": action,
        "system": doc.name,
        "system_id": doc.system_id,
        "system_name": doc.system_name,
        "gateway_api_key": doc.gateway_api_key,
        "api_secret_visible_once": bool(secret_plain),
        "require_hmac": bool(doc.require_hmac),
        "is_active": bool(doc.is_active),
        "allowed_doctypes_json": _phase26h_parse_json(doc.allowed_doctypes_json, []),
    }

    if secret_plain:
        out["api_secret"] = secret_plain
        out["warning"] = "Store api_secret securely. It will not be shown again unless regenerated."

    return out


def _phase26h_find_system_by_api_key(api_key):
    if not api_key:
        return None

    rows = frappe.get_all(
        PHASE26H_SYSTEM_DT,
        filters={"gateway_api_key": api_key},
        pluck="name",
        limit=1,
    )

    return rows[0] if rows else None


def _phase26h_authenticate_external(payload=None, system_id=None, purpose="create"):
    phase26h_install_external_gateway()

    # Admin/session mode for internal tests and management.
    if frappe.session.user != "Guest" and _phase26h_is_admin():
        if system_id and frappe.db.exists(PHASE26H_SYSTEM_DT, system_id):
            doc = frappe.get_doc(PHASE26H_SYSTEM_DT, system_id)
        else:
            rows = frappe.get_all(PHASE26H_SYSTEM_DT, pluck="name", limit=1)
            doc = frappe.get_doc(PHASE26H_SYSTEM_DT, rows[0]) if rows else None

        if doc:
            return {
                "ok": True,
                "mode": "admin_session",
                "system": doc,
                "hmac_verified": False,
            }

    api_key = (
        frappe.get_request_header("X-Surhan-Api-Key")
        or frappe.get_request_header("X-Signature-Api-Key")
        or frappe.form_dict.get("api_key")
    )

    system_name = _phase26h_find_system_by_api_key(api_key)

    if not system_name:
        frappe.throw("External signature gateway authentication failed: invalid API key.")

    system = frappe.get_doc(PHASE26H_SYSTEM_DT, system_name)

    if not int(system.is_active or 0):
        frappe.throw("External signature system is inactive.")

    if purpose == "create" and not int(system.allow_create_requests or 0):
        frappe.throw("External system is not allowed to create requests.")

    if purpose == "status" and not int(system.allow_status_lookup or 0):
        frappe.throw("External system is not allowed to check status.")

    hmac_verified = False

    if int(system.require_hmac or 0):
        timestamp = frappe.get_request_header("X-Surhan-Timestamp") or frappe.form_dict.get("timestamp")
        signature = frappe.get_request_header("X-Surhan-Signature") or frappe.form_dict.get("signature")

        if not timestamp or not signature:
            frappe.throw("Missing HMAC timestamp or signature.")

        try:
            ts = int(timestamp)
        except Exception:
            frappe.throw("Invalid HMAC timestamp.")

        if abs(int(_phase26h_time.time()) - ts) > 300:
            frappe.throw("HMAC timestamp expired.")

        raw_body = _phase26h_raw_body()
        if not raw_body and payload is not None:
            raw_body = _phase26h_json_dumps(payload)

        secret = _phase26h_get_encrypted_secret(system.name)

        expected = _phase26h_hmac_sha256(secret, f"{timestamp}.{raw_body}")
        expected_alt = _phase26h_hmac_sha256(secret, raw_body)

        provided = str(signature).replace("sha256=", "").strip().lower()

        if not _phase26h_hmac.compare_digest(provided, expected) and not _phase26h_hmac.compare_digest(provided, expected_alt):
            frappe.throw("Invalid HMAC signature.")

        replay_material = f"{system.name}|{timestamp}|{provided}"
        replay_key = "surhan_signature:hmac_replay:" + _phase26h_sha256_text(replay_material)
        cache = frappe.cache()
        if not cache.set(replay_key, "1", ex=600, nx=True):
            frappe.throw("HMAC replay detected.")

        hmac_verified = True

    frappe.db.set_value(
        PHASE26H_SYSTEM_DT,
        system.name,
        {
            "last_used_at": now_datetime(),
            "last_used_ip": _phase26h_request_ip(),
        },
        update_modified=False,
    )
    frappe.db.commit()

    return {
        "ok": True,
        "mode": "external_hmac",
        "system": system,
        "hmac_verified": hmac_verified,
    }


def _phase26h_validate_system_allowed_doctype(system, reference_doctype):
    allowed = _phase26h_parse_json(system.allowed_doctypes_json, [])

    if allowed and reference_doctype not in allowed:
        frappe.throw(f"External system is not allowed to use DocType: {reference_doctype}")

    return True


def _phase26h_policy_allows_external(reference_doctype):
    policy = _phase26c_get_policy(reference_doctype)

    if not int(getattr(policy, "is_active", 0) or 0):
        frappe.throw("Internal signature policy is inactive for this DocType.")

    if not int(getattr(policy, "allow_external_requests", 0) or 0):
        frappe.throw("External requests are not allowed for this DocType policy.")

    return policy


def _phase26h_normalize_action(action):
    action = str(action or "Saved Signature").strip().lower()

    if action in {"saved", "saved_signature", "signature", "sign", "approve"}:
        return "Saved Signature"

    if action in {"direction", "direct", "routing", "route"}:
        return "Direction"

    if action in {"both", "signature_and_direction", "sign_and_direction"}:
        return "Both"

    return "Saved Signature"


def _phase26h_signer_to_ac_footer_row(doc, signer, idx):
    employee = signer.get("employee")
    user = signer.get("user")

    identity = _phase26c_identity_from_employee_or_user(employee=employee, user=user)

    if not identity.get("user"):
        frappe.throw(f"Signer {idx} has no valid employee/user mapping.")

    action = _phase26h_normalize_action(signer.get("action") or signer.get("action_required"))

    row = doc.append("ac_footer", {})
    row.employee = identity.get("employee")
    row.user = identity.get("user")
    row.full_name = identity.get("full_name")
    row.designation = identity.get("designation")
    row.department = identity.get("department")
    row.sign_order = int(signer.get("order") or signer.get("sign_order") or idx)
    row.action_required = action
    row.can_use_saved_signature = 1 if action in {"Saved Signature", "Both"} else int(signer.get("can_use_saved_signature") or 0)
    row.can_draw_direction = 1 if action in {"Direction", "Both"} else int(signer.get("can_draw_direction") or 0)
    row.can_write_direction_text = 1 if action in {"Direction", "Both"} else int(signer.get("can_write_direction_text") or 0)
    row.can_reject = int(signer.get("can_reject") if signer.get("can_reject") is not None else 1)
    row.status = "Draft"
    row.notes = signer.get("notes") or "Created by external signature gateway."

    return row


def _phase26h_external_request_id(system_id, external_reference):
    safe = _phase26h_sha256_text(f"{system_id}:{external_reference}")[:12]
    return f"EXTSIG-{safe}"


def _phase26h_status_from_state(state):
    counts = state.get("status_counts") or {}

    if counts.get("Rejected"):
        return "Rejected"

    if state.get("complete"):
        return "Completed"

    if counts.get("Pending") or counts.get("Waiting"):
        return "In Progress"

    return "Pending"


def _phase26h_update_gateway_request_from_state(gateway_doc):
    state = get_document_signature_state(gateway_doc.reference_doctype, gateway_doc.reference_name)
    gateway_status = _phase26h_status_from_state(state)

    gateway_doc.gateway_status = gateway_status
    gateway_doc.document_signature_requests_json = _phase26h_json_dumps([
        {
            "name": r.get("name"),
            "requested_user": r.get("requested_user"),
            "requested_employee": r.get("requested_employee"),
            "status": r.get("status"),
            "sequence_order": r.get("sequence_order"),
            "action_required": r.get("action_required"),
            "completed_at": str(r.get("completed_at") or ""),
        }
        for r in state.get("requests") or []
    ])
    gateway_doc.updated_at = now_datetime()

    if gateway_status == "Completed":
        try:
            cert = generate_internal_signature_certificate(
                gateway_doc.reference_doctype,
                gateway_doc.reference_name,
                force=0,
            )
            gateway_doc.verification_code = cert.get("verification_code")
            gateway_doc.verification_url = cert.get("verification_url")
            gateway_doc.signed_pdf = cert.get("signed_pdf")
            gateway_doc.signed_pdf_sha256 = cert.get("signed_pdf_sha256")
        except Exception as exc:
            gateway_doc.error_message = str(exc)

    gateway_doc.save(ignore_permissions=True)
    frappe.db.commit()

    return state


def _phase26h_find_gateway_request(system_name=None, external_reference=None, gateway_request=None):
    if gateway_request and frappe.db.exists(PHASE26H_REQUEST_DT, gateway_request):
        return gateway_request

    filters = {}

    if system_name:
        filters["external_system"] = system_name

    if external_reference:
        filters["external_reference"] = external_reference

    if not filters:
        return None

    rows = frappe.get_all(
        PHASE26H_REQUEST_DT,
        filters=filters,
        pluck="name",
        order_by="creation desc",
        limit=1,
    )

    return rows[0] if rows else None


@frappe.whitelist(allow_guest=True)
def external_signature_gateway_create_request(
    reference_doctype: str,
    reference_name: str,
    external_reference: str,
    signers=None,
    callback_url: str = None,
    replace_ac_footer: int = 0,
    metadata_json=None,
    external_system: str = None,
    force_update: int = 0,
):
    payload_for_auth = {
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "external_reference": external_reference,
        "signers": signers,
        "callback_url": callback_url,
        "replace_ac_footer": replace_ac_footer,
        "metadata_json": metadata_json,
        "external_system": external_system,
    }

    auth = _phase26h_authenticate_external(payload_for_auth, system_id=external_system, purpose="create")
    system = auth["system"]

    selected_callback_url = callback_url or system.default_callback_url or ""
    if selected_callback_url:
        try:
            selected_callback_url = validate_outbound_url(selected_callback_url)
        except ValueError as exc:
            frappe.throw(str(exc))

    if not external_reference:
        frappe.throw("external_reference is required.")

    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    if not frappe.db.exists(reference_doctype, reference_name):
        frappe.throw(f"Reference document not found: {reference_doctype} {reference_name}")

    _phase26h_validate_system_allowed_doctype(system, reference_doctype)
    policy = _phase26h_policy_allows_external(reference_doctype)

    meta = frappe.get_meta(reference_doctype)
    ac_field = getattr(policy, "ac_footer_fieldname", "ac_footer") or "ac_footer"

    if not meta.has_field(ac_field):
        frappe.throw(f"Reference DocType does not have Ac Footer field: {ac_field}")

    df = meta.get_field(ac_field)

    if df.fieldtype != "Table":
        frappe.throw("External gateway requires Ac Footer to be a Table field.")

    signers = _phase26h_parse_json(signers, [])

    if not isinstance(signers, list) or not signers:
        frappe.throw("signers must be a non-empty list.")

    existing_name = _phase26h_find_gateway_request(system.name, external_reference=external_reference)

    if existing_name and not int(force_update or 0):
        gateway_doc = frappe.get_doc(PHASE26H_REQUEST_DT, existing_name)
        state = _phase26h_update_gateway_request_from_state(gateway_doc)

        return {
            "ok": True,
            "phase": "26H",
            "idempotent": True,
            "gateway_request": gateway_doc.name,
            "external_reference": external_reference,
            "gateway_status": gateway_doc.gateway_status,
            "reference_doctype": gateway_doc.reference_doctype,
            "reference_name": gateway_doc.reference_name,
            "state": state,
            "verification_url": gateway_doc.verification_url,
            "signed_pdf": gateway_doc.signed_pdf if frappe.session.user != "Guest" else None,
        }

    doc = frappe.get_doc(reference_doctype, reference_name)

    if int(replace_ac_footer or 0):
        doc.set(ac_field, [])

    for idx, signer in enumerate(signers, start=1):
        if not isinstance(signer, dict):
            frappe.throw(f"Signer {idx} must be an object.")
        _phase26h_signer_to_ac_footer_row(doc, signer, idx)

    doc.save(ignore_permissions=True)
    frappe.db.commit()

    sync = sync_ac_footer_requests(reference_doctype, reference_name)
    state = get_document_signature_state(reference_doctype, reference_name)

    external_request_id = _phase26h_external_request_id(system.system_id, external_reference)

    if existing_name:
        gateway_doc = frappe.get_doc(PHASE26H_REQUEST_DT, existing_name)
        action = "updated"
    else:
        gateway_doc = frappe.new_doc(PHASE26H_REQUEST_DT)
        gateway_doc.name = external_request_id
        gateway_doc.external_request_id = external_request_id
        action = "created"

    gateway_doc.external_system = system.name
    gateway_doc.external_reference = external_reference
    gateway_doc.reference_doctype = reference_doctype
    gateway_doc.reference_name = reference_name
    gateway_doc.gateway_status = _phase26h_status_from_state(state)
    gateway_doc.signers_json = _phase26h_json_dumps(signers)
    gateway_doc.document_signature_requests_json = _phase26h_json_dumps([
        {
            "name": r.get("name"),
            "requested_user": r.get("requested_user"),
            "requested_employee": r.get("requested_employee"),
            "status": r.get("status"),
            "sequence_order": r.get("sequence_order"),
            "action_required": r.get("action_required"),
        }
        for r in state.get("requests") or []
    ])
    gateway_doc.callback_url = selected_callback_url
    gateway_doc.callback_status = "Not Sent"
    gateway_doc.request_hash = _phase26h_sha256_text(_phase26h_json_dumps(payload_for_auth))
    gateway_doc.created_via = "Admin" if auth["mode"] == "admin_session" else "External API"
    gateway_doc.created_ip = _phase26h_request_ip()
    gateway_doc.user_agent = _phase26h_user_agent()
    gateway_doc.created_at = now_datetime()
    gateway_doc.updated_at = now_datetime()
    gateway_doc.metadata_json = _phase26h_json_dumps(_phase26h_parse_json(metadata_json, {}))

    if existing_name:
        gateway_doc.save(ignore_permissions=True)
    else:
        gateway_doc.insert(ignore_permissions=True)

    frappe.db.commit()

    try:
        log_audit(
            "external_signature_gateway.request_created",
            {
                "gateway_request": gateway_doc.name,
                "external_system": system.name,
                "external_reference": external_reference,
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "signers_count": len(signers),
                "status": gateway_doc.gateway_status,
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "26H",
        "action": action,
        "gateway_request": gateway_doc.name,
        "external_system": system.name,
        "external_reference": external_reference,
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "gateway_status": gateway_doc.gateway_status,
        "sync": sync,
        "state": state,
        "callback_url": gateway_doc.callback_url,
        "request_hash": gateway_doc.request_hash,
    }


@frappe.whitelist(allow_guest=True)
def external_signature_gateway_status(
    external_reference: str = None,
    gateway_request: str = None,
    external_system: str = None,
):
    payload_for_auth = {
        "external_reference": external_reference,
        "gateway_request": gateway_request,
        "external_system": external_system,
    }

    auth = _phase26h_authenticate_external(payload_for_auth, system_id=external_system, purpose="status")
    system = auth["system"]

    gateway_name = _phase26h_find_gateway_request(
        system.name,
        external_reference=external_reference,
        gateway_request=gateway_request,
    )

    if not gateway_name:
        return {
            "ok": True,
            "found": False,
            "external_reference": external_reference,
            "gateway_request": gateway_request,
        }

    gateway_doc = frappe.get_doc(PHASE26H_REQUEST_DT, gateway_name)
    state = _phase26h_update_gateway_request_from_state(gateway_doc)

    out = {
        "ok": True,
        "found": True,
        "phase": "26H",
        "gateway_request": gateway_doc.name,
        "external_system": gateway_doc.external_system,
        "external_reference": gateway_doc.external_reference,
        "reference_doctype": gateway_doc.reference_doctype,
        "reference_name": gateway_doc.reference_name,
        "gateway_status": gateway_doc.gateway_status,
        "state": state,
        "verification_code": gateway_doc.verification_code,
        "verification_url": gateway_doc.verification_url,
        "signed_pdf_sha256": gateway_doc.signed_pdf_sha256,
        "callback_status": gateway_doc.callback_status,
        "callback_attempts": gateway_doc.callback_attempts,
        "updated_at": str(gateway_doc.updated_at or ""),
    }

    if frappe.session.user != "Guest":
        out["signed_pdf"] = gateway_doc.signed_pdf

    return out


def _phase26h_callback_payload(gateway_doc):
    status = external_signature_gateway_status(
        external_reference=gateway_doc.external_reference,
        gateway_request=gateway_doc.name,
        external_system=gateway_doc.external_system,
    )

    return {
        "event": "internal_signature.gateway_status",
        "gateway_request": gateway_doc.name,
        "external_system": gateway_doc.external_system,
        "external_reference": gateway_doc.external_reference,
        "reference_doctype": gateway_doc.reference_doctype,
        "reference_name": gateway_doc.reference_name,
        "gateway_status": gateway_doc.gateway_status,
        "status": status,
        "sent_at": str(now_datetime()),
    }




def _phase26h_after_internal_request_completed(reference_doctype, reference_name):
    if not frappe.db.exists("DocType", PHASE26H_REQUEST_DT):
        return []

    rows = frappe.get_all(
        PHASE26H_REQUEST_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
        },
        pluck="name",
        limit_page_length=50,
    )

    updated = []

    for name in rows:
        try:
            gateway_doc = frappe.get_doc(PHASE26H_REQUEST_DT, name)
            _phase26h_update_gateway_request_from_state(gateway_doc)
            updated.append({
                "gateway_request": name,
                "gateway_status": gateway_doc.gateway_status,
            })

            if gateway_doc.gateway_status in {"Completed", "Rejected"} and gateway_doc.callback_url:
                try:
                    send_external_signature_gateway_callback(name)
                except Exception:
                    pass
        except Exception:
            pass

    return updated


if not globals().get("_phase26h_original_finalize_request") and globals().get("_phase26d_finalize_request"):
    _phase26h_original_finalize_request = _phase26d_finalize_request


if globals().get("_phase26h_original_finalize_request"):
    def _phase26d_finalize_request(req, status: str, payload: dict):
        result = _phase26h_original_finalize_request(req, status, payload)

        try:
            result["external_gateway_updates"] = _phase26h_after_internal_request_completed(
                req.reference_doctype,
                req.reference_name,
            )
        except Exception:
            result["external_gateway_updates"] = []

        return result


@frappe.whitelist()
def phase26h_create_gateway_demo_request():
    _phase26h_require_admin()
    phase26h_install_external_gateway()

    system = admin_upsert_external_signature_system(
        system_id="demo-external-system",
        system_name="Demo External System",
        allowed_doctypes_json=["Internal Signature Demo Document"],
        default_callback_url="dry-run://callback",
        require_hmac=1,
        is_active=1,
        regenerate_secret=0,
        notes="Demo system for Phase 26H external gateway.",
    )

    # Create a fresh demo document without Ac Footer, then let the external gateway fill Ac Footer.
    phase26c_install_document_signature_requests()
    _phase26c_ensure_demo_policy()

    doc = frappe.new_doc(PHASE26C_DEMO_DT)
    doc.name = _phase26c_fix3_next_demo_name() if globals().get("_phase26c_fix3_next_demo_name") else None
    doc.title = "Phase 26H External Gateway Demo"
    doc.content = """
        <h2>External Gateway Demo</h2>
        <p>This document was created to test external API request creation.</p>
        <p>The signer was inserted through the External Signature Gateway.</p>
    """
    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    identity = _phase26c_identity_from_employee_or_user(user=frappe.session.user)

    external_reference = f"EXT-DEMO-{doc.name}"

    created = external_signature_gateway_create_request(
        external_system="demo-external-system",
        external_reference=external_reference,
        reference_doctype=PHASE26C_DEMO_DT,
        reference_name=doc.name,
        signers=[
            {
                "user": frappe.session.user,
                "employee": identity.get("employee"),
                "order": 1,
                "action": "Both",
                "can_reject": 1,
            }
        ],
        callback_url="dry-run://callback",
        replace_ac_footer=1,
        metadata_json={
            "demo": True,
            "created_from": "phase26h_create_gateway_demo_request",
        },
        force_update=1,
    )

    status = external_signature_gateway_status(
        external_system="demo-external-system",
        external_reference=external_reference,
    )

    return {
        "ok": True,
        "phase": "26H",
        "external_system": system,
        "demo_document": {
            "doctype": doc.doctype,
            "name": doc.name,
            "url": f"/app/{frappe.scrub(doc.doctype).replace('_', '-')}/{doc.name}",
        },
        "created": created,
        "status": status,
        "action_url": (status.get("state", {}).get("requests") or [{}])[0].get("action_url"),
    }


@frappe.whitelist()
def phase26h_external_gateway_health():
    phase26h_install_external_gateway()

    counts = {}
    for dt in [PHASE26H_SYSTEM_DT, PHASE26H_REQUEST_DT]:
        counts[dt] = frappe.db.count(dt) if frappe.db.exists("DocType", dt) else 0

    demo = None
    try:
        if _phase26h_is_admin():
            demo = phase26h_create_gateway_demo_request()
    except Exception as exc:
        demo = {
            "ok": False,
            "error": str(exc),
        }

    return {
        "ok": True,
        "phase": "26H",
        "doctypes": {
            PHASE26H_SYSTEM_DT: bool(frappe.db.exists("DocType", PHASE26H_SYSTEM_DT)),
            PHASE26H_REQUEST_DT: bool(frappe.db.exists("DocType", PHASE26H_REQUEST_DT)),
        },
        "counts": counts,
        "demo": demo,
        "endpoints": {
            "create_request": "/api/method/surhan_signature.api.external_signature_gateway_create_request",
            "status": "/api/method/surhan_signature.api.external_signature_gateway_status",
            "verify": "/internal-sign-verify?code=<verification_code>",
            "docs": "/external-signature-gateway",
        },
        "ready": bool(
            frappe.db.exists("DocType", PHASE26H_SYSTEM_DT)
            and frappe.db.exists("DocType", PHASE26H_REQUEST_DT)
        ),
    }


# Phase 26I: External Gateway Security + End-to-End Tests.
import json as _phase26i_json
import time as _phase26i_time


def _phase26i_json_dumps(data):
    return _phase26i_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _phase26i_deep_contains_key(value, keys):
    keys = set(keys or [])

    if isinstance(value, dict):
        for k, v in value.items():
            if k in keys:
                return True
            if _phase26i_deep_contains_key(v, keys):
                return True

    elif isinstance(value, list):
        for item in value:
            if _phase26i_deep_contains_key(item, keys):
                return True

    return False


def _phase26i_record(tests, name, passed, details=None):
    tests.append({
        "name": name,
        "passed": bool(passed),
        "details": details or {},
    })


def _phase26i_validate_hmac_direct(system_id, raw_body, timestamp, signature):
    if not frappe.db.exists(PHASE26H_SYSTEM_DT, system_id):
        return {
            "ok": True,
            "valid": False,
            "reason": "system_not_found",
        }

    system = frappe.get_doc(PHASE26H_SYSTEM_DT, system_id)
    secret = _phase26h_get_encrypted_secret(system.name)

    try:
        ts = int(timestamp)
    except Exception:
        return {
            "ok": True,
            "valid": False,
            "reason": "invalid_timestamp",
        }

    expired = abs(int(_phase26i_time.time()) - ts) > 300

    expected = _phase26h_hmac_sha256(secret, f"{timestamp}.{raw_body}")
    provided = str(signature or "").replace("sha256=", "").strip().lower()

    valid = bool(
        not expired
        and _phase26h_hmac.compare_digest(provided, expected)
    )

    return {
        "ok": True,
        "valid": valid,
        "expired": expired,
        "expected_prefix": expected[:12],
        "provided_prefix": provided[:12],
    }


def _phase26i_get_first_request_name(state):
    try:
        requests = state.get("requests") or []
        return requests[0].get("name") if requests else None
    except Exception:
        return None


def _phase26i_add_action_urls_to_gateway_status(out):
    try:
        state = out.get("state") or {}
        for r in state.get("requests") or []:
            if r.get("name"):
                r["action_url"] = f"/document-sign-action?request={r.get('name')}"
            if out.get("reference_doctype") and out.get("reference_name"):
                r["document_url"] = f"/app/{frappe.scrub(out.get('reference_doctype')).replace('_', '-')}/{out.get('reference_name')}"
    except Exception:
        pass

    return out


if not globals().get("_phase26i_original_external_signature_gateway_status") and globals().get("external_signature_gateway_status"):
    _phase26i_original_external_signature_gateway_status = external_signature_gateway_status


@frappe.whitelist(allow_guest=True)
def external_signature_gateway_status(
    external_reference: str = None,
    gateway_request: str = None,
    external_system: str = None,
):
    out = _phase26i_original_external_signature_gateway_status(
        external_reference=external_reference,
        gateway_request=gateway_request,
        external_system=external_system,
    )

    if isinstance(out, dict):
        out = _phase26i_add_action_urls_to_gateway_status(out)
        if frappe.session.user == "Guest":
            from surhan_signature.security.file_security import assert_public_payload_safe

            assert_public_payload_safe(out)

    return out


@frappe.whitelist()
def phase26i_external_gateway_security_tests():
    if not _phase26h_is_admin():
        frappe.throw("Only Internal Signature Administrator can run Phase 26I tests.")

    phase26h_install_external_gateway()

    tests = []

    system_id = "phase26i-test-system"

    system_result = admin_upsert_external_signature_system(
        system_id=system_id,
        system_name="Phase 26I Test External System",
        allowed_doctypes_json=["Internal Signature Demo Document"],
        default_callback_url="dry-run://phase26i-callback",
        require_hmac=1,
        is_active=1,
        regenerate_secret=1,
        notes="Temporary system generated by Phase 26I security tests.",
    )

    api_secret = system_result.get("api_secret")
    system_result_redacted = dict(system_result)
    if "api_secret" in system_result_redacted:
        system_result_redacted["api_secret"] = "***REDACTED***"

    _phase26i_record(
        tests,
        "External test system created with API key and secret",
        bool(system_result.get("gateway_api_key") and api_secret),
        system_result_redacted,
    )

    raw_body = _phase26i_json_dumps({
        "external_reference": "HMAC-DIRECT-TEST",
        "reference_doctype": "Internal Signature Demo Document",
    })
    timestamp = str(int(_phase26i_time.time()))
    correct_signature = "sha256=" + _phase26h_hmac_sha256(api_secret, f"{timestamp}.{raw_body}")
    wrong_signature = "sha256=" + ("0" * 64)
    expired_timestamp = str(int(_phase26i_time.time()) - 1000)
    expired_signature = "sha256=" + _phase26h_hmac_sha256(api_secret, f"{expired_timestamp}.{raw_body}")

    hmac_ok = _phase26i_validate_hmac_direct(system_id, raw_body, timestamp, correct_signature)
    hmac_bad = _phase26i_validate_hmac_direct(system_id, raw_body, timestamp, wrong_signature)
    hmac_expired = _phase26i_validate_hmac_direct(system_id, raw_body, expired_timestamp, expired_signature)

    _phase26i_record(tests, "Valid HMAC accepted", hmac_ok.get("valid") is True, hmac_ok)
    _phase26i_record(tests, "Invalid HMAC rejected", hmac_bad.get("valid") is False, hmac_bad)
    _phase26i_record(tests, "Expired HMAC rejected", hmac_expired.get("valid") is False and hmac_expired.get("expired") is True, hmac_expired)

    phase26c_install_document_signature_requests()
    _phase26c_ensure_demo_policy()

    doc = frappe.new_doc(PHASE26C_DEMO_DT)
    if globals().get("_phase26c_fix3_next_demo_name"):
        doc.name = _phase26c_fix3_next_demo_name()
    doc.title = "Phase 26I External Gateway Security Demo"
    doc.content = """
        <h2>Phase 26I External Gateway Security Demo</h2>
        <p>This document validates HMAC, gateway creation, idempotency, signing, PDF verification, and dry-run callback.</p>
    """
    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    identity = _phase26c_identity_from_employee_or_user(user=frappe.session.user)
    external_reference = f"PHASE26I-{doc.name}"

    created = external_signature_gateway_create_request(
        external_system=system_id,
        external_reference=external_reference,
        reference_doctype=PHASE26C_DEMO_DT,
        reference_name=doc.name,
        signers=[
            {
                "user": frappe.session.user,
                "employee": identity.get("employee"),
                "order": 1,
                "action": "Both",
                "can_reject": 1,
            }
        ],
        callback_url="dry-run://phase26i-callback",
        replace_ac_footer=1,
        metadata_json={
            "phase": "26I",
            "test": "end_to_end_gateway",
        },
        force_update=1,
    )

    _phase26i_record(
        tests,
        "External gateway request created",
        bool(created.get("ok") and created.get("gateway_status") in {"Pending", "In Progress"}),
        {
            "gateway_request": created.get("gateway_request"),
            "gateway_status": created.get("gateway_status"),
            "reference": f"{created.get('reference_doctype')} / {created.get('reference_name')}",
        },
    )

    status_1 = external_signature_gateway_status(
        external_system=system_id,
        external_reference=external_reference,
    )

    _phase26i_record(
        tests,
        "Gateway status lookup returns In Progress",
        bool(status_1.get("found") and status_1.get("gateway_status") in {"Pending", "In Progress"}),
        {
            "gateway_request": status_1.get("gateway_request"),
            "gateway_status": status_1.get("gateway_status"),
            "request_count": len((status_1.get("state") or {}).get("requests") or []),
        },
    )

    repeated = external_signature_gateway_create_request(
        external_system=system_id,
        external_reference=external_reference,
        reference_doctype=PHASE26C_DEMO_DT,
        reference_name=doc.name,
        signers=[
            {
                "user": frappe.session.user,
                "employee": identity.get("employee"),
                "order": 1,
                "action": "Both",
                "can_reject": 1,
            }
        ],
        callback_url="dry-run://phase26i-callback",
        replace_ac_footer=0,
        metadata_json={
            "phase": "26I",
            "test": "idempotency",
        },
        force_update=0,
    )

    _phase26i_record(
        tests,
        "Idempotency prevents duplicate external_reference",
        bool(repeated.get("idempotent") and repeated.get("gateway_request") == created.get("gateway_request")),
        {
            "first_gateway_request": created.get("gateway_request"),
            "second_gateway_request": repeated.get("gateway_request"),
            "idempotent": repeated.get("idempotent"),
        },
    )

    unauthorized_blocked = False
    unauthorized_error = None

    try:
        external_signature_gateway_create_request(
            external_system=system_id,
            external_reference=external_reference + "-BAD",
            reference_doctype="User",
            reference_name="Administrator",
            signers=[
                {
                    "user": frappe.session.user,
                    "order": 1,
                    "action": "Saved Signature",
                }
            ],
            callback_url="dry-run://phase26i-callback",
            replace_ac_footer=0,
            metadata_json={"phase": "26I", "test": "unauthorized_doctype"},
            force_update=1,
        )
    except Exception as exc:
        unauthorized_blocked = True
        unauthorized_error = str(exc)

    _phase26i_record(
        tests,
        "Unauthorized DocType blocked",
        unauthorized_blocked,
        {"error": unauthorized_error},
    )

    request_name = _phase26i_get_first_request_name(status_1.get("state") or {})

    signed = apply_saved_signature_request(request_name)

    _phase26i_record(
        tests,
        "Pending external request signed with saved signature",
        bool(signed.get("ok") and signed.get("status") == "Signed"),
        {
            "request": request_name,
            "status": signed.get("status"),
            "reference": f"{signed.get('reference_doctype')} / {signed.get('reference_name')}",
        },
    )

    status_2 = external_signature_gateway_status(
        external_system=system_id,
        external_reference=external_reference,
    )

    _phase26i_record(
        tests,
        "Gateway status becomes Completed after signing",
        bool(status_2.get("gateway_status") == "Completed"),
        {
            "gateway_request": status_2.get("gateway_request"),
            "gateway_status": status_2.get("gateway_status"),
            "verification_url": status_2.get("verification_url"),
            "signed_pdf_sha256": status_2.get("signed_pdf_sha256"),
        },
    )

    cert_verify = None
    if status_2.get("verification_code"):
        cert_verify = verify_internal_signature_certificate(status_2.get("verification_code"))

    _phase26i_record(
        tests,
        "Generated internal certificate verifies successfully",
        bool(cert_verify and cert_verify.get("valid")),
        cert_verify or {"reason": "missing verification_code"},
    )

    callback = send_external_signature_gateway_callback(status_2.get("gateway_request"))

    _phase26i_record(
        tests,
        "Webhook callback dry-run stored payload",
        bool(callback.get("ok") and callback.get("callback_status") in {"Dry Run", "Sent"}),
        callback,
    )

    final_status = external_signature_gateway_status(
        external_system=system_id,
        external_reference=external_reference,
    )

    raw_signature_leak = _phase26i_deep_contains_key(
        final_status,
        {
            "signature_png",
            "signature_svg",
            "signature_vector_json",
            "signature_svg_encrypted",
            "signature_vector_json_encrypted",
            "hmac_secret_encrypted",
            "api_secret",
        },
    )

    _phase26i_record(
        tests,
        "External status does not expose raw signature or secrets",
        raw_signature_leak is False,
        {
            "raw_signature_or_secret_key_found": raw_signature_leak,
            "gateway_request": final_status.get("gateway_request"),
        },
    )

    passed = sum(1 for t in tests if t.get("passed"))
    failed = len(tests) - passed

    report = {
        "ok": failed == 0,
        "phase": "26I",
        "summary": {
            "total": len(tests),
            "passed": passed,
            "failed": failed,
        },
        "system": {
            "system_id": system_id,
            "gateway_api_key": system_result.get("gateway_api_key"),
            "api_secret": "***REDACTED***",
        },
        "demo": {
            "doctype": doc.doctype,
            "name": doc.name,
            "document_url": f"/app/{frappe.scrub(doc.doctype).replace('_', '-')}/{doc.name}",
            "external_reference": external_reference,
            "gateway_request": final_status.get("gateway_request"),
            "gateway_status": final_status.get("gateway_status"),
            "verification_url": final_status.get("verification_url"),
            "signed_pdf": final_status.get("signed_pdf"),
            "signed_pdf_sha256": final_status.get("signed_pdf_sha256"),
            "callback_status": final_status.get("callback_status"),
        },
        "tests": tests,
    }

    return report


@frappe.whitelist()
def export_phase26i_gateway_security_report_json():
    report = phase26i_external_gateway_security_tests()
    content = _phase26i_json_dumps(report).encode("utf-8")
    sha = _phase26h_sha256_text(content.decode("utf-8"))

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26i-external-gateway-security-report-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26I",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "summary": report.get("summary"),
    }


@frappe.whitelist()
def phase26i_gateway_security_health():
    report = phase26i_external_gateway_security_tests()

    return {
        "ok": True,
        "phase": "26I",
        "ready": bool(report.get("ok")),
        "summary": report.get("summary"),
        "demo": report.get("demo"),
        "failed_tests": [t for t in report.get("tests") or [] if not t.get("passed")],
    }


# Phase 26I-FIX1: safe callback update to avoid TimestampMismatchError.
@frappe.whitelist()
def send_external_signature_gateway_callback(gateway_request: str):
    _phase26h_require_admin()

    if not gateway_request or not frappe.db.exists(PHASE26H_REQUEST_DT, gateway_request):
        frappe.throw("Gateway request not found.")

    gateway_doc = frappe.get_doc(PHASE26H_REQUEST_DT, gateway_request)

    if not gateway_doc.callback_url:
        return {
            "ok": True,
            "sent": False,
            "reason": "No callback URL configured.",
            "gateway_request": gateway_request,
        }

    system = frappe.get_doc(PHASE26H_SYSTEM_DT, gateway_doc.external_system)

    if not int(system.allow_callback_delivery or 0):
        frappe.throw("Callback delivery is disabled for this external system.")

    # This may update the same gateway request internally, so do not save the old doc after this.
    payload = _phase26h_callback_payload(gateway_doc)
    body = _phase26h_json_dumps(payload)

    # Reload fresh values after payload/status update.
    gateway_doc = frappe.get_doc(PHASE26H_REQUEST_DT, gateway_request)

    callback_attempts = int(gateway_doc.callback_attempts or 0) + 1
    callback_status = "Not Sent"
    callback_response = ""

    if not str(gateway_doc.callback_url).startswith("http"):
        callback_status = "Dry Run"
        callback_response = body[:1000]

        frappe.db.set_value(
            PHASE26H_REQUEST_DT,
            gateway_request,
            {
                "callback_attempts": callback_attempts,
                "last_callback_at": now_datetime(),
                "callback_status": callback_status,
                "callback_response": callback_response,
            },
            update_modified=True,
        )
        frappe.db.commit()

        return {
            "ok": True,
            "sent": False,
            "dry_run": True,
            "gateway_request": gateway_request,
            "callback_status": callback_status,
            "payload": payload,
        }

    secret = _phase26h_get_encrypted_secret(system.name)
    timestamp = _phase26h_now_ts()
    signature = _phase26h_hmac_sha256(secret, f"{timestamp}.{body}")

    try:
        response = safe_post(
            gateway_doc.callback_url,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Surhan-Timestamp": timestamp,
                "X-Surhan-Signature": "sha256=" + signature,
                "X-Surhan-System": system.system_id,
            },
            timeout=10,
        )
        resp_body = response.text[:900]
        callback_status = "Sent" if 200 <= response.status_code < 300 else "Failed"
        callback_response = f"HTTP {response.status_code}: {resp_body}"
        sent = callback_status == "Sent"
        response.close()
    except Exception as exc:
        callback_status = "Failed"
        callback_response = str(exc)[:1000]
        sent = False

    frappe.db.set_value(
        PHASE26H_REQUEST_DT,
        gateway_request,
        {
            "callback_attempts": callback_attempts,
            "last_callback_at": now_datetime(),
            "callback_status": callback_status,
            "callback_response": callback_response,
        },
        update_modified=True,
    )
    frappe.db.commit()

    return {
        "ok": True,
        "sent": sent,
        "gateway_request": gateway_request,
        "callback_status": callback_status,
        "callback_response": callback_response,
    }


@frappe.whitelist()
def phase26i_fix1_resume_security_tests():
    report = phase26i_external_gateway_security_tests()
    export = export_phase26i_gateway_security_report_json()

    return {
        "ok": bool(report.get("ok")),
        "phase_fix": "26I-FIX1",
        "summary": report.get("summary"),
        "demo": report.get("demo"),
        "failed_tests": [t for t in report.get("tests") or [] if not t.get("passed")],
        "export": export,
        "ready": bool(report.get("ok") and (report.get("summary") or {}).get("failed") == 0),
    }


# Phase 26J: External Gateway Operations Console.
import json as _phase26j_json
import hashlib as _phase26j_hashlib


def _phase26j_request_dt():
    return globals().get("PHASE26H_REQUEST_DT", "Internal Signature External Request")


def _phase26j_system_dt():
    return globals().get("PHASE26H_SYSTEM_DT", "Internal Signature External System")


def _phase26j_cert_dt():
    return globals().get("PHASE26G_CERT_DT", "Internal Signature Certificate")


def _phase26j_json_dumps(data):
    return _phase26j_json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        default=str,
    )


def _phase26j_sha256(data):
    if not isinstance(data, str):
        data = _phase26j_json_dumps(data)
    return _phase26j_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26j_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
        "Internal Signature API User",
    }))


def _phase26j_require_admin():
    if not _phase26j_is_admin():
        frappe.throw("Only Internal Signature Administrator / Manager / Auditor can access the external gateway console.")


def _phase26j_doc_url(doctype, name):
    if not doctype or not name:
        return None
    return f"/app/{frappe.scrub(doctype).replace('_', '-')}/{name}"


def _phase26j_action_url(request_name):
    if not request_name:
        return None
    return f"/document-sign-action?request={request_name}"




@frappe.whitelist()
def phase26j_external_gateway_summary():
    _phase26j_require_admin()

    request_dt = _phase26j_request_dt()
    system_dt = _phase26j_system_dt()
    cert_dt = _phase26j_cert_dt()

    installed = {
        "external_system": bool(frappe.db.exists("DocType", system_dt)),
        "external_request": bool(frappe.db.exists("DocType", request_dt)),
        "certificate": bool(frappe.db.exists("DocType", cert_dt)),
    }

    systems = []
    if installed["external_system"]:
        systems = frappe.get_all(
            system_dt,
            fields=[
                "name",
                "system_id",
                "system_name",
                "is_active",
                "gateway_api_key",
                "require_hmac",
                "allow_create_requests",
                "allow_status_lookup",
                "allow_callback_delivery",
                "last_used_at",
                "last_used_ip",
            ],
            order_by="modified desc",
            limit_page_length=100,
        )

    counts = {
        "total_systems": len(systems),
        "active_systems": sum(1 for s in systems if int(s.get("is_active") or 0)),
        "total_requests": frappe.db.count(request_dt) if installed["external_request"] else 0,
        "total_certificates": frappe.db.count(cert_dt) if installed["certificate"] else 0,
    }

    gateway_status_counts = _phase26j_status_counts(request_dt, "gateway_status") if installed["external_request"] else {}
    callback_status_counts = _phase26j_status_counts(request_dt, "callback_status") if installed["external_request"] else {}
    certificate_status_counts = _phase26j_status_counts(cert_dt, "certificate_status") if installed["certificate"] else {}

    recent_requests = phase26j_external_gateway_requests(limit=10).get("items", []) if installed["external_request"] else []

    blockers = []

    if not installed["external_system"]:
        blockers.append("Internal Signature External System DocType is missing.")

    if not installed["external_request"]:
        blockers.append("Internal Signature External Request DocType is missing.")

    warnings = []

    if gateway_status_counts.get("Error"):
        warnings.append(f"{gateway_status_counts.get('Error')} external request(s) are in Error status.")

    if callback_status_counts.get("Failed"):
        warnings.append(f"{callback_status_counts.get('Failed')} callback(s) failed.")

    if gateway_status_counts.get("In Progress"):
        warnings.append(f"{gateway_status_counts.get('In Progress')} external request(s) are still In Progress.")

    return {
        "ok": True,
        "phase": "26J",
        "installed": installed,
        "counts": counts,
        "gateway_status_counts": gateway_status_counts,
        "callback_status_counts": callback_status_counts,
        "certificate_status_counts": certificate_status_counts,
        "systems": systems,
        "recent_requests": recent_requests,
        "blockers": blockers,
        "warnings": warnings,
        "ready": bool(not blockers),
        "generated_at": str(now_datetime()),
    }


@frappe.whitelist()
def phase26j_external_gateway_requests(
    gateway_status: str = None,
    callback_status: str = None,
    external_system: str = None,
    limit: int = 50,
):
    _phase26j_require_admin()

    request_dt = _phase26j_request_dt()

    if not frappe.db.exists("DocType", request_dt):
        return {
            "ok": True,
            "count": 0,
            "items": [],
            "reason": f"{request_dt} is not installed.",
        }

    filters = {}

    if gateway_status:
        filters["gateway_status"] = gateway_status

    if callback_status:
        filters["callback_status"] = callback_status

    if external_system:
        filters["external_system"] = external_system

    rows = frappe.get_all(
        request_dt,
        filters=filters,
        fields=[
            "name",
            "external_request_id",
            "external_system",
            "external_reference",
            "reference_doctype",
            "reference_name",
            "gateway_status",
            "callback_status",
            "callback_attempts",
            "last_callback_at",
            "verification_code",
            "verification_url",
            "signed_pdf",
            "signed_pdf_sha256",
            "created_at",
            "updated_at",
            "modified",
        ],
        order_by="modified desc",
        limit_page_length=int(limit or 50),
    )

    for r in rows:
        r["document_url"] = _phase26j_doc_url(r.get("reference_doctype"), r.get("reference_name"))
        r["console_detail_method"] = "surhan_signature.api.phase26j_external_gateway_request_detail"

        if r.get("verification_code"):
            r["internal_verify_url"] = f"/internal-sign-verify?code={r.get('verification_code')}"

        try:
            state = get_document_signature_state(r.get("reference_doctype"), r.get("reference_name"))
            r["signature_state"] = {
                "count": state.get("count"),
                "complete": state.get("complete"),
                "status_counts": state.get("status_counts"),
            }

            pending = [
                x for x in (state.get("requests") or [])
                if x.get("status") == "Pending"
            ]

            if pending:
                r["first_pending_signature_request"] = pending[0].get("name")
                r["first_pending_action_url"] = _phase26j_action_url(pending[0].get("name"))

        except Exception as exc:
            r["signature_state_error"] = str(exc)

    return {
        "ok": True,
        "phase": "26J",
        "count": len(rows),
        "filters": filters,
        "items": rows,
    }


@frappe.whitelist()
def phase26j_external_gateway_request_detail(gateway_request: str):
    _phase26j_require_admin()

    request_dt = _phase26j_request_dt()

    if not gateway_request or not frappe.db.exists(request_dt, gateway_request):
        frappe.throw("External gateway request not found.")

    doc = frappe.get_doc(request_dt, gateway_request)

    status = None
    try:
        status = external_signature_gateway_status(
            external_system=doc.external_system,
            external_reference=doc.external_reference,
            gateway_request=doc.name,
        )
    except Exception as exc:
        status = {
            "ok": False,
            "error": str(exc),
        }

    certificate = None
    if doc.verification_code:
        try:
            certificate = verify_internal_signature_certificate(doc.verification_code)
        except Exception as exc:
            certificate = {
                "ok": False,
                "error": str(exc),
            }

    callbacks_available = bool(doc.callback_url)

    out = doc.as_dict()

    # No secrets exist on request doc, but keep the response intentionally sanitized.
    for key in [
        "hmac_secret_encrypted",
        "api_secret",
        "signature_svg",
        "signature_vector_json",
        "signature_svg_encrypted",
        "signature_vector_json_encrypted",
    ]:
        out.pop(key, None)

    out["document_url"] = _phase26j_doc_url(doc.reference_doctype, doc.reference_name)
    out["internal_verify_url"] = f"/internal-sign-verify?code={doc.verification_code}" if doc.verification_code else None
    out["signed_print_url"] = f"/signed-print?doctype={frappe.utils.quote(doc.reference_doctype)}&name={frappe.utils.quote(doc.reference_name)}"
    out["callbacks_available"] = callbacks_available

    return {
        "ok": True,
        "phase": "26J",
        "gateway_request": gateway_request,
        "request": out,
        "live_status": status,
        "certificate": certificate,
    }


@frappe.whitelist()
def phase26j_retry_external_callback(gateway_request: str):
    _phase26j_require_admin()

    result = send_external_signature_gateway_callback(gateway_request)

    detail = phase26j_external_gateway_request_detail(gateway_request)

    return {
        "ok": True,
        "phase": "26J",
        "callback_result": result,
        "detail": detail,
    }


@frappe.whitelist()
def phase26j_verify_gateway_certificate(gateway_request: str):
    _phase26j_require_admin()

    request_dt = _phase26j_request_dt()

    if not gateway_request or not frappe.db.exists(request_dt, gateway_request):
        frappe.throw("External gateway request not found.")

    doc = frappe.get_doc(request_dt, gateway_request)

    if not doc.verification_code:
        return {
            "ok": True,
            "valid": False,
            "reason": "No verification code generated yet.",
            "gateway_request": gateway_request,
        }

    return verify_internal_signature_certificate(doc.verification_code)


@frappe.whitelist()
def phase26j_generate_missing_certificate(gateway_request: str):
    _phase26j_require_admin()

    request_dt = _phase26j_request_dt()

    if not gateway_request or not frappe.db.exists(request_dt, gateway_request):
        frappe.throw("External gateway request not found.")

    doc = frappe.get_doc(request_dt, gateway_request)

    state = get_document_signature_state(doc.reference_doctype, doc.reference_name)

    if not state.get("complete"):
        frappe.throw("Cannot generate certificate because signature workflow is not complete.")

    cert = generate_internal_signature_certificate(
        doc.reference_doctype,
        doc.reference_name,
        force=0,
    )

    frappe.db.set_value(
        request_dt,
        gateway_request,
        {
            "verification_code": cert.get("verification_code"),
            "verification_url": cert.get("verification_url"),
            "signed_pdf": cert.get("signed_pdf"),
            "signed_pdf_sha256": cert.get("signed_pdf_sha256"),
            "gateway_status": "Completed",
            "updated_at": now_datetime(),
        },
        update_modified=True,
    )
    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26J",
        "gateway_request": gateway_request,
        "certificate": cert,
    }


@frappe.whitelist()
def phase26j_export_external_console_snapshot_json():
    _phase26j_require_admin()

    snapshot = {
        "summary": phase26j_external_gateway_summary(),
        "requests": phase26j_external_gateway_requests(limit=200),
    }

    sha = _phase26j_sha256(snapshot)
    content = _phase26j_json_dumps(snapshot).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26j-external-gateway-console-snapshot-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26J",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "summary": snapshot.get("summary", {}).get("counts"),
    }


@frappe.whitelist()
def phase26j_external_console_health():
    summary = phase26j_external_gateway_summary()
    export = None

    try:
        export = phase26j_export_external_console_snapshot_json()
    except Exception as exc:
        export = {
            "ok": False,
            "error": str(exc),
        }

    return {
        "ok": True,
        "phase": "26J",
        "ready": bool(summary.get("ready")),
        "summary": summary,
        "export": export,
        "console_url": "/external-signature-console",
    }


# Phase 26J-FIX1: Frappe v16-safe status count helper.
def _phase26j_status_counts(doctype, fieldname):
    if not frappe.db.exists("DocType", doctype):
        return {}

    # Validate field exists to avoid unsafe SQL interpolation.
    meta = frappe.get_meta(doctype)
    if not meta.has_field(fieldname):
        return {}

    table = f"tab{doctype}"

    rows = frappe.db.sql(
        f"""
        SELECT `{fieldname}` AS status_value, COUNT(`name`) AS count_value
        FROM `{table}`
        GROUP BY `{fieldname}`
        """,
        as_dict=True,
    )

    return {
        (r.get("status_value") or "Blank"): int(r.get("count_value") or 0)
        for r in rows
    }


@frappe.whitelist()
def phase26j_fix1_resume_external_console():
    summary = phase26j_external_gateway_summary()
    requests = phase26j_external_gateway_requests(limit=10)
    health = phase26j_external_console_health()

    return {
        "ok": True,
        "phase_fix": "26J-FIX1",
        "summary_ready": bool(summary.get("ready")),
        "request_count": requests.get("count"),
        "health_ready": bool(health.get("ready")),
        "summary": summary,
        "requests": requests,
        "health": health,
    }


# Phase 26K: Roll out Ac Footer internal signatures to real ERPNext/HRMS DocTypes.
import json as _phase26k_json
import hashlib as _phase26k_hashlib


PHASE26K_COMMON_DOCTYPES = [
    "Material Request",
    "Purchase Order",
    "Purchase Receipt",
    "Purchase Invoice",
    "Supplier Quotation",
    "Request for Quotation",
    "Sales Order",
    "Delivery Note",
    "Sales Invoice",
    "Quotation",
    "Payment Entry",
    "Journal Entry",
    "Expense Claim",
    "Employee Advance",
    "Leave Application",
    "Job Offer",
    "Employee Onboarding",
    "Employee Separation",
    "Training Event",
    "Issue",
    "Project",
    "Task",
]


def _phase26k_json_dumps(data):
    return _phase26k_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase26k_sha256(data):
    if not isinstance(data, str):
        data = _phase26k_json_dumps(data)
    return _phase26k_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26k_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase26k_require_admin():
    if not _phase26k_is_admin():
        frappe.throw("Only Internal Signature Administrator / Manager can roll out signatures to DocTypes.")


def _phase26k_field_exists(reference_doctype, fieldname):
    try:
        return bool(frappe.get_meta(reference_doctype).has_field(fieldname))
    except Exception:
        return False


def _phase26k_last_fieldname(reference_doctype):
    try:
        meta = frappe.get_meta(reference_doctype)
        fields = [df.fieldname for df in meta.fields if df.fieldname]
        return fields[-1] if fields else None
    except Exception:
        return None


def _phase26k_create_or_update_custom_field(reference_doctype, fieldname, props):
    if not frappe.db.exists("DocType", "Custom Field"):
        frappe.throw("Custom Field DocType is not available.")

    cf_name = f"{reference_doctype}-{fieldname}"
    existing = frappe.db.exists("Custom Field", cf_name)

    if existing:
        cf = frappe.get_doc("Custom Field", existing)
        action = "updated"
    else:
        cf = frappe.new_doc("Custom Field")
        cf.dt = reference_doctype
        cf.fieldname = fieldname
        action = "created"

    for k, v in props.items():
        if hasattr(cf, k):
            setattr(cf, k, v)

    if existing:
        cf.save(ignore_permissions=True)
    else:
        cf.insert(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache(doctype=reference_doctype)

    try:
        frappe.db.updatedb(reference_doctype)
    except Exception:
        pass

    return {
        "fieldname": fieldname,
        "custom_field": cf.name,
        "action": action,
    }


def _phase26k_ensure_ac_footer_fields(reference_doctype):
    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    if not frappe.db.exists("DocType", PHASE26C_AC_FOOTER_CHILD_DT):
        frappe.throw("AC Footer Signer child table is not installed.")

    created = []

    last_field = _phase26k_last_fieldname(reference_doctype)

    if not _phase26k_field_exists(reference_doctype, "ac_footer_section"):
        created.append(_phase26k_create_or_update_custom_field(
            reference_doctype,
            "ac_footer_section",
            {
                "label": "Internal Signature",
                "fieldtype": "Section Break",
                "insert_after": last_field,
                "collapsible": 1,
            },
        ))

    if not _phase26k_field_exists(reference_doctype, "internal_signature_status"):
        created.append(_phase26k_create_or_update_custom_field(
            reference_doctype,
            "internal_signature_status",
            {
                "label": "Internal Signature Status",
                "fieldtype": "Data",
                "insert_after": "ac_footer_section",
                "read_only": 1,
                "no_copy": 1,
                "default": "Draft",
            },
        ))

    if not _phase26k_field_exists(reference_doctype, "ac_footer"):
        created.append(_phase26k_create_or_update_custom_field(
            reference_doctype,
            "ac_footer",
            {
                "label": "Ac Footer",
                "fieldtype": "Table",
                "options": PHASE26C_AC_FOOTER_CHILD_DT,
                "insert_after": "internal_signature_status",
                "allow_on_submit": 1,
                "no_copy": 1,
                "description": "Internal authorized signers for this document.",
            },
        ))

    frappe.clear_cache(doctype=reference_doctype)

    return {
        "ok": True,
        "reference_doctype": reference_doctype,
        "created_or_updated": created,
        "has_ac_footer": _phase26k_field_exists(reference_doctype, "ac_footer"),
        "has_internal_signature_status": _phase26k_field_exists(reference_doctype, "internal_signature_status"),
    }


def _phase26k_policy_name(reference_doctype):
    return "ISP-" + frappe.scrub(reference_doctype).replace("_", "-").upper()


def _phase26k_create_or_update_policy(reference_doctype, workflow_mode="Sequential", allow_external_requests=1):
    if not frappe.db.exists("DocType", "Internal Signature Policy"):
        frappe.throw("Internal Signature Policy is not installed.")

    existing = None

    rows = frappe.get_all(
        "Internal Signature Policy",
        filters={"reference_doctype": reference_doctype},
        pluck="name",
        limit=1,
    )

    if rows:
        existing = rows[0]

    if existing:
        doc = frappe.get_doc("Internal Signature Policy", existing)
        action = "updated"
    else:
        doc = frappe.new_doc("Internal Signature Policy")
        doc.name = _phase26k_policy_name(reference_doctype)
        action = "created"

    meta = frappe.get_meta("Internal Signature Policy")

    values = {
        "policy_name": f"{reference_doctype} Internal Signature Policy",
        "reference_doctype": reference_doctype,
        "is_active": 1,
        "ac_footer_fieldname": "ac_footer",
        "workflow_mode": workflow_mode or "Sequential",
        "allow_saved_signature": 1,
        "allow_direction": 1,
        "allow_direction_drawing": 1,
        "allow_direction_text": 1,
        "allow_reject": 1,
        "require_signature_profile": 1,
        "allow_external_requests": int(allow_external_requests or 0),
    }

    for field, value in values.items():
        if meta.has_field(field):
            setattr(doc, field, value)

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()

    return {
        "ok": True,
        "reference_doctype": reference_doctype,
        "policy": doc.name,
        "action": action,
        "workflow_mode": getattr(doc, "workflow_mode", workflow_mode),
        "allow_external_requests": bool(getattr(doc, "allow_external_requests", allow_external_requests)),
    }


def _phase26k_add_doctype_to_external_systems(reference_doctype):
    if not frappe.db.exists("DocType", "Internal Signature External System"):
        return {
            "ok": True,
            "updated": [],
            "reason": "External gateway not installed.",
        }

    updated = []

    rows = frappe.get_all(
        "Internal Signature External System",
        filters={"is_active": 1},
        fields=["name", "allowed_doctypes_json"],
        limit_page_length=100,
    )

    for r in rows:
        allowed = _phase26h_parse_json(r.allowed_doctypes_json, []) if globals().get("_phase26h_parse_json") else []

        if allowed and reference_doctype not in allowed:
            allowed.append(reference_doctype)
            frappe.db.set_value(
                "Internal Signature External System",
                r.name,
                "allowed_doctypes_json",
                _phase26k_json.dumps(sorted(set(allowed)), ensure_ascii=False),
                update_modified=True,
            )
            updated.append(r.name)

    frappe.db.commit()

    return {
        "ok": True,
        "updated": updated,
    }


@frappe.whitelist()
def phase26k_candidate_doctypes():
    _phase26k_require_admin()

    items = []

    for dt in PHASE26K_COMMON_DOCTYPES:
        if not frappe.db.exists("DocType", dt):
            continue

        meta = frappe.get_meta(dt)

        item = {
            "doctype": dt,
            "module": getattr(meta, "module", None),
            "is_submittable": bool(getattr(meta, "is_submittable", 0)),
            "custom": bool(getattr(meta, "custom", 0)),
            "has_ac_footer": meta.has_field("ac_footer"),
            "has_internal_signature_status": meta.has_field("internal_signature_status"),
            "policy_exists": bool(frappe.get_all("Internal Signature Policy", filters={"reference_doctype": dt}, limit=1)),
            "desk_buttons_installed": bool(frappe.db.exists("Client Script", f"Surhan Internal Signature Buttons - {dt}")) if frappe.db.exists("DocType", "Client Script") else False,
            "signed_print_installed": bool(frappe.db.exists("Client Script", f"Surhan Signed Print View - {dt}")) if frappe.db.exists("DocType", "Client Script") else False,
            "certificate_buttons_installed": bool(frappe.db.exists("Client Script", f"Surhan Internal Certificate PDF - {dt}")) if frappe.db.exists("DocType", "Client Script") else False,
        }

        item["enabled"] = bool(
            item["has_ac_footer"]
            and item["policy_exists"]
            and item["desk_buttons_installed"]
        )

        items.append(item)

    return {
        "ok": True,
        "phase": "26K",
        "count": len(items),
        "items": items,
    }


@frappe.whitelist()
def phase26k_enable_doctype(
    reference_doctype: str,
    workflow_mode: str = "Sequential",
    allow_external_requests: int = 1,
    add_to_external_systems: int = 0,
):
    _phase26k_require_admin()

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    phase26c_install_document_signature_requests()
    fields = _phase26k_ensure_ac_footer_fields(reference_doctype)
    policy = _phase26k_create_or_update_policy(
        reference_doctype,
        workflow_mode=workflow_mode,
        allow_external_requests=allow_external_requests,
    )

    client_scripts = []

    if globals().get("install_internal_signature_client_script"):
        client_scripts.append(install_internal_signature_client_script(reference_doctype))

    if globals().get("install_signed_print_client_script"):
        client_scripts.append(install_signed_print_client_script(reference_doctype))

    if globals().get("install_internal_certificate_client_script"):
        client_scripts.append(install_internal_certificate_client_script(reference_doctype))

    external_systems = None

    if int(add_to_external_systems or 0):
        external_systems = _phase26k_add_doctype_to_external_systems(reference_doctype)

    frappe.clear_cache(doctype=reference_doctype)
    frappe.db.commit()

    try:
        log_audit(
            "internal_document_signature.doctype_enabled",
            {
                "reference_doctype": reference_doctype,
                "workflow_mode": workflow_mode,
                "allow_external_requests": bool(int(allow_external_requests or 0)),
                "add_to_external_systems": bool(int(add_to_external_systems or 0)),
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "26K",
        "reference_doctype": reference_doctype,
        "fields": fields,
        "policy": policy,
        "client_scripts": client_scripts,
        "external_systems": external_systems,
        "doctype_url": f"/app/doctype/{frappe.scrub(reference_doctype).replace('_', '-')}",
    }


@frappe.whitelist()
def phase26k_enable_common_doctypes(doctypes=None, workflow_mode="Sequential", allow_external_requests: int = 1):
    _phase26k_require_admin()

    selected = doctypes

    if isinstance(selected, str):
        try:
            selected = _phase26k_json.loads(selected)
        except Exception:
            selected = [x.strip() for x in selected.split(",") if x.strip()]

    if not selected:
        selected = [dt for dt in PHASE26K_COMMON_DOCTYPES if frappe.db.exists("DocType", dt)]

    results = []

    for dt in selected:
        if not frappe.db.exists("DocType", dt):
            results.append({
                "ok": False,
                "reference_doctype": dt,
                "error": "DocType does not exist.",
            })
            continue

        try:
            results.append(phase26k_enable_doctype(
                dt,
                workflow_mode=workflow_mode,
                allow_external_requests=allow_external_requests,
                add_to_external_systems=0,
            ))
        except Exception as exc:
            results.append({
                "ok": False,
                "reference_doctype": dt,
                "error": str(exc),
            })

    return {
        "ok": True,
        "phase": "26K",
        "count": len(results),
        "enabled": [r for r in results if r.get("ok")],
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase26k_rollout_health():
    _phase26k_require_admin()

    candidates = phase26k_candidate_doctypes()

    enabled = [x for x in candidates.get("items") or [] if x.get("enabled")]

    return {
        "ok": True,
        "phase": "26K",
        "candidate_count": candidates.get("count"),
        "enabled_count": len(enabled),
        "enabled_doctypes": [x.get("doctype") for x in enabled],
        "candidates": candidates.get("items"),
        "rollout_console": "/internal-signature-rollout",
        "ready": True,
    }


@frappe.whitelist()
def phase26k_export_rollout_snapshot_json():
    _phase26k_require_admin()

    snapshot = {
        "health": phase26k_rollout_health(),
        "generated_at": str(now_datetime()),
    }

    sha = _phase26k_sha256(snapshot)
    content = _phase26k_json_dumps(snapshot).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26k-real-doctype-rollout-snapshot-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26K",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "enabled_count": snapshot["health"].get("enabled_count"),
    }


# Phase 26L: Real DocType End-to-End Signature Test.
import json as _phase26l_json
import hashlib as _phase26l_hashlib


def _phase26l_json_dumps(data):
    return _phase26l_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase26l_sha256(data):
    if not isinstance(data, str):
        data = _phase26l_json_dumps(data)
    return _phase26l_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26l_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase26l_require_admin():
    if not _phase26l_is_admin():
        frappe.throw("Only Internal Signature Administrator / Manager can run real DocType E2E tests.")


def _phase26l_doc_url(doctype, name):
    return f"/app/{frappe.scrub(doctype).replace('_', '-')}/{name}"


def _phase26l_signed_print_url(doctype, name):
    return f"/signed-print?doctype={frappe.utils.quote(doctype)}&name={frappe.utils.quote(name)}"


def _phase26l_assert_doctype_ready(reference_doctype):
    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    meta = frappe.get_meta(reference_doctype)

    missing = []

    if not meta.has_field("ac_footer"):
        missing.append("ac_footer")

    if not meta.has_field("internal_signature_status"):
        missing.append("internal_signature_status")

    policy_exists = bool(
        frappe.get_all(
            "Internal Signature Policy",
            filters={"reference_doctype": reference_doctype},
            limit=1,
        )
    )

    if not policy_exists:
        missing.append("Internal Signature Policy")

    if missing:
        if globals().get("phase26k_enable_doctype"):
            phase26k_enable_doctype(
                reference_doctype,
                workflow_mode="Sequential",
                allow_external_requests=1,
                add_to_external_systems=0,
            )
            frappe.clear_cache(doctype=reference_doctype)
        else:
            frappe.throw(f"DocType is not ready for internal signatures: {', '.join(missing)}")

    return {
        "ok": True,
        "reference_doctype": reference_doctype,
        "has_ac_footer": frappe.get_meta(reference_doctype).has_field("ac_footer"),
        "has_internal_signature_status": frappe.get_meta(reference_doctype).has_field("internal_signature_status"),
        "policy_exists": bool(
            frappe.get_all(
                "Internal Signature Policy",
                filters={"reference_doctype": reference_doctype},
                limit=1,
            )
        ),
    }


def _phase26l_current_identity():
    identity = _phase26c_identity_from_employee_or_user(user=frappe.session.user)

    if not identity.get("user"):
        frappe.throw("Current user has no valid signer identity.")

    if not identity.get("employee"):
        frappe.throw("Current user has no linked Employee. Please link Employee before real DocType signing.")

    return identity


def _phase26l_create_task_doc():
    _phase26l_assert_doctype_ready("Task")
    identity = _phase26l_current_identity()

    doc = frappe.new_doc("Task")
    doc.subject = "Phase 26L Real Task Signature Test"
    doc.description = """
        <h2>Phase 26L Real DocType Signature Test</h2>
        <p>This is a real ERPNext/Projects Task used to test the internal Ac Footer signature workflow.</p>
        <p>The signer is inserted into Ac Footer, then the saved employee signature is applied, then certificate and signed PDF are generated.</p>
    """

    try:
        doc.status = "Open"
    except Exception:
        pass

    doc.append("ac_footer", {
        "employee": identity.get("employee"),
        "user": identity.get("user"),
        "full_name": identity.get("full_name"),
        "designation": identity.get("designation"),
        "department": identity.get("department"),
        "sign_order": 1,
        "action_required": "Both",
        "can_use_saved_signature": 1,
        "can_draw_direction": 1,
        "can_write_direction_text": 1,
        "can_reject": 1,
        "status": "Draft",
        "notes": "Phase 26L real DocType E2E test.",
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return doc


def _phase26l_first_pending_request(reference_doctype, reference_name):
    rows = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
            "requested_user": frappe.session.user,
            "status": "Pending",
        },
        pluck="name",
        order_by="sequence_order asc, creation asc",
        limit=1,
    )

    return rows[0] if rows else None


@frappe.whitelist()
def phase26l_real_task_e2e_test():
    _phase26l_require_admin()

    reference_doctype = "Task"

    _phase26l_assert_doctype_ready(reference_doctype)

    if not frappe.db.exists(PHASE26A_PROFILE_DT, frappe.session.user):
        frappe.throw("Current user has no Employee Signature Profile.")

    profile = frappe.get_doc(PHASE26A_PROFILE_DT, frappe.session.user)

    if not profile.get("signature_hash"):
        frappe.throw("Current user has no saved signature hash.")

    task = _phase26l_create_task_doc()

    sync = sync_ac_footer_requests(task.doctype, task.name)
    state_before = get_document_signature_state(task.doctype, task.name)

    request_name = _phase26l_first_pending_request(task.doctype, task.name)

    if not request_name:
        frappe.throw("No pending Document Signature Request was created for the real Task.")

    context_before = get_document_signature_request_action_context(request_name)

    signed = apply_saved_signature_request(request_name)

    state_after = get_document_signature_state(task.doctype, task.name)

    print_context = get_signed_document_print_context(task.doctype, task.name)

    certificate = generate_internal_signature_certificate(
        task.doctype,
        task.name,
        force=0,
    )

    verification = verify_internal_signature_certificate(certificate.get("verification_code"))

    form_context = get_document_signature_form_context(task.doctype, task.name, auto_sync=0)

    report = {
        "ok": True,
        "phase": "26L",
        "reference_doctype": task.doctype,
        "reference_name": task.name,
        "document_url": _phase26l_doc_url(task.doctype, task.name),
        "signed_print_url": _phase26l_signed_print_url(task.doctype, task.name),
        "sync": sync,
        "request_name": request_name,
        "action_url": f"/document-sign-action?request={request_name}",
        "state_before": state_before,
        "context_before": context_before,
        "signed": signed,
        "state_after": state_after,
        "print_context_ok": bool(print_context.get("ok")),
        "certificate": certificate,
        "verification": verification,
        "form_context": {
            "ok": form_context.get("ok"),
            "has_action": form_context.get("has_action"),
            "complete": form_context.get("complete"),
            "my_pending_count": form_context.get("my_pending_count"),
            "state": form_context.get("state"),
        },
        "checks": {
            "task_created": bool(task.name),
            "request_created": bool(request_name),
            "signed_status": signed.get("status") == "Signed",
            "document_complete": bool(state_after.get("complete")),
            "signature_count_signed": (state_after.get("status_counts") or {}).get("Signed") == 1,
            "certificate_generated": bool(certificate.get("verification_code")),
            "certificate_valid": bool(verification.get("valid")),
            "signed_pdf_generated": bool(certificate.get("signed_pdf")),
            "signed_pdf_sha256_present": bool(certificate.get("signed_pdf_sha256")),
        },
    }

    report["ready"] = all(report["checks"].values())

    return report


@frappe.whitelist()
def phase26l_export_real_task_e2e_report_json():
    report = phase26l_real_task_e2e_test()
    sha = _phase26l_sha256(report)
    content = _phase26l_json_dumps(report).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26l-real-task-e2e-report-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26L",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "ready": report.get("ready"),
        "reference_doctype": report.get("reference_doctype"),
        "reference_name": report.get("reference_name"),
        "document_url": report.get("document_url"),
        "signed_print_url": report.get("signed_print_url"),
        "verification_url": (report.get("certificate") or {}).get("verification_url"),
        "signed_pdf": (report.get("certificate") or {}).get("signed_pdf"),
    }


@frappe.whitelist()
def phase26l_real_task_e2e_health():
    report = phase26l_real_task_e2e_test()
    export = phase26l_export_real_task_e2e_report_json()

    failed_checks = {
        k: v for k, v in (report.get("checks") or {}).items()
        if not v
    }

    return {
        "ok": True,
        "phase": "26L",
        "ready": bool(report.get("ready")),
        "failed_checks": failed_checks,
        "reference_doctype": report.get("reference_doctype"),
        "reference_name": report.get("reference_name"),
        "document_url": report.get("document_url"),
        "signed_print_url": report.get("signed_print_url"),
        "verification_url": (report.get("certificate") or {}).get("verification_url"),
        "signed_pdf": (report.get("certificate") or {}).get("signed_pdf"),
        "signed_pdf_sha256": (report.get("certificate") or {}).get("signed_pdf_sha256"),
        "request_name": report.get("request_name"),
        "action_url": report.get("action_url"),
        "checks": report.get("checks"),
        "export": export,
    }


# Phase 26M: Professional signed print layouts for ERPNext/HRMS DocTypes.
import json as _phase26m_json
import hashlib as _phase26m_hashlib
import re as _phase26m_re


def _phase26m_json_dumps(data):
    return _phase26m_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase26m_sha256(data):
    if not isinstance(data, str):
        data = _phase26m_json_dumps(data)
    return _phase26m_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26m_esc(value):
    try:
        return frappe.utils.escape_html("" if value is None else str(value))
    except Exception:
        return "" if value is None else str(value)


def _phase26m_sanitize_html(html):
    html = html or ""
    html = _phase26m_re.sub(r"<script[\s\S]*?</script>", "", html, flags=_phase26m_re.IGNORECASE)
    html = _phase26m_re.sub(r"\son[a-zA-Z]+\s*=\s*(['\"]).*?\1", "", html)
    return html


def _phase26m_value(doc, fieldname):
    try:
        value = doc.get(fieldname)
    except Exception:
        value = None

    if value in [None, ""]:
        return None

    return value


def _phase26m_first_value(doc, fieldnames):
    for fieldname in fieldnames:
        value = _phase26m_value(doc, fieldname)
        if value not in [None, ""]:
            return value
    return None


def _phase26m_money(value, currency=None):
    if value in [None, ""]:
        return ""

    try:
        if currency:
            return frappe.utils.fmt_money(value, currency=currency)
        return frappe.utils.fmt_money(value)
    except Exception:
        return str(value)


def _phase26m_date(value):
    if value in [None, ""]:
        return ""

    try:
        return frappe.utils.formatdate(value)
    except Exception:
        return str(value)


def _phase26m_datetime(value):
    if value in [None, ""]:
        return ""

    try:
        return frappe.utils.format_datetime(value)
    except Exception:
        return str(value)


def _phase26m_doc_title(doc):
    try:
        return doc.get_title()
    except Exception:
        return doc.get("title") or doc.get("subject") or doc.name


def _phase26m_card(title, inner_html):
    if not inner_html:
        return ""

    return f"""
    <div style="border:1px solid #e5e7eb;border-radius:12px;padding:14px;margin:12px 0;background:#ffffff;">
      <div style="font-size:15px;font-weight:800;margin-bottom:10px;color:#111827;">{_phase26m_esc(title)}</div>
      {inner_html}
    </div>
    """


def _phase26m_kv_grid(pairs):
    cells = []

    for label, value in pairs:
        if value in [None, ""]:
            continue

        cells.append(f"""
        <div style="display:grid;grid-template-columns:135px 1fr;gap:8px;border-bottom:1px dashed #e5e7eb;padding:7px 0;">
          <div style="color:#6b7280;font-size:12px;">{_phase26m_esc(label)}</div>
          <div style="color:#111827;font-size:12px;font-weight:650;word-break:break-word;">{_phase26m_esc(value)}</div>
        </div>
        """)

    if not cells:
        return ""

    return f"""
    <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 18px;">
      {''.join(cells)}
    </div>
    """


def _phase26m_table(title, rows, columns):
    if not rows:
        return ""

    header = "".join(
        f"<th style='text-align:left;padding:8px;border-bottom:1px solid #d1d5db;color:#374151;font-size:11px;'>{_phase26m_esc(label)}</th>"
        for label, fieldname in columns
    )

    body_rows = []

    for row in rows:
        cells = []

        for label, fieldname in columns:
            value = row.get(fieldname) if hasattr(row, "get") else getattr(row, fieldname, "")
            if fieldname in {"amount", "base_amount", "net_amount", "rate", "base_rate", "tax_amount", "total", "grand_total", "sanctioned_amount", "claimed_amount"}:
                value = _phase26m_money(value, row.get("currency") if hasattr(row, "get") else None)

            cells.append(
                f"<td style='padding:8px;border-bottom:1px solid #eef2f7;font-size:11px;color:#111827;vertical-align:top;word-break:break-word;'>{_phase26m_esc(value)}</td>"
            )

        body_rows.append(f"<tr>{''.join(cells)}</tr>")

    return _phase26m_card(
        title,
        f"""
        <div style="overflow:auto;">
          <table style="width:100%;border-collapse:collapse;background:#fff;">
            <thead><tr>{header}</tr></thead>
            <tbody>{''.join(body_rows)}</tbody>
          </table>
        </div>
        """
    )


def _phase26m_status_banner(doc):
    status = _phase26m_first_value(doc, ["status", "docstatus", "workflow_state", "approval_status"])
    internal = _phase26m_value(doc, "internal_signature_status")

    return f"""
    <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;border:1px solid #d1d5db;border-radius:14px;padding:14px;margin-bottom:14px;background:#f9fafb;">
      <div>
        <div style="font-size:22px;font-weight:900;color:#111827;letter-spacing:-0.03em;">{_phase26m_esc(_phase26m_doc_title(doc))}</div>
        <div style="color:#6b7280;font-size:12px;margin-top:3px;">{_phase26m_esc(doc.doctype)} / {_phase26m_esc(doc.name)}</div>
      </div>
      <div style="text-align:right;">
        <div style="display:inline-block;border:1px solid #10b981;color:#047857;border-radius:999px;padding:5px 10px;font-weight:800;font-size:11px;margin-bottom:5px;">Internal Signature: {_phase26m_esc(internal or '—')}</div><br>
        <div style="display:inline-block;border:1px solid #94a3b8;color:#334155;border-radius:999px;padding:5px 10px;font-weight:800;font-size:11px;">Document Status: {_phase26m_esc(status or '—')}</div>
      </div>
    </div>
    """


def _phase26m_get_rows(doc, table_field):
    try:
        rows = doc.get(table_field) or []
        return list(rows)
    except Exception:
        return []


def _phase26m_commercial_layout(doc):
    currency = _phase26m_first_value(doc, ["currency", "company_currency", "party_account_currency"])

    party_label = "Party"
    party_fields = ["customer", "supplier", "party", "employee"]

    if doc.doctype in {"Sales Order", "Sales Invoice", "Delivery Note", "Quotation"}:
        party_label = "Customer"
        party_fields = ["customer", "customer_name", "party_name"]
    elif doc.doctype in {"Purchase Order", "Purchase Receipt", "Purchase Invoice", "Supplier Quotation", "Request for Quotation"}:
        party_label = "Supplier"
        party_fields = ["supplier", "supplier_name", "party_name"]

    header = _phase26m_kv_grid([
        ("Company", _phase26m_value(doc, "company")),
        (party_label, _phase26m_first_value(doc, party_fields)),
        ("Posting Date", _phase26m_date(_phase26m_value(doc, "posting_date"))),
        ("Transaction Date", _phase26m_date(_phase26m_value(doc, "transaction_date"))),
        ("Due Date", _phase26m_date(_phase26m_value(doc, "due_date"))),
        ("Schedule Date", _phase26m_date(_phase26m_value(doc, "schedule_date"))),
        ("Currency", currency),
        ("Cost Center", _phase26m_value(doc, "cost_center")),
        ("Warehouse", _phase26m_first_value(doc, ["set_warehouse", "warehouse", "from_warehouse", "to_warehouse"])),
    ])

    items = _phase26m_get_rows(doc, "items")
    item_table = _phase26m_table(
        "Items",
        items,
        [
            ("Item Code", "item_code"),
            ("Item Name", "item_name"),
            ("Description", "description"),
            ("Qty", "qty"),
            ("UOM", "uom"),
            ("Rate", "rate"),
            ("Amount", "amount"),
        ],
    )

    taxes = _phase26m_get_rows(doc, "taxes")
    tax_table = _phase26m_table(
        "Taxes and Charges",
        taxes,
        [
            ("Type", "charge_type"),
            ("Account", "account_head"),
            ("Description", "description"),
            ("Rate", "rate"),
            ("Tax Amount", "tax_amount"),
            ("Total", "total"),
        ],
    )

    totals = _phase26m_kv_grid([
        ("Net Total", _phase26m_money(_phase26m_first_value(doc, ["net_total", "base_net_total"]), currency)),
        ("Total Taxes", _phase26m_money(_phase26m_first_value(doc, ["total_taxes_and_charges", "base_total_taxes_and_charges"]), currency)),
        ("Grand Total", _phase26m_money(_phase26m_first_value(doc, ["grand_total", "base_grand_total"]), currency)),
        ("Rounded Total", _phase26m_money(_phase26m_first_value(doc, ["rounded_total", "base_rounded_total"]), currency)),
        ("In Words", _phase26m_first_value(doc, ["in_words", "base_in_words"])),
    ])

    terms = _phase26m_first_value(doc, ["terms", "terms_and_conditions", "tc_name", "remarks", "instructions"])
    terms_html = ""

    if terms:
        if str(terms).lstrip().startswith("<"):
            terms_html = _phase26m_card("Terms / Remarks", _phase26m_sanitize_html(str(terms)))
        else:
            terms_html = _phase26m_card("Terms / Remarks", f"<p style='margin:0;color:#374151;font-size:12px;line-height:1.6'>{_phase26m_esc(terms)}</p>")

    return (
        _phase26m_status_banner(doc)
        + _phase26m_card("Document Summary", header)
        + item_table
        + tax_table
        + _phase26m_card("Totals", totals)
        + terms_html
    )


def _phase26m_task_project_issue_layout(doc):
    header_pairs = [
        ("Subject", _phase26m_first_value(doc, ["subject", "project_name", "issue_type"])),
        ("Status", _phase26m_value(doc, "status")),
        ("Priority", _phase26m_value(doc, "priority")),
        ("Project", _phase26m_value(doc, "project")),
        ("Issue Type", _phase26m_value(doc, "issue_type")),
        ("Customer", _phase26m_value(doc, "customer")),
        ("Expected Start", _phase26m_date(_phase26m_first_value(doc, ["exp_start_date", "expected_start_date"]))),
        ("Expected End", _phase26m_date(_phase26m_first_value(doc, ["exp_end_date", "expected_end_date"]))),
        ("Progress", _phase26m_value(doc, "progress")),
        ("Assigned To", _phase26m_value(doc, "_assign")),
    ]

    description = _phase26m_first_value(doc, ["description", "details", "resolution_details"])

    description_html = ""

    if description:
        description_html = _phase26m_card(
            "Description",
            f"<div style='font-size:12px;color:#374151;line-height:1.65'>{_phase26m_sanitize_html(str(description))}</div>"
        )

    return (
        _phase26m_status_banner(doc)
        + _phase26m_card("Document Summary", _phase26m_kv_grid(header_pairs))
        + description_html
    )


def _phase26m_hr_layout(doc):
    currency = _phase26m_first_value(doc, ["currency", "company_currency"])

    header = _phase26m_kv_grid([
        ("Employee", _phase26m_first_value(doc, ["employee", "applicant_name"])),
        ("Employee Name", _phase26m_first_value(doc, ["employee_name", "applicant_name"])),
        ("Department", _phase26m_value(doc, "department")),
        ("Designation", _phase26m_value(doc, "designation")),
        ("Company", _phase26m_value(doc, "company")),
        ("Status", _phase26m_first_value(doc, ["status", "approval_status"])),
        ("Posting Date", _phase26m_date(_phase26m_value(doc, "posting_date"))),
        ("From Date", _phase26m_date(_phase26m_value(doc, "from_date"))),
        ("To Date", _phase26m_date(_phase26m_value(doc, "to_date"))),
        ("Leave Type", _phase26m_value(doc, "leave_type")),
        ("Total Leave Days", _phase26m_value(doc, "total_leave_days")),
        ("Leave Approver", _phase26m_value(doc, "leave_approver")),
        ("Claimed Amount", _phase26m_money(_phase26m_value(doc, "total_claimed_amount"), currency)),
        ("Sanctioned Amount", _phase26m_money(_phase26m_value(doc, "total_sanctioned_amount"), currency)),
        ("Advance Amount", _phase26m_money(_phase26m_value(doc, "advance_amount"), currency)),
        ("Offer Date", _phase26m_date(_phase26m_value(doc, "offer_date"))),
        ("Date of Joining", _phase26m_date(_phase26m_value(doc, "date_of_joining"))),
    ])

    expenses = _phase26m_get_rows(doc, "expenses")
    expenses_table = _phase26m_table(
        "Expense Details",
        expenses,
        [
            ("Date", "expense_date"),
            ("Type", "expense_type"),
            ("Description", "description"),
            ("Claimed", "amount"),
            ("Sanctioned", "sanctioned_amount"),
        ],
    )

    reason = _phase26m_first_value(doc, ["reason", "description", "terms", "offer_terms"])

    reason_html = ""

    if reason:
        reason_html = _phase26m_card(
            "Reason / Description",
            f"<div style='font-size:12px;color:#374151;line-height:1.65'>{_phase26m_sanitize_html(str(reason))}</div>"
        )

    return (
        _phase26m_status_banner(doc)
        + _phase26m_card("HR Summary", header)
        + expenses_table
        + reason_html
    )


def _phase26m_generic_layout(doc):
    meta = frappe.get_meta(doc.doctype)

    pairs = []

    skip = {
        "ac_footer",
        "amended_from",
        "idx",
        "docstatus",
        "naming_series",
    }

    for df in meta.fields:
        if not df.fieldname:
            continue

        if df.fieldname in skip:
            continue

        if df.fieldtype in {"Section Break", "Column Break", "Tab Break", "Table", "HTML", "Button", "Fold"}:
            continue

        value = _phase26m_value(doc, df.fieldname)

        if value in [None, ""]:
            continue

        if df.fieldtype in {"Date"}:
            value = _phase26m_date(value)

        if df.fieldtype in {"Datetime"}:
            value = _phase26m_datetime(value)

        pairs.append((df.label or df.fieldname, value))

        if len(pairs) >= 24:
            break

    return _phase26m_status_banner(doc) + _phase26m_card("Document Fields", _phase26m_kv_grid(pairs))


def _phase26m_build_professional_content(doc):
    commercial = {
        "Material Request",
        "Purchase Order",
        "Purchase Receipt",
        "Purchase Invoice",
        "Supplier Quotation",
        "Request for Quotation",
        "Sales Order",
        "Delivery Note",
        "Sales Invoice",
        "Quotation",
        "Payment Entry",
        "Journal Entry",
    }

    hr = {
        "Expense Claim",
        "Employee Advance",
        "Leave Application",
        "Job Offer",
        "Employee Onboarding",
        "Employee Separation",
        "Training Event",
    }

    work = {
        "Task",
        "Project",
        "Issue",
    }

    if doc.doctype in commercial:
        body = _phase26m_commercial_layout(doc)
        layout_type = "commercial"

    elif doc.doctype in hr:
        body = _phase26m_hr_layout(doc)
        layout_type = "hr"

    elif doc.doctype in work:
        body = _phase26m_task_project_issue_layout(doc)
        layout_type = "work"

    else:
        body = _phase26m_generic_layout(doc)
        layout_type = "generic"

    wrapped = f"""
    <div data-surhan-print-layout="26M" data-layout-type="{_phase26m_esc(layout_type)}" style="font-family:Inter,Arial,sans-serif;">
      {body}
    </div>
    """

    return {
        "layout_version": "26M",
        "layout_type": layout_type,
        "html": wrapped,
    }


if not globals().get("_phase26m_original_phase26f_get_document_payload") and globals().get("_phase26f_get_document_payload"):
    _phase26m_original_phase26f_get_document_payload = _phase26f_get_document_payload


def _phase26f_get_document_payload(doc):
    if globals().get("_phase26m_original_phase26f_get_document_payload"):
        base = _phase26m_original_phase26f_get_document_payload(doc)
    else:
        base = {
            "doctype": doc.doctype,
            "name": doc.name,
            "title": _phase26m_doc_title(doc),
            "content_html": "",
            "fields": [],
            "document_url": f"/app/{frappe.scrub(doc.doctype).replace('_', '-')}/{doc.name}",
        }

    layout = _phase26m_build_professional_content(doc)

    base["content_html"] = layout.get("html")
    base["professional_layout"] = {
        "version": layout.get("layout_version"),
        "type": layout.get("layout_type"),
    }

    # Keep document fields concise because the professional layout now carries the main body.
    base["fields"] = [
        {
            "label": "Document Type",
            "fieldname": "doctype",
            "fieldtype": "Data",
            "value": doc.doctype,
        },
        {
            "label": "Document Name",
            "fieldname": "name",
            "fieldtype": "Data",
            "value": doc.name,
        },
        {
            "label": "Internal Signature Status",
            "fieldname": "internal_signature_status",
            "fieldtype": "Data",
            "value": doc.get("internal_signature_status") or "",
        },
    ]

    return base


@frappe.whitelist()
def phase26m_preview_professional_print_context(reference_doctype: str, reference_name: str):
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")

    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    if not frappe.db.exists(reference_doctype, reference_name):
        frappe.throw(f"Document not found: {reference_doctype} {reference_name}")

    ctx = get_signed_document_print_context(reference_doctype, reference_name)

    document = ctx.get("document") or {}
    layout = document.get("professional_layout") or {}

    return {
        "ok": True,
        "phase": "26M",
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "layout": layout,
        "content_has_professional_marker": "data-surhan-print-layout=\"26M\"" in (document.get("content_html") or ""),
        "signed_print_url": f"/signed-print?doctype={frappe.utils.quote(reference_doctype)}&name={frappe.utils.quote(reference_name)}",
        "print_hash": ctx.get("print_hash"),
        "complete": ctx.get("complete"),
        "status_counts": ctx.get("status_counts"),
        "context": ctx,
        "ready": bool(layout.get("version") == "26M"),
    }


def _phase26m_find_latest_signed_real_doc():
    if not frappe.db.exists("DocType", PHASE26C_REQUEST_DT):
        return None

    rows = frappe.get_all(
        PHASE26C_REQUEST_DT,
        filters={
            "status": ["in", ["Signed", "Directed"]],
        },
        fields=["reference_doctype", "reference_name", "completed_at", "name"],
        order_by="completed_at desc",
        limit_page_length=30,
    )

    for r in rows:
        if r.reference_doctype == "Internal Signature Demo Document":
            continue

        try:
            state = get_document_signature_state(r.reference_doctype, r.reference_name)
            if state.get("complete"):
                return {
                    "reference_doctype": r.reference_doctype,
                    "reference_name": r.reference_name,
                    "request": r.name,
                }
        except Exception:
            continue

    return None


@frappe.whitelist()
def phase26m_professional_print_health(reference_doctype: str = None, reference_name: str = None):
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")

    target = None

    if reference_doctype and reference_name:
        target = {
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
        }
    else:
        target = _phase26m_find_latest_signed_real_doc()

    if not target:
        return {
            "ok": True,
            "phase": "26M",
            "ready": False,
            "reason": "No completed real signed document found yet.",
            "hint": "Run Phase 26L first or pass reference_doctype/reference_name.",
        }

    preview = phase26m_preview_professional_print_context(
        target["reference_doctype"],
        target["reference_name"],
    )

    return {
        "ok": True,
        "phase": "26M",
        "target": target,
        "ready": bool(preview.get("ready") and preview.get("content_has_professional_marker")),
        "layout": preview.get("layout"),
        "signed_print_url": preview.get("signed_print_url"),
        "print_hash": preview.get("print_hash"),
        "complete": preview.get("complete"),
    }


@frappe.whitelist()
def phase26m_export_professional_print_preview_json(reference_doctype: str = None, reference_name: str = None):
    health = phase26m_professional_print_health(reference_doctype, reference_name)

    if not health.get("ready"):
        return {
            "ok": False,
            "phase": "26M",
            "health": health,
        }

    preview = phase26m_preview_professional_print_context(
        health["target"]["reference_doctype"],
        health["target"]["reference_name"],
    )

    sha = _phase26m_sha256(preview)
    content = _phase26m_json_dumps(preview).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26m-professional-print-preview-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26M",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "signed_print_url": health.get("signed_print_url"),
        "layout": health.get("layout"),
        "target": health.get("target"),
    }


# Phase 26N-FIX1: Secure Classic AC Footer Signing UX without Python f-string JS interpolation.
import json as _phase26n_json
import hashlib as _phase26n_hashlib


def _phase26n_json_dumps(data):
    return _phase26n_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase26n_sha256(data):
    if not isinstance(data, str):
        data = _phase26n_json_dumps(data)
    return _phase26n_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26n_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase26n_require_login():
    if frappe.session.user == "Guest":
        frappe.throw("Login is required.")


def _phase26n_require_admin():
    if not _phase26n_is_admin():
        frappe.throw("Only Internal Signature Administrator / Manager can install Classic Signature UX.")


def _phase26n_clean_note(note, max_len=1200):
    note = (note or "").strip()

    if len(note) > max_len:
        frappe.throw(f"Note is too long. Maximum allowed length is {max_len} characters.")

    return note


def _phase26n_doc_url(doctype, name):
    return f"/app/{frappe.scrub(doctype).replace('_', '-')}/{name}"


def _phase26n_signed_print_url(doctype, name):
    return f"/signed-print?doctype={frappe.utils.quote(doctype)}&name={frappe.utils.quote(name)}"


@frappe.whitelist()
def phase26n_get_classic_signature_context(reference_doctype: str, reference_name: str):
    _phase26n_require_login()

    if not reference_doctype or not reference_name:
        frappe.throw("reference_doctype and reference_name are required.")

    if not frappe.db.exists(reference_doctype, reference_name):
        frappe.throw(f"Document not found: {reference_doctype} {reference_name}")

    form_ctx = get_document_signature_form_context(
        reference_doctype=reference_doctype,
        reference_name=reference_name,
        auto_sync=0,
    )

    first = form_ctx.get("first_pending")
    state = form_ctx.get("state") or {}

    request_ctx = None

    if first and first.get("name"):
        try:
            request_ctx = get_document_signature_request_action_context(first.get("name"))
        except Exception as exc:
            request_ctx = {
                "ok": False,
                "error": str(exc),
            }

    return {
        "ok": True,
        "phase": "26N-FIX1",
        "reference_doctype": reference_doctype,
        "reference_name": reference_name,
        "document_url": _phase26n_doc_url(reference_doctype, reference_name),
        "signed_print_url": _phase26n_signed_print_url(reference_doctype, reference_name),
        "state": state,
        "complete": bool(form_ctx.get("complete")),
        "my_pending_count": form_ctx.get("my_pending_count"),
        "first_pending": first,
        "request_context": request_ctx,
        "allowed_actions": (first or {}).get("allowed_actions") or {},
        "has_signature_action": bool(first),
    }


@frappe.whitelist()
def phase26n_accept_signature_request(request_name: str, note: str = None):
    _phase26n_require_login()

    note = _phase26n_clean_note(note)

    req = _phase26d_get_request(request_name)

    if note:
        frappe.db.set_value(
            PHASE26C_REQUEST_DT,
            req.name,
            "direction_text",
            note,
            update_modified=False,
        )
        frappe.db.commit()

    result = apply_saved_signature_request(request_name)

    result["phase"] = "26N-FIX1"
    result["classic_action"] = "accept_with_note" if note else "accept"
    result["note_saved"] = bool(note)

    try:
        log_audit(
            "internal_document_signature.classic_accept",
            {
                "request": request_name,
                "note_saved": bool(note),
                "reference_doctype": result.get("reference_doctype"),
                "reference_name": result.get("reference_name"),
            },
        )
    except Exception:
        pass

    return result


@frappe.whitelist()
def phase26n_refuse_signature_request(request_name: str, reason: str = None):
    _phase26n_require_login()

    reason = _phase26n_clean_note(reason, max_len=1200)

    if not reason:
        reason = "Rejected by signer."

    result = reject_document_signature_request(
        request_name=request_name,
        reason=reason,
    )

    result["phase"] = "26N-FIX1"
    result["classic_action"] = "refusal"

    try:
        log_audit(
            "internal_document_signature.classic_refusal",
            {
                "request": request_name,
                "reason_hash": _phase26n_sha256(reason),
                "reference_doctype": result.get("reference_doctype"),
                "reference_name": result.get("reference_name"),
            },
        )
    except Exception:
        pass

    return result


@frappe.whitelist()
def phase26n_linear_guidance_signature_request(request_name: str, guidance_text: str = None, direction_svg: str = None):
    _phase26n_require_login()

    guidance_text = _phase26n_clean_note(guidance_text, max_len=1500)
    direction_svg = (direction_svg or "").strip()

    if not guidance_text and not direction_svg:
        frappe.throw("Guidance text or drawing is required.")

    result = apply_direction_signature_request(
        request_name=request_name,
        direction_text=guidance_text,
        direction_svg=direction_svg,
    )

    result["phase"] = "26N-FIX1"
    result["classic_action"] = "linear_guidance"

    try:
        log_audit(
            "internal_document_signature.classic_linear_guidance",
            {
                "request": request_name,
                "has_text": bool(guidance_text),
                "has_drawing": bool(direction_svg),
                "reference_doctype": result.get("reference_doctype"),
                "reference_name": result.get("reference_name"),
            },
        )
    except Exception:
        pass

    return result


def _phase26n_client_script_code(reference_doctype: str):
    import json
    doctype_json = json.dumps(reference_doctype)

    code = r'''
// Surhan Signature Phase 26N-FIX1 - Secure Classic AC Footer Signing UX

frappe.ui.form.on(__DOCTYPE_JSON__, {
  refresh: function(frm) {
    if (!frm || !frm.doc || frm.is_new()) return;

    if (!window.surhan_signature_phase26n_fix1) {
      window.surhan_signature_phase26n_fix1 = (function() {
        const GROUP = __('Internal Signature');

        function esc(value) {
          if (frappe.utils && frappe.utils.escape_html) {
            return frappe.utils.escape_html(String(value || ''));
          }
          return String(value || '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
        }

        function call(method, args, message) {
          return frappe.call({
            method: method,
            args: args || {},
            freeze: true,
            freeze_message: message || __('Processing signature action...')
          });
        }

        function showJSON(title, data) {
          const d = new frappe.ui.Dialog({
            title: title,
            size: 'large',
            fields: [
              {
                fieldtype: 'Code',
                fieldname: 'json',
                label: __('Result'),
                options: 'JSON',
                read_only: 1
              }
            ],
            primary_action_label: __('Close'),
            primary_action: function() {
              d.hide();
            }
          });

          d.set_value('json', JSON.stringify(data || {}, null, 2));
          d.show();
        }

        function loadContext(frm) {
          return call(
            'surhan_signature.api.phase26n_get_classic_signature_context',
            {
              reference_doctype: frm.doc.doctype,
              reference_name: frm.doc.name
            },
            __('Loading signature context...')
          );
        }

        function accept(frm, requestName, note) {
          return call(
            'surhan_signature.api.phase26n_accept_signature_request',
            {
              request_name: requestName,
              note: note || ''
            },
            __('Applying saved signature...')
          ).then(function(r) {
            const data = r.message || r;
            frappe.show_alert({
              message: __('Signature accepted successfully.'),
              indicator: 'green'
            });
            showJSON(__('Signature Accepted'), data);
            frm.reload_doc();
          });
        }

        function refuse(frm, requestName, reason) {
          return call(
            'surhan_signature.api.phase26n_refuse_signature_request',
            {
              request_name: requestName,
              reason: reason || ''
            },
            __('Rejecting / returning signature request...')
          ).then(function(r) {
            const data = r.message || r;
            frappe.show_alert({
              message: __('Signature request rejected / returned.'),
              indicator: 'red'
            });
            showJSON(__('Signature Refusal'), data);
            frm.reload_doc();
          });
        }

        function linearGuidance(frm, requestName, guidanceText, directionSvg) {
          return call(
            'surhan_signature.api.phase26n_linear_guidance_signature_request',
            {
              request_name: requestName,
              guidance_text: guidanceText || '',
              direction_svg: directionSvg || ''
            },
            __('Saving linear guidance...')
          ).then(function(r) {
            const data = r.message || r;
            frappe.show_alert({
              message: __('Linear guidance saved successfully.'),
              indicator: 'green'
            });
            showJSON(__('Linear Guidance Saved'), data);
            frm.reload_doc();
          });
        }

        function badge(text, color) {
          return '<span style="display:inline-block;border:1px solid ' + color + ';color:' + color + ';border-radius:999px;padding:5px 10px;margin:3px;font-weight:800;font-size:12px;">' + esc(text) + '</span>';
        }

        function openSignatureDialog(frm, ctx) {
          const first = ctx.first_pending || {};
          const actions = ctx.allowed_actions || {};
          const reqName = first.name;

          if (!reqName) {
            showJSON(__('No Pending Signature'), ctx);
            return;
          }

          let html = '';
          html += '<div style="line-height:1.6">';
          html += '<div style="border:1px solid #e5e7eb;border-radius:14px;padding:12px;margin-bottom:12px;background:#f9fafb;">';
          html += '<div style="font-size:17px;font-weight:900;margin-bottom:4px;">' + esc(frm.doc.doctype) + ' / ' + esc(frm.doc.name) + '</div>';
          html += '<div style="color:#6b7280;font-size:13px;">Request: <b>' + esc(reqName) + '</b></div>';
          html += '<div style="color:#6b7280;font-size:13px;">Signer: <b>' + esc(first.full_name || first.requested_user || '') + '</b></div>';
          html += '<div style="margin-top:8px;">';
          html += badge('Saved Signature: ' + (actions.saved_signature ? 'Allowed' : 'Blocked'), actions.saved_signature ? '#059669' : '#dc2626');
          html += badge('Direction: ' + (actions.direction ? 'Allowed' : 'Blocked'), actions.direction ? '#b45309' : '#dc2626');
          html += badge('Reject: ' + (actions.reject ? 'Allowed' : 'Blocked'), actions.reject ? '#dc2626' : '#6b7280');
          html += '</div></div>';

          html += '<div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;">';
          html += '<button class="btn btn-primary" id="surhan26n_accept" ' + (actions.saved_signature ? '' : 'disabled') + '>موافقة</button>';
          html += '<button class="btn btn-default" id="surhan26n_accept_note" ' + (actions.saved_signature ? '' : 'disabled') + '>موافقة مع ملاحظة</button>';
          html += '<button class="btn btn-danger" id="surhan26n_refuse" ' + (actions.reject ? '' : 'disabled') + '>رفض</button>';
          html += '<button class="btn btn-default" id="surhan26n_refuse_note" ' + (actions.reject ? '' : 'disabled') + '>رفض مع ملاحظة</button>';
          html += '<button class="btn btn-warning" id="surhan26n_guidance" ' + (actions.direction ? '' : 'disabled') + ' style="grid-column:1 / -1;">توجيه خطي / رسم يدوي</button>';
          html += '</div>';

          html += '<div style="margin-top:12px;color:#6b7280;font-size:12px;">كل إجراء هنا يمر عبر خادم التوقيع الآمن، ولا يتم تعديل حالة التوقيع من المتصفح مباشرة.</div>';
          html += '</div>';

          const d = new frappe.ui.Dialog({
            title: __('Signature'),
            size: 'large',
            fields: [
              {
                fieldtype: 'HTML',
                fieldname: 'signature_html',
                options: html
              }
            ],
            primary_action_label: __('Close'),
            primary_action: function() {
              d.hide();
            }
          });

          d.show();

          setTimeout(function() {
            const acceptBtn = document.getElementById('surhan26n_accept');
            const acceptNoteBtn = document.getElementById('surhan26n_accept_note');
            const refuseBtn = document.getElementById('surhan26n_refuse');
            const refuseNoteBtn = document.getElementById('surhan26n_refuse_note');
            const guidanceBtn = document.getElementById('surhan26n_guidance');

            if (acceptBtn) {
              acceptBtn.onclick = function() {
                frappe.confirm(__('Apply your saved signature?'), function() {
                  d.hide();
                  accept(frm, reqName, '');
                });
              };
            }

            if (acceptNoteBtn) {
              acceptNoteBtn.onclick = function() {
                frappe.prompt(
                  [
                    {
                      fieldname: 'note',
                      fieldtype: 'Small Text',
                      label: __('Acceptance Note'),
                      reqd: 1
                    }
                  ],
                  function(values) {
                    d.hide();
                    accept(frm, reqName, values.note || '');
                  },
                  __('Accept with Note'),
                  __('Accept')
                );
              };
            }

            if (refuseBtn) {
              refuseBtn.onclick = function() {
                frappe.confirm(__('Reject / return this signature request without a detailed note?'), function() {
                  d.hide();
                  refuse(frm, reqName, 'Rejected by signer.');
                });
              };
            }

            if (refuseNoteBtn) {
              refuseNoteBtn.onclick = function() {
                frappe.prompt(
                  [
                    {
                      fieldname: 'reason',
                      fieldtype: 'Small Text',
                      label: __('Refusal / Return Reason'),
                      reqd: 1
                    }
                  ],
                  function(values) {
                    d.hide();
                    refuse(frm, reqName, values.reason || '');
                  },
                  __('Reject / Return with Note'),
                  __('Reject / Return')
                );
              };
            }

            if (guidanceBtn) {
              guidanceBtn.onclick = function() {
                d.hide();
                openGuidanceCanvas(frm, reqName);
              };
            }
          }, 300);
        }

        function openGuidanceCanvas(frm, requestName) {
          const html = ''
            + '<div>'
            + '<p style="color:#6b7280;margin-top:0;">اكتب توجيهك أو ارسمه بخط اليد، ثم اضغط حفظ التوجيه.</p>'
            + '<textarea id="surhan26n_guidance_text" class="form-control" rows="4" placeholder="اكتب التوجيه هنا..." style="margin-bottom:12px;"></textarea>'
            + '<div style="display:flex;gap:8px;margin-bottom:8px;align-items:center;">'
            + '<button class="btn btn-default btn-sm" id="surhan26n_undo">Undo</button>'
            + '<button class="btn btn-default btn-sm" id="surhan26n_clear">Clear</button>'
            + '<label style="margin:0;color:#6b7280;">Pen</label>'
            + '<input id="surhan26n_pen" type="range" min="1" max="8" value="3">'
            + '</div>'
            + '<div style="border:1px solid #d1d5db;border-radius:14px;overflow:hidden;background:#fff;">'
            + '<canvas id="surhan26n_canvas" style="width:100%;height:280px;display:block;touch-action:none;cursor:crosshair;"></canvas>'
            + '</div>'
            + '</div>';

          const d = new frappe.ui.Dialog({
            title: __('Linear Guidance / Handwritten Direction'),
            size: 'large',
            fields: [
              {
                fieldtype: 'HTML',
                fieldname: 'canvas_html',
                options: html
              }
            ],
            primary_action_label: __('Save Guidance'),
            primary_action: function() {
              const text = document.getElementById('surhan26n_guidance_text').value || '';
              const svg = canvasState.exportSVG();

              if (!text.trim() && !svg) {
                frappe.msgprint(__('Write guidance text or draw something first.'));
                return;
              }

              d.hide();
              linearGuidance(frm, requestName, text, svg);
            }
          });

          let canvasState = null;

          d.show();

          setTimeout(function() {
            canvasState = setupCanvas();
          }, 350);
        }

        function setupCanvas() {
          const canvas = document.getElementById('surhan26n_canvas');
          const pen = document.getElementById('surhan26n_pen');
          const undo = document.getElementById('surhan26n_undo');
          const clear = document.getElementById('surhan26n_clear');

          const ctx = canvas.getContext('2d');
          let strokes = [];
          let current = null;
          let drawing = false;

          function resize() {
            const ratio = Math.max(window.devicePixelRatio || 1, 1);
            const rect = canvas.getBoundingClientRect();
            canvas.width = Math.floor(rect.width * ratio);
            canvas.height = Math.floor(rect.height * ratio);
            ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
            redraw();
          }

          function point(e) {
            const rect = canvas.getBoundingClientRect();
            return {
              x: +(e.clientX - rect.left).toFixed(2),
              y: +(e.clientY - rect.top).toFixed(2),
              p: +(e.pressure && e.pressure > 0 ? e.pressure : 0.55).toFixed(3)
            };
          }

          function drawStroke(stroke) {
            if (!stroke || stroke.length < 2) return;

            ctx.save();
            ctx.lineCap = 'round';
            ctx.lineJoin = 'round';
            ctx.strokeStyle = '#111827';
            ctx.lineWidth = Number(pen.value || 3);

            ctx.beginPath();
            ctx.moveTo(stroke[0].x, stroke[0].y);

            for (let i = 1; i < stroke.length - 1; i++) {
              const p0 = stroke[i];
              const p1 = stroke[i + 1];
              const mx = (p0.x + p1.x) / 2;
              const my = (p0.y + p1.y) / 2;
              ctx.quadraticCurveTo(p0.x, p0.y, mx, my);
            }

            const last = stroke[stroke.length - 1];
            ctx.lineTo(last.x, last.y);
            ctx.stroke();
            ctx.restore();
          }

          function redraw() {
            const rect = canvas.getBoundingClientRect();
            ctx.clearRect(0, 0, rect.width, rect.height);

            for (const s of strokes) drawStroke(s);
            if (current) drawStroke(current);
          }

          function start(e) {
            e.preventDefault();
            drawing = true;
            current = [point(e)];
          }

          function move(e) {
            if (!drawing || !current) return;
            e.preventDefault();

            const pt = point(e);
            const last = current[current.length - 1];
            const dx = pt.x - last.x;
            const dy = pt.y - last.y;

            if (Math.sqrt(dx * dx + dy * dy) < 1.4) return;

            current.push(pt);
            redraw();
          }

          function end(e) {
            if (!drawing || !current) return;
            e.preventDefault();

            drawing = false;

            if (current.length > 1) strokes.push(current);

            current = null;
            redraw();
          }

          function pathForStroke(stroke) {
            if (!stroke || stroke.length < 2) return '';

            let d = 'M ' + stroke[0].x + ' ' + stroke[0].y;

            for (let i = 1; i < stroke.length - 1; i++) {
              const p0 = stroke[i];
              const p1 = stroke[i + 1];
              const mx = ((p0.x + p1.x) / 2).toFixed(2);
              const my = ((p0.y + p1.y) / 2).toFixed(2);
              d += ' Q ' + p0.x + ' ' + p0.y + ' ' + mx + ' ' + my;
            }

            const last = stroke[stroke.length - 1];
            d += ' L ' + last.x + ' ' + last.y;

            return d;
          }

          function exportSVG() {
            if (!strokes.length) return '';

            const rect = canvas.getBoundingClientRect();
            const width = Math.round(rect.width);
            const height = Math.round(rect.height);
            const strokeWidth = Number(pen.value || 3);

            const paths = strokes.map(function(stroke) {
              const d = pathForStroke(stroke);
              return '<path d="' + d + '" fill="none" stroke="#111827" stroke-width="' + strokeWidth + '" stroke-linecap="round" stroke-linejoin="round"/>';
            }).join('\\n');

            return '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '"><rect width="100%" height="100%" fill="none"/><g>' + paths + '</g></svg>';
          }

          canvas.addEventListener('pointerdown', start);
          canvas.addEventListener('pointermove', move);
          canvas.addEventListener('pointerup', end);
          canvas.addEventListener('pointercancel', end);
          canvas.addEventListener('pointerleave', function(e) {
            if (drawing) end(e);
          });

          undo.onclick = function() {
            strokes.pop();
            redraw();
          };

          clear.onclick = function() {
            strokes = [];
            current = null;
            redraw();
          };

          window.addEventListener('resize', resize);
          resize();

          return {
            exportSVG: exportSVG
          };
        }

        function load(frm) {
          loadContext(frm).then(function(r) {
            const ctx = r.message || r;

            frm.__surhan_phase26n_context = ctx;

            if (ctx && ctx.has_signature_action) {
              if (frm.dashboard) {
                frm.dashboard.add_indicator(__('Signature Action Required'), 'orange');
              }

              frm.add_custom_button(__('Signature'), function() {
                openSignatureDialog(frm, ctx);
              }, GROUP);
            } else if (ctx && ctx.complete) {
              frm.add_custom_button(__('Signature Completed'), function() {
                showJSON(__('Signature State'), ctx);
              }, GROUP);
            }
          }).catch(function(e) {
            console.warn('Surhan Signature Phase 26N-FIX1 failed', e);
          });
        }

        return {
          load: load
        };
      })();
    }

    window.surhan_signature_phase26n_fix1.load(frm);
  }
});
'''
    return code.replace("__DOCTYPE_JSON__", doctype_json)


@frappe.whitelist()
def phase26n_install_classic_client_script(reference_doctype: str):
    _phase26n_require_admin()

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists("DocType", reference_doctype):
        frappe.throw(f"DocType does not exist: {reference_doctype}")

    if not frappe.db.exists("DocType", "Client Script"):
        frappe.throw("Client Script DocType is not available.")

    script_name = f"Surhan Classic Signature UX - {reference_doctype}"
    script_code = _phase26n_client_script_code(reference_doctype)

    existing = frappe.db.exists("Client Script", script_name)

    if existing:
        doc = frappe.get_doc("Client Script", existing)
        action = "updated"
    else:
        doc = frappe.new_doc("Client Script")
        doc.name = script_name
        action = "created"

    doc.dt = reference_doctype
    doc.script = script_code
    doc.enabled = 1

    meta = frappe.get_meta("Client Script")

    if meta.has_field("view"):
        doc.view = "Form"

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache(doctype=reference_doctype)

    return {
        "ok": True,
        "phase": "26N-FIX1",
        "action": action,
        "client_script": doc.name,
        "reference_doctype": reference_doctype,
        "enabled": bool(doc.enabled),
    }


@frappe.whitelist()
def phase26n_install_classic_client_scripts_for_policies():
    _phase26n_require_admin()

    doctypes = set()

    if frappe.db.exists("DocType", "Internal Signature Policy"):
        rows = frappe.get_all(
            "Internal Signature Policy",
            filters={"is_active": 1},
            fields=["reference_doctype"],
            limit_page_length=500,
        )

        for r in rows:
            if r.reference_doctype and frappe.db.exists("DocType", r.reference_doctype):
                doctypes.add(r.reference_doctype)

    if "PHASE26C_DEMO_DT" in globals() and frappe.db.exists("DocType", PHASE26C_DEMO_DT):
        doctypes.add(PHASE26C_DEMO_DT)

    results = []

    for dt in sorted(doctypes):
        try:
            results.append(phase26n_install_classic_client_script(dt))
        except Exception as exc:
            results.append({
                "ok": False,
                "reference_doctype": dt,
                "error": str(exc),
            })

    return {
        "ok": True,
        "phase": "26N-FIX1",
        "count": len(results),
        "installed": [r for r in results if r.get("ok")],
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase26n_create_classic_task_demo():
    _phase26n_require_admin()

    if not frappe.db.exists("DocType", "Task"):
        frappe.throw("Task DocType is not available.")

    if globals().get("phase26k_enable_doctype"):
        phase26k_enable_doctype(
            "Task",
            workflow_mode="Sequential",
            allow_external_requests=1,
            add_to_external_systems=0,
        )

    identity = _phase26c_identity_from_employee_or_user(user=frappe.session.user)

    if not identity.get("employee"):
        frappe.throw("Current user has no linked Employee.")

    doc = frappe.new_doc("Task")
    doc.subject = "Phase 26N Classic UX Pending Signature Test"
    doc.description = """
        <h2>Phase 26N Classic Signature UX Test</h2>
        <p>This real Task is created to test the simple Signature dialog: Accept, Accept with Note, Refusal, Refusal with Note, and Linear Guidance.</p>
    """

    try:
        doc.status = "Open"
    except Exception:
        pass

    doc.append("ac_footer", {
        "employee": identity.get("employee"),
        "user": identity.get("user"),
        "full_name": identity.get("full_name"),
        "designation": identity.get("designation"),
        "department": identity.get("department"),
        "sign_order": 1,
        "action_required": "Both",
        "can_use_saved_signature": 1,
        "can_draw_direction": 1,
        "can_write_direction_text": 1,
        "can_reject": 1,
        "status": "Draft",
        "notes": "Phase 26N Classic UX pending test.",
    })

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    sync = sync_ac_footer_requests(doc.doctype, doc.name)
    ctx = phase26n_get_classic_signature_context(doc.doctype, doc.name)

    return {
        "ok": True,
        "phase": "26N-FIX1",
        "doctype": doc.doctype,
        "name": doc.name,
        "document_url": _phase26n_doc_url(doc.doctype, doc.name),
        "signed_print_url": _phase26n_signed_print_url(doc.doctype, doc.name),
        "sync": sync,
        "context": ctx,
        "request": (ctx.get("first_pending") or {}).get("name"),
        "action_url": f"/document-sign-action?request={(ctx.get('first_pending') or {}).get('name')}" if ctx.get("first_pending") else None,
        "ready": bool(ctx.get("has_signature_action")),
    }


@frappe.whitelist()
def phase26n_classic_ux_health():
    _phase26n_require_admin()

    install = phase26n_install_classic_client_scripts_for_policies()

    demo = None

    try:
        demo = phase26n_create_classic_task_demo()
    except Exception as exc:
        demo = {
            "ok": False,
            "error": str(exc),
        }

    return {
        "ok": True,
        "phase": "26N-FIX1",
        "installed_count": len(install.get("installed") or []),
        "failed_count": len(install.get("failed") or []),
        "install": install,
        "demo": demo,
        "ready": bool(
            install.get("ok")
            and not install.get("failed")
            and demo
            and demo.get("ready")
        ),
    }


@frappe.whitelist()
def phase26n_export_classic_ux_snapshot_json():
    health = phase26n_classic_ux_health()
    sha = _phase26n_sha256(health)
    content = _phase26n_json_dumps(health).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26n-classic-signature-ux-snapshot-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26N-FIX1",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "ready": health.get("ready"),
        "demo_document_url": ((health.get("demo") or {}).get("document_url")),
        "demo_request": ((health.get("demo") or {}).get("request")),
    }


# Phase 26O: Production Hardening + Readiness Report.
import json as _phase26o_json
import hashlib as _phase26o_hashlib
import secrets as _phase26o_secrets


def _phase26o_json_dumps(data):
    return _phase26o_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase26o_sha256(data):
    if not isinstance(data, str):
        data = _phase26o_json_dumps(data)
    return _phase26o_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase26o_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
        "Internal Signature API User",
    }))


def _phase26o_require_admin():
    if not _phase26o_is_admin():
        frappe.throw("Only Internal Signature Administrator / Manager / Auditor can access production readiness.")


def _phase26o_dt(name):
    return frappe.db.exists("DocType", name)


def _phase26o_count(doctype, filters=None):
    if not _phase26o_dt(doctype):
        return 0
    try:
        return frappe.db.count(doctype, filters=filters or {})
    except Exception:
        return 0


def _phase26o_status_counts(doctype, fieldname):
    if not _phase26o_dt(doctype):
        return {}

    try:
        meta = frappe.get_meta(doctype)
        if not meta.has_field(fieldname):
            return {}

        rows = frappe.db.sql(
            f"""
            SELECT `{fieldname}` AS status_value, COUNT(`name`) AS count_value
            FROM `tab{doctype}`
            GROUP BY `{fieldname}`
            """,
            as_dict=True,
        )

        return {
            (r.get("status_value") or "Blank"): int(r.get("count_value") or 0)
            for r in rows
        }
    except Exception:
        return {}


def _phase26o_doc_url(doctype, name):
    if not doctype or not name:
        return None
    return f"/app/{frappe.scrub(doctype).replace('_', '-')}/{name}"


def _phase26o_secret(prefix="ssec_"):
    try:
        return prefix + frappe.generate_hash(length=40)
    except Exception:
        return prefix + _phase26o_secrets.token_hex(20)


def _phase26o_hash_secret(secret):
    if globals().get("_phase26h_hash_secret"):
        try:
            return _phase26h_hash_secret(secret)
        except Exception:
            pass

    return _phase26o_hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _phase26o_set_gateway_secret(system_name, secret):
    if globals().get("_phase26h_set_encrypted_secret"):
        try:
            _phase26h_set_encrypted_secret(system_name, secret)
            return True
        except Exception:
            return False

    return False


def _phase26o_is_test_external_system(doc):
    text = " ".join([
        str(doc.get("name") or ""),
        str(doc.get("system_id") or ""),
        str(doc.get("system_name") or ""),
        str(doc.get("notes") or ""),
    ]).lower()

    markers = [
        "demo-external-system",
        "phase26i-test-system",
        "demo external system",
        "phase 26i test",
        "test external system",
    ]

    return any(m in text for m in markers)


@frappe.whitelist()
def phase26o_disable_and_rotate_test_external_systems():
    _phase26o_require_admin()

    system_dt = "Internal Signature External System"

    if not _phase26o_dt(system_dt):
        return {
            "ok": True,
            "phase": "26O",
            "updated": [],
            "reason": "External gateway system DocType is not installed.",
        }

    rows = frappe.get_all(
        system_dt,
        fields=[
            "name",
            "system_id",
            "system_name",
            "is_active",
            "gateway_api_key",
            "require_hmac",
            "notes",
        ],
        limit_page_length=500,
    )

    updated = []
    skipped = []

    for r in rows:
        if not _phase26o_is_test_external_system(r):
            skipped.append({
                "name": r.name,
                "system_id": r.system_id,
                "reason": "not_test_system",
            })
            continue

        doc = frappe.get_doc(system_dt, r.name)
        old_key_prefix = (doc.gateway_api_key or "")[:12]

        new_api_key = "sgw_disabled_" + _phase26o_secrets.token_hex(12)
        new_secret = _phase26o_secret("ssec_disabled_")

        doc.gateway_api_key = new_api_key
        doc.api_secret_hash = _phase26o_hash_secret(new_secret)

        if hasattr(doc, "is_active"):
            doc.is_active = 0

        if hasattr(doc, "allow_create_requests"):
            doc.allow_create_requests = 0

        if hasattr(doc, "allow_status_lookup"):
            doc.allow_status_lookup = 0

        if hasattr(doc, "allow_callback_delivery"):
            doc.allow_callback_delivery = 0

        if hasattr(doc, "require_hmac"):
            doc.require_hmac = 1

        existing_notes = doc.notes or ""
        stamp = f"Disabled and rotated by Phase 26O at {now_datetime()}."
        doc.notes = (existing_notes + "\n" + stamp).strip()

        doc.save(ignore_permissions=True)

        encrypted_rotated = _phase26o_set_gateway_secret(doc.name, new_secret)

        updated.append({
            "name": doc.name,
            "system_id": doc.system_id,
            "system_name": doc.system_name,
            "old_gateway_api_key_prefix": old_key_prefix,
            "new_gateway_api_key_prefix": new_api_key[:18],
            "api_secret_rotated": True,
            "hmac_secret_rotated": bool(encrypted_rotated),
            "is_active": bool(doc.is_active),
            "allow_create_requests": bool(getattr(doc, "allow_create_requests", 0)),
            "allow_status_lookup": bool(getattr(doc, "allow_status_lookup", 0)),
            "allow_callback_delivery": bool(getattr(doc, "allow_callback_delivery", 0)),
        })

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "26O",
        "updated_count": len(updated),
        "updated": updated,
        "skipped": skipped,
        "secret_policy": "New secrets were generated and stored, but not returned.",
    }


def _phase26o_scan_external_systems():
    system_dt = "Internal Signature External System"

    if not _phase26o_dt(system_dt):
        return {
            "installed": False,
            "active": [],
            "inactive": [],
            "warnings": [],
            "blockers": [],
        }

    rows = frappe.get_all(
        system_dt,
        fields=[
            "name",
            "system_id",
            "system_name",
            "is_active",
            "gateway_api_key",
            "api_secret_hash",
            "require_hmac",
            "allow_create_requests",
            "allow_status_lookup",
            "allow_callback_delivery",
            "default_callback_url",
            "notes",
        ],
        limit_page_length=500,
        order_by="modified desc",
    )

    active = []
    inactive = []
    warnings = []
    blockers = []

    for r in rows:
        item = {
            "name": r.name,
            "system_id": r.system_id,
            "system_name": r.system_name,
            "is_active": bool(r.is_active),
            "gateway_api_key_prefix": (r.gateway_api_key or "")[:16],
            "has_api_secret_hash": bool(r.api_secret_hash),
            "require_hmac": bool(r.require_hmac),
            "allow_create_requests": bool(r.allow_create_requests),
            "allow_status_lookup": bool(r.allow_status_lookup),
            "allow_callback_delivery": bool(r.allow_callback_delivery),
            "default_callback_url": r.default_callback_url,
            "is_test_system": _phase26o_is_test_external_system(r),
        }

        if item["is_active"]:
            active.append(item)

            if item["is_test_system"]:
                blockers.append(f"Test external system is still active: {r.system_id or r.name}")

            if not item["require_hmac"]:
                blockers.append(f"Active external system does not require HMAC: {r.system_id or r.name}")

            if not item["gateway_api_key_prefix"]:
                blockers.append(f"Active external system has no API key: {r.system_id or r.name}")

            if not item["has_api_secret_hash"]:
                blockers.append(f"Active external system has no API secret hash: {r.system_id or r.name}")

            if item["default_callback_url"] and str(item["default_callback_url"]).startswith("dry-run://"):
                warnings.append(f"Active external system uses dry-run callback URL: {r.system_id or r.name}")

        else:
            inactive.append(item)

    return {
        "installed": True,
        "active": active,
        "inactive": inactive,
        "warnings": warnings,
        "blockers": blockers,
        "active_count": len(active),
        "inactive_count": len(inactive),
    }


def _phase26o_classic_scripts_summary():
    if not _phase26o_dt("Client Script"):
        return {
            "installed": False,
            "count": 0,
            "items": [],
        }

    rows = frappe.get_all(
        "Client Script",
        filters={"name": ["like", "Surhan Classic Signature UX -%"]},
        fields=["name", "dt", "enabled"],
        limit_page_length=500,
        order_by="dt asc",
    )

    return {
        "installed": True,
        "count": len(rows),
        "enabled_count": sum(1 for r in rows if int(r.enabled or 0)),
        "items": rows,
    }


def _phase26o_rollout_summary():
    if globals().get("phase26k_rollout_health"):
        try:
            return phase26k_rollout_health()
        except Exception as exc:
            return {
                "ok": False,
                "error": str(exc),
            }

    return {
        "ok": False,
        "reason": "phase26k_rollout_health is not installed.",
    }


def _phase26o_verify_recent_internal_certificates(limit=10):
    cert_dt = "Internal Signature Certificate"

    if not _phase26o_dt(cert_dt):
        return {
            "installed": False,
            "count": 0,
            "valid_count": 0,
            "invalid": [],
            "items": [],
        }

    names = frappe.get_all(
        cert_dt,
        pluck="name",
        order_by="modified desc",
        limit_page_length=int(limit or 10),
    )

    items = []
    invalid = []

    for name in names:
        try:
            doc = frappe.get_doc(cert_dt, name)
            code = doc.get("verification_code") or doc.name
            result = verify_internal_signature_certificate(code)

            item = {
                "certificate": name,
                "verification_code": code,
                "valid": bool(result.get("valid")),
                "reference_doctype": result.get("reference_doctype") or doc.get("reference_doctype"),
                "reference_name": result.get("reference_name") or doc.get("reference_name"),
                "signed_pdf_sha256_matches": result.get("signed_pdf_sha256_matches"),
                "verification_url": result.get("verification_url") or doc.get("verification_url"),
            }

            if not item["valid"]:
                invalid.append(item)

            items.append(item)

        except Exception as exc:
            item = {
                "certificate": name,
                "valid": False,
                "error": str(exc),
            }
            items.append(item)
            invalid.append(item)

    return {
        "installed": True,
        "count": len(items),
        "valid_count": sum(1 for x in items if x.get("valid")),
        "invalid_count": len(invalid),
        "invalid": invalid,
        "items": items,
    }


def _phase26o_email_status():
    try:
        outgoing = frappe.get_all(
            "Email Account",
            filters={
                "default_outgoing": 1,
                "enable_outgoing": 1,
            },
            fields=["name", "email_id"],
            limit=1,
        )

        return {
            "configured": bool(outgoing),
            "account": outgoing[0] if outgoing else None,
        }
    except Exception as exc:
        return {
            "configured": False,
            "error": str(exc),
        }


def _phase26o_site_flags():
    return {
        "developer_mode": bool(frappe.conf.get("developer_mode")),
        "server_script_enabled": bool(frappe.conf.get("server_script_enabled")),
        "host_name": frappe.conf.get("host_name"),
        "webserver_port": frappe.conf.get("webserver_port"),
    }


@frappe.whitelist()
def phase26o_production_readiness_report(run_cleanup: int = 0):
    _phase26o_require_admin()

    cleanup = None

    if int(run_cleanup or 0):
        cleanup = phase26o_disable_and_rotate_test_external_systems()

    core_doctypes = [
        "Employee Signature Profile",
        "Document Signature Request",
        "AC Footer Signer",
        "Internal Signature Policy",
        "Internal Signature Permission",
        "Internal Signature Certificate",
        "Internal Signature External System",
        "Internal Signature External Request",
    ]

    doctype_status = {
        dt: bool(_phase26o_dt(dt))
        for dt in core_doctypes
    }

    request_dt = "Document Signature Request"
    cert_dt = "Internal Signature Certificate"

    counts = {
        "signature_profiles": _phase26o_count("Employee Signature Profile"),
        "active_signature_profiles": _phase26o_count("Employee Signature Profile", {"is_active": 1}) if _phase26o_dt("Employee Signature Profile") else 0,
        "document_signature_requests": _phase26o_count(request_dt),
        "internal_certificates": _phase26o_count(cert_dt),
        "active_policies": _phase26o_count("Internal Signature Policy", {"is_active": 1}) if _phase26o_dt("Internal Signature Policy") else 0,
        "external_systems": _phase26o_count("Internal Signature External System"),
        "external_requests": _phase26o_count("Internal Signature External Request"),
    }

    request_status_counts = _phase26o_status_counts(request_dt, "status")
    certificate_status_counts = _phase26o_status_counts(cert_dt, "certificate_status")

    rollout = _phase26o_rollout_summary()
    classic = _phase26o_classic_scripts_summary()
    external_scan = _phase26o_scan_external_systems()
    cert_verify = _phase26o_verify_recent_internal_certificates(limit=10)
    email = _phase26o_email_status()
    site_flags = _phase26o_site_flags()

    blockers = []
    warnings = []

    missing = [dt for dt, ok in doctype_status.items() if not ok]
    if missing:
        blockers.append("Missing core DocTypes: " + ", ".join(missing))

    if counts["active_signature_profiles"] < 1:
        blockers.append("No active Employee Signature Profile found.")

    if counts["active_policies"] < 1:
        blockers.append("No active Internal Signature Policy found.")

    if not classic.get("enabled_count"):
        blockers.append("Classic Signature UX client scripts are not enabled.")

    if external_scan.get("blockers"):
        blockers.extend(external_scan.get("blockers"))

    if cert_verify.get("invalid_count"):
        warnings.append(f"{cert_verify.get('invalid_count')} recent certificate(s) failed verification.")

    if request_status_counts.get("Rejected"):
        warnings.append(f"{request_status_counts.get('Rejected')} signature request(s) are rejected.")

    if request_status_counts.get("Pending"):
        warnings.append(f"{request_status_counts.get('Pending')} signature request(s) are still pending.")

    if not email.get("configured"):
        warnings.append("Default outgoing Email Account is not configured. Internal signing still works; email notifications may not.")

    if site_flags.get("developer_mode"):
        warnings.append("developer_mode is enabled. Disable it before final production deployment.")

    if external_scan.get("warnings"):
        warnings.extend(external_scan.get("warnings"))

    staging_ready = bool(not blockers)
    production_ready = bool(staging_ready and not site_flags.get("developer_mode"))

    report = {
        "ok": True,
        "phase": "26O",
        "generated_at": str(now_datetime()),
        "cleanup": cleanup,
        "readiness": {
            "staging_ready": staging_ready,
            "production_ready": production_ready,
            "blocker_count": len(blockers),
            "warning_count": len(warnings),
        },
        "blockers": blockers,
        "warnings": warnings,
        "site_flags": site_flags,
        "email": email,
        "doctype_status": doctype_status,
        "counts": counts,
        "request_status_counts": request_status_counts,
        "certificate_status_counts": certificate_status_counts,
        "rollout": rollout,
        "classic_signature_ux": classic,
        "external_gateway_security": external_scan,
        "recent_certificate_verification": cert_verify,
        "routes": {
            "signature_dashboard": "/signature-dashboard",
            "rollout_console": "/internal-signature-rollout",
            "external_console": "/external-signature-console",
            "production_readiness": "/signature-production-readiness",
            "signature_profile": "/signature-profile",
        },
    }

    return report


@frappe.whitelist()
def phase26o_export_production_readiness_report(run_cleanup: int = 0):
    report = phase26o_production_readiness_report(run_cleanup=run_cleanup)
    sha = _phase26o_sha256(report)
    content = _phase26o_json_dumps(report).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase26o-production-readiness-report-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "26O",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "readiness": report.get("readiness"),
        "blockers": report.get("blockers"),
        "warnings": report.get("warnings"),
    }


@frappe.whitelist()
def phase26o_hardening_health():
    cleanup = phase26o_disable_and_rotate_test_external_systems()
    report = phase26o_production_readiness_report(run_cleanup=0)
    export = phase26o_export_production_readiness_report(run_cleanup=0)

    return {
        "ok": True,
        "phase": "26O",
        "cleanup": cleanup,
        "readiness": report.get("readiness"),
        "blockers": report.get("blockers"),
        "warnings": report.get("warnings"),
        "export": export,
        "routes": report.get("routes"),
        "ready": bool(report.get("readiness", {}).get("staging_ready")),
    }


# Phase 27A: Central Signature Admin Control Center.
import json as _phase27a_json
import hashlib as _phase27a_hashlib


PHASE27A_SETTINGS_DT = "Signature System Settings"
PHASE27A_DTC_DT = "Signature DocType Control"
PHASE27A_EMP_DT = "Signature Employee Control"


def _phase27a_json_dumps(data):
    return _phase27a_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27a_sha256(data):
    if not isinstance(data, str):
        data = _phase27a_json_dumps(data)
    return _phase27a_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27a_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase27a_require_admin():
    if not _phase27a_is_admin():
        frappe.throw("Only Signature Administrators can access the Signature Admin Control Center.")




def _phase27a_role_permissions():
    roles = [
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    ]

    perms = []

    for idx, role in enumerate(roles):
        if not frappe.db.exists("Role", role):
            r = frappe.new_doc("Role")
            r.role_name = role
            r.desk_access = 1
            r.insert(ignore_permissions=True)

        perms.append({
            "role": role,
            "read": 1,
            "write": 1,
            "create": 1,
            "delete": 1 if role in {"System Manager", "Internal Signature Administrator"} else 0,
            "submit": 0,
            "cancel": 0,
            "amend": 0,
            "export": 1,
            "report": 1,
            "share": 1,
            "print": 1,
            "email": 1,
            "idx": idx + 1,
        })

    auditor = "Internal Signature Auditor"

    if frappe.db.exists("Role", auditor):
        perms.append({
            "role": auditor,
            "read": 1,
            "write": 0,
            "create": 0,
            "delete": 0,
            "submit": 0,
            "cancel": 0,
            "amend": 0,
            "export": 1,
            "report": 1,
            "share": 0,
            "print": 1,
            "email": 0,
            "idx": len(perms) + 1,
        })

    return perms




def _phase27a_install_settings_doctype():
    fields = [
        {"fieldname": "system_section", "label": "System", "fieldtype": "Section Break"},
        {"fieldname": "system_enabled", "label": "System Enabled", "fieldtype": "Check", "default": "1"},
        {"fieldname": "admin_only_employee_signatures", "label": "Only Admin Can Register Employee Signatures", "fieldtype": "Check", "default": "1"},
        {"fieldname": "show_classic_signature_button", "label": "Show Classic Signature Button", "fieldtype": "Check", "default": "1"},
        {"fieldname": "lock_signed_documents", "label": "Lock Signed Documents", "fieldtype": "Check", "default": "0"},
        {"fieldname": "defaults_section", "label": "Default Signature Policy", "fieldtype": "Section Break"},
        {"fieldname": "default_workflow_mode", "label": "Default Workflow Mode", "fieldtype": "Select", "options": "Sequential\nParallel", "default": "Sequential"},
        {"fieldname": "default_allow_saved_signature", "label": "Allow Saved Signature", "fieldtype": "Check", "default": "1"},
        {"fieldname": "default_allow_direction_text", "label": "Allow Direction Text", "fieldtype": "Check", "default": "1"},
        {"fieldname": "default_allow_direction_drawing", "label": "Allow Direction Drawing", "fieldtype": "Check", "default": "1"},
        {"fieldname": "default_allow_reject", "label": "Allow Reject / Return", "fieldtype": "Check", "default": "1"},
        {"fieldname": "require_signature_profile", "label": "Require Employee Signature Profile", "fieldtype": "Check", "default": "1"},
        {"fieldname": "certificate_section", "label": "Certificate and Verification", "fieldtype": "Section Break"},
        {"fieldname": "auto_generate_certificate", "label": "Auto Generate Certificate After Completion", "fieldtype": "Check", "default": "1"},
        {"fieldname": "auto_generate_signed_pdf", "label": "Auto Generate Signed PDF", "fieldtype": "Check", "default": "1"},
        {"fieldname": "public_verification_enabled", "label": "Public Verification Enabled", "fieldtype": "Check", "default": "1"},
        {"fieldname": "external_section", "label": "External Gateway", "fieldtype": "Section Break"},
        {"fieldname": "external_gateway_enabled", "label": "External Gateway Enabled", "fieldtype": "Check", "default": "1"},
        {"fieldname": "require_hmac_for_external_gateway", "label": "Require HMAC for External Gateway", "fieldtype": "Check", "default": "1"},
        {"fieldname": "audit_section", "label": "Audit", "fieldtype": "Section Break"},
        {"fieldname": "last_applied_at", "label": "Last Applied At", "fieldtype": "Datetime", "read_only": 1},
        {"fieldname": "last_applied_by", "label": "Last Applied By", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "admin_notes", "label": "Admin Notes", "fieldtype": "Small Text"},
    ]

    result = _phase27a_ensure_doctype(PHASE27A_SETTINGS_DT, fields, issingle=1)

    settings = frappe.get_single(PHASE27A_SETTINGS_DT)

    changed = False

    defaults = {
        "system_enabled": 1,
        "admin_only_employee_signatures": 1,
        "show_classic_signature_button": 1,
        "default_workflow_mode": "Sequential",
        "default_allow_saved_signature": 1,
        "default_allow_direction_text": 1,
        "default_allow_direction_drawing": 1,
        "default_allow_reject": 1,
        "require_signature_profile": 1,
        "auto_generate_certificate": 1,
        "auto_generate_signed_pdf": 1,
        "public_verification_enabled": 1,
        "external_gateway_enabled": 1,
        "require_hmac_for_external_gateway": 1,
    }

    for k, v in defaults.items():
        if settings.get(k) in [None, ""]:
            setattr(settings, k, v)
            changed = True

    if changed:
        settings.save(ignore_permissions=True)
        frappe.db.commit()

    return result


def _phase27a_install_doctype_control():
    fields = [
        {"fieldname": "main_section", "label": "DocType", "fieldtype": "Section Break"},
        {"fieldname": "reference_doctype", "label": "Reference DocType", "fieldtype": "Link", "options": "DocType", "reqd": 1, "unique": 1},
        {"fieldname": "enabled", "label": "Enabled", "fieldtype": "Check", "default": "1"},
        {"fieldname": "show_signature_button", "label": "Show Signature Button", "fieldtype": "Check", "default": "1"},
        {"fieldname": "allow_external_requests", "label": "Allow External Requests", "fieldtype": "Check", "default": "1"},
        {"fieldname": "policy_section", "label": "Signature Method", "fieldtype": "Section Break"},
        {"fieldname": "workflow_mode", "label": "Workflow Mode", "fieldtype": "Select", "options": "Sequential\nParallel", "default": "Sequential"},
        {"fieldname": "allow_saved_signature", "label": "Allow Saved Signature", "fieldtype": "Check", "default": "1"},
        {"fieldname": "allow_direction_text", "label": "Allow Direction Text", "fieldtype": "Check", "default": "1"},
        {"fieldname": "allow_direction_drawing", "label": "Allow Direction Drawing", "fieldtype": "Check", "default": "1"},
        {"fieldname": "allow_reject", "label": "Allow Reject / Return", "fieldtype": "Check", "default": "1"},
        {"fieldname": "require_signature_profile", "label": "Require Signature Profile", "fieldtype": "Check", "default": "1"},
        {"fieldname": "certificate_section", "label": "Certificate", "fieldtype": "Section Break"},
        {"fieldname": "auto_generate_certificate", "label": "Auto Generate Certificate", "fieldtype": "Check", "default": "1"},
        {"fieldname": "auto_generate_signed_pdf", "label": "Auto Generate Signed PDF", "fieldtype": "Check", "default": "1"},
        {"fieldname": "advanced_section", "label": "Advanced", "fieldtype": "Section Break"},
        {"fieldname": "allowed_signer_mode", "label": "Allowed Signer Mode", "fieldtype": "Select", "options": "Ac Footer\nAdmin Fixed List\nBoth", "default": "Ac Footer"},
        {"fieldname": "admin_notes", "label": "Admin Notes", "fieldtype": "Small Text"},
        {"fieldname": "audit_section", "label": "Apply State", "fieldtype": "Section Break"},
        {"fieldname": "last_applied_at", "label": "Last Applied At", "fieldtype": "Datetime", "read_only": 1},
        {"fieldname": "last_applied_by", "label": "Last Applied By", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "applied_status", "label": "Applied Status", "fieldtype": "Small Text", "read_only": 1},
    ]

    return _phase27a_ensure_doctype(
        PHASE27A_DTC_DT,
        fields,
        issingle=0,
        autoname="field:reference_doctype",
        title_field="reference_doctype",
    )


def _phase27a_install_employee_control():
    fields = [
        {"fieldname": "identity_section", "label": "Employee Identity", "fieldtype": "Section Break"},
        {"fieldname": "employee_user", "label": "User", "fieldtype": "Link", "options": "User", "reqd": 1, "unique": 1},
        {"fieldname": "employee", "label": "Employee", "fieldtype": "Link", "options": "Employee"},
        {"fieldname": "full_name", "label": "Full Name", "fieldtype": "Data"},
        {"fieldname": "designation", "label": "Designation", "fieldtype": "Data"},
        {"fieldname": "department", "label": "Department", "fieldtype": "Data"},
        {"fieldname": "is_active", "label": "Active", "fieldtype": "Check", "default": "1"},
        {"fieldname": "signature_section", "label": "Signature Profile", "fieldtype": "Section Break"},
        {"fieldname": "signature_profile", "label": "Signature Profile", "fieldtype": "Link", "options": "Employee Signature Profile", "read_only": 1},
        {"fieldname": "signature_status", "label": "Signature Status", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "signature_hash_prefix", "label": "Signature Hash Prefix", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "admin_only_signature_registration", "label": "Admin Only Signature Registration", "fieldtype": "Check", "default": "1"},
        {"fieldname": "permissions_section", "label": "Permissions", "fieldtype": "Section Break"},
        {"fieldname": "can_receive_requests", "label": "Can Receive Requests", "fieldtype": "Check", "default": "1"},
        {"fieldname": "can_use_saved_signature", "label": "Can Use Saved Signature", "fieldtype": "Check", "default": "1"},
        {"fieldname": "can_draw_direction", "label": "Can Draw Direction", "fieldtype": "Check", "default": "0"},
        {"fieldname": "can_write_direction_text", "label": "Can Write Direction Text", "fieldtype": "Check", "default": "0"},
        {"fieldname": "can_reject", "label": "Can Reject / Return", "fieldtype": "Check", "default": "0"},
        {"fieldname": "can_override_sequence", "label": "Can Override Sequence", "fieldtype": "Check", "default": "0"},
        {"fieldname": "can_manage_external_requests", "label": "Can Manage External Requests", "fieldtype": "Check", "default": "0"},
        {"fieldname": "can_view_signature_audit", "label": "Can View Signature Audit", "fieldtype": "Check", "default": "0"},
        {"fieldname": "max_sequence_level", "label": "Max Sequence Level", "fieldtype": "Int", "default": "1"},
        {"fieldname": "audit_section", "label": "Apply State", "fieldtype": "Section Break"},
        {"fieldname": "last_applied_at", "label": "Last Applied At", "fieldtype": "Datetime", "read_only": 1},
        {"fieldname": "last_applied_by", "label": "Last Applied By", "fieldtype": "Data", "read_only": 1},
        {"fieldname": "admin_notes", "label": "Admin Notes", "fieldtype": "Small Text"},
    ]

    return _phase27a_ensure_doctype(
        PHASE27A_EMP_DT,
        fields,
        issingle=0,
        autoname="field:employee_user",
        title_field="full_name",
    )


def _phase27a_default_common_doctypes():
    if globals().get("PHASE26K_COMMON_DOCTYPES"):
        return list(PHASE26K_COMMON_DOCTYPES)

    return [
        "Material Request",
        "Purchase Order",
        "Purchase Receipt",
        "Purchase Invoice",
        "Sales Order",
        "Delivery Note",
        "Sales Invoice",
        "Quotation",
        "Payment Entry",
        "Journal Entry",
        "Expense Claim",
        "Employee Advance",
        "Leave Application",
        "Job Offer",
        "Issue",
        "Project",
        "Task",
    ]


def _phase27a_get_policy_for_doctype(reference_doctype):
    if not frappe.db.exists("DocType", "Internal Signature Policy"):
        return None

    rows = frappe.get_all(
        "Internal Signature Policy",
        filters={"reference_doctype": reference_doctype},
        pluck="name",
        limit=1,
    )

    return rows[0] if rows else None


def _phase27a_create_or_update_doctype_control(reference_doctype, source_policy=None):
    settings = frappe.get_single(PHASE27A_SETTINGS_DT)

    existing = frappe.db.exists(PHASE27A_DTC_DT, reference_doctype)

    if existing:
        doc = frappe.get_doc(PHASE27A_DTC_DT, existing)
        action = "updated"
    else:
        doc = frappe.new_doc(PHASE27A_DTC_DT)
        doc.reference_doctype = reference_doctype
        action = "created"

    policy_name = source_policy or _phase27a_get_policy_for_doctype(reference_doctype)
    policy = frappe.get_doc("Internal Signature Policy", policy_name) if policy_name else None

    doc.enabled = 1 if policy else 0
    doc.show_signature_button = int(settings.show_classic_signature_button or 0)
    doc.workflow_mode = getattr(policy, "workflow_mode", None) or settings.default_workflow_mode or "Sequential"
    doc.allow_saved_signature = int(getattr(policy, "allow_saved_signature", settings.default_allow_saved_signature) or 0)
    doc.allow_direction_text = int(getattr(policy, "allow_direction_text", settings.default_allow_direction_text) or 0)
    doc.allow_direction_drawing = int(getattr(policy, "allow_direction_drawing", settings.default_allow_direction_drawing) or 0)
    doc.allow_reject = int(getattr(policy, "allow_reject", settings.default_allow_reject) or 0)
    doc.allow_external_requests = int(getattr(policy, "allow_external_requests", settings.external_gateway_enabled) or 0)
    doc.require_signature_profile = int(getattr(policy, "require_signature_profile", settings.require_signature_profile) or 0)
    doc.auto_generate_certificate = int(settings.auto_generate_certificate or 0)
    doc.auto_generate_signed_pdf = int(settings.auto_generate_signed_pdf or 0)
    doc.allowed_signer_mode = doc.allowed_signer_mode or "Ac Footer"

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    return {
        "reference_doctype": reference_doctype,
        "action": action,
        "control": doc.name,
    }


def _phase27a_seed_doctype_controls():
    doctypes = set()

    if frappe.db.exists("DocType", "Internal Signature Policy"):
        policies = frappe.get_all(
            "Internal Signature Policy",
            fields=["name", "reference_doctype"],
            limit_page_length=500,
        )

        for p in policies:
            if p.reference_doctype and frappe.db.exists("DocType", p.reference_doctype):
                doctypes.add(p.reference_doctype)

    for dt in _phase27a_default_common_doctypes():
        if frappe.db.exists("DocType", dt):
            doctypes.add(dt)

    if globals().get("PHASE26C_DEMO_DT") and frappe.db.exists("DocType", PHASE26C_DEMO_DT):
        doctypes.add(PHASE26C_DEMO_DT)

    results = []

    for dt in sorted(doctypes):
        try:
            results.append(_phase27a_create_or_update_doctype_control(dt))
        except Exception as exc:
            results.append({
                "reference_doctype": dt,
                "error": str(exc),
                "ok": False,
            })

    frappe.db.commit()

    return results


def _phase27a_permission_doc_for_user(user):
    if not frappe.db.exists("DocType", "Internal Signature Permission"):
        return None

    meta = frappe.get_meta("Internal Signature Permission")
    candidate_fields = ["user", "signature_user", "employee_user", "target_user", "requested_user"]

    for fieldname in candidate_fields:
        if meta.has_field(fieldname):
            rows = frappe.get_all(
                "Internal Signature Permission",
                filters={fieldname: user},
                pluck="name",
                limit=1,
            )

            if rows:
                return rows[0]

    rows = frappe.get_all(
        "Internal Signature Permission",
        filters={"name": user},
        pluck="name",
        limit=1,
    )

    return rows[0] if rows else None


def _phase27a_seed_employee_controls():
    if not frappe.db.exists("DocType", "User"):
        return []

    users = set()

    if frappe.db.exists("DocType", "Employee Signature Profile"):
        profiles = frappe.get_all(
            "Employee Signature Profile",
            fields=["name"],
            limit_page_length=500,
        )
        for p in profiles:
            users.add(p.name)

    if not users:
        users.add(frappe.session.user)

    results = []

    for user in sorted(users):
        try:
            identity = _phase26c_identity_from_employee_or_user(user=user) if globals().get("_phase26c_identity_from_employee_or_user") else {"user": user}

            existing = frappe.db.exists(PHASE27A_EMP_DT, user)

            if existing:
                doc = frappe.get_doc(PHASE27A_EMP_DT, existing)
                action = "updated"
            else:
                doc = frappe.new_doc(PHASE27A_EMP_DT)
                doc.employee_user = user
                action = "created"

            doc.employee = identity.get("employee")
            doc.full_name = identity.get("full_name") or user
            doc.designation = identity.get("designation")
            doc.department = identity.get("department")
            doc.is_active = 1

            if frappe.db.exists("Employee Signature Profile", user):
                prof = frappe.get_doc("Employee Signature Profile", user)
                doc.signature_profile = prof.name
                doc.signature_status = "Registered" if prof.get("signature_hash") else "Missing Signature"
                doc.signature_hash_prefix = (prof.get("signature_hash") or "")[:18]
            else:
                doc.signature_profile = ""
                doc.signature_status = "Missing Profile"
                doc.signature_hash_prefix = ""

            perm_name = _phase27a_permission_doc_for_user(user)

            if perm_name:
                perm = frappe.get_doc("Internal Signature Permission", perm_name)

                for fieldname in [
                    "can_receive_requests",
                    "can_use_saved_signature",
                    "can_draw_direction",
                    "can_write_direction_text",
                    "can_reject",
                    "can_override_sequence",
                    "can_manage_external_requests",
                    "can_view_signature_audit",
                    "max_sequence_level",
                ]:
                    if hasattr(perm, fieldname) and hasattr(doc, fieldname):
                        setattr(doc, fieldname, getattr(perm, fieldname))

            if existing:
                doc.save(ignore_permissions=True)
            else:
                doc.insert(ignore_permissions=True)

            results.append({
                "user": user,
                "control": doc.name,
                "action": action,
                "signature_status": doc.signature_status,
            })

        except Exception as exc:
            results.append({
                "user": user,
                "ok": False,
                "error": str(exc),
            })

    frappe.db.commit()

    return results


def _phase27a_workspace_links():
    return [
        {"label": "Signature Admin Control", "url": "/signature-admin-control"},
        {"label": "Signature System Settings", "doctype": PHASE27A_SETTINGS_DT},
        {"label": "Signature DocType Control", "doctype": PHASE27A_DTC_DT},
        {"label": "Signature Employee Control", "doctype": PHASE27A_EMP_DT},
        {"label": "Employee Signature Profile", "doctype": "Employee Signature Profile"},
        {"label": "Document Signature Request", "doctype": "Document Signature Request"},
        {"label": "Internal Signature Certificate", "doctype": "Internal Signature Certificate"},
        {"label": "External Systems", "doctype": "Internal Signature External System"},
        {"label": "External Requests", "doctype": "Internal Signature External Request"},
        {"label": "Rollout Console", "url": "/internal-signature-rollout"},
        {"label": "External Console", "url": "/external-signature-console"},
        {"label": "Production Readiness", "url": "/signature-production-readiness"},
    ]




@frappe.whitelist()
def phase27a_install_admin_control_center():
    _phase27a_require_admin()

    doctypes = [
        _phase27a_install_settings_doctype(),
        _phase27a_install_doctype_control(),
        _phase27a_install_employee_control(),
    ]

    dt_controls = _phase27a_seed_doctype_controls()
    emp_controls = _phase27a_seed_employee_controls()
    workspace = _phase27a_create_workspace()

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "27A",
        "doctypes": doctypes,
        "doctype_controls_count": len(dt_controls),
        "employee_controls_count": len(emp_controls),
        "workspace": workspace,
        "routes": {
            "admin_control": "/signature-admin-control",
            "workspace": "/app/workspace/surhan-signature",
            "settings": f"/app/{frappe.scrub(PHASE27A_SETTINGS_DT).replace('_', '-')}",
            "doctype_control": f"/app/{frappe.scrub(PHASE27A_DTC_DT).replace('_', '-')}",
            "employee_control": f"/app/{frappe.scrub(PHASE27A_EMP_DT).replace('_', '-')}",
        },
        "ready": True,
    }


@frappe.whitelist()
def phase27a_admin_control_data():
    _phase27a_require_admin()

    if not frappe.db.exists("DocType", PHASE27A_SETTINGS_DT):
        phase27a_install_admin_control_center()

    settings = frappe.get_single(PHASE27A_SETTINGS_DT).as_dict()

    dt_controls = []

    if frappe.db.exists("DocType", PHASE27A_DTC_DT):
        dt_controls = frappe.get_all(
            PHASE27A_DTC_DT,
            fields=[
                "name",
                "reference_doctype",
                "enabled",
                "show_signature_button",
                "workflow_mode",
                "allow_saved_signature",
                "allow_direction_text",
                "allow_direction_drawing",
                "allow_reject",
                "allow_external_requests",
                "require_signature_profile",
                "auto_generate_certificate",
                "auto_generate_signed_pdf",
                "allowed_signer_mode",
                "last_applied_at",
                "applied_status",
            ],
            order_by="reference_doctype asc",
            limit_page_length=500,
        )

    emp_controls = []

    if frappe.db.exists("DocType", PHASE27A_EMP_DT):
        emp_controls = frappe.get_all(
            PHASE27A_EMP_DT,
            fields=[
                "name",
                "employee_user",
                "employee",
                "full_name",
                "designation",
                "department",
                "is_active",
                "signature_status",
                "signature_hash_prefix",
                "admin_only_signature_registration",
                "can_receive_requests",
                "can_use_saved_signature",
                "can_draw_direction",
                "can_write_direction_text",
                "can_reject",
                "can_override_sequence",
                "can_manage_external_requests",
                "can_view_signature_audit",
                "max_sequence_level",
            ],
            order_by="full_name asc",
            limit_page_length=500,
        )

    counts = {
        "doctype_controls": len(dt_controls),
        "enabled_doctypes": sum(1 for x in dt_controls if int(x.get("enabled") or 0)),
        "employee_controls": len(emp_controls),
        "registered_signatures": sum(1 for x in emp_controls if x.get("signature_status") == "Registered"),
        "signature_requests": frappe.db.count("Document Signature Request") if frappe.db.exists("DocType", "Document Signature Request") else 0,
        "certificates": frappe.db.count("Internal Signature Certificate") if frappe.db.exists("DocType", "Internal Signature Certificate") else 0,
    }

    setup_steps = [
        {"step": "Create employee signature profiles", "ready": counts["registered_signatures"] > 0},
        {"step": "Configure employee permissions", "ready": counts["employee_controls"] > 0},
        {"step": "Enable DocTypes for signature", "ready": counts["enabled_doctypes"] > 0},
        {"step": "Install Classic Signature UX", "ready": bool(frappe.get_all("Client Script", filters={"name": ["like", "Surhan Classic Signature UX -%"]}, limit=1)) if frappe.db.exists("DocType", "Client Script") else False},
        {"step": "Generate certificates and signed PDFs", "ready": counts["certificates"] > 0},
        {"step": "Review production readiness", "ready": True},
    ]

    return {
        "ok": True,
        "phase": "27A",
        "settings": settings,
        "doctype_controls": dt_controls,
        "employee_controls": emp_controls,
        "counts": counts,
        "setup_steps": setup_steps,
        "routes": {
            "workspace": "/app/workspace/surhan-signature",
            "admin_control": "/signature-admin-control",
            "settings": f"/app/{frappe.scrub(PHASE27A_SETTINGS_DT).replace('_', '-')}",
            "doctype_control": f"/app/{frappe.scrub(PHASE27A_DTC_DT).replace('_', '-')}",
            "employee_control": f"/app/{frappe.scrub(PHASE27A_EMP_DT).replace('_', '-')}",
            "signature_profile": "/signature-profile",
            "readiness": "/signature-production-readiness",
        },
        "ready": True,
    }


def _phase27a_bool(v):
    return 1 if str(v).lower() in {"1", "true", "yes", "on"} or v is True else 0


@frappe.whitelist()
def phase27a_update_doctype_control(reference_doctype: str, values=None):
    _phase27a_require_admin()

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists(PHASE27A_DTC_DT, reference_doctype):
        _phase27a_create_or_update_doctype_control(reference_doctype)

    doc = frappe.get_doc(PHASE27A_DTC_DT, reference_doctype)

    if isinstance(values, str):
        values = _phase27a_json.loads(values)

    values = values or {}

    allowed = {
        "enabled",
        "show_signature_button",
        "allow_external_requests",
        "workflow_mode",
        "allow_saved_signature",
        "allow_direction_text",
        "allow_direction_drawing",
        "allow_reject",
        "require_signature_profile",
        "auto_generate_certificate",
        "auto_generate_signed_pdf",
        "allowed_signer_mode",
        "admin_notes",
    }

    check_fields = {
        "enabled",
        "show_signature_button",
        "allow_external_requests",
        "allow_saved_signature",
        "allow_direction_text",
        "allow_direction_drawing",
        "allow_reject",
        "require_signature_profile",
        "auto_generate_certificate",
        "auto_generate_signed_pdf",
    }

    for k, v in values.items():
        if k not in allowed:
            continue

        if k in check_fields:
            setattr(doc, k, _phase27a_bool(v))
        else:
            setattr(doc, k, v)

    doc.save(ignore_permissions=True)
    frappe.db.commit()

    return {
        "ok": True,
        "phase": "27A",
        "action": "updated",
        "doctype_control": doc.name,
        "reference_doctype": reference_doctype,
    }


def _phase27a_find_or_create_policy(reference_doctype):
    rows = frappe.get_all(
        "Internal Signature Policy",
        filters={"reference_doctype": reference_doctype},
        pluck="name",
        limit=1,
    )

    if rows:
        return frappe.get_doc("Internal Signature Policy", rows[0]), "updated"

    doc = frappe.new_doc("Internal Signature Policy")
    doc.reference_doctype = reference_doctype

    if frappe.get_meta("Internal Signature Policy").has_field("policy_name"):
        doc.policy_name = f"{reference_doctype} Internal Signature Policy"

    return doc, "created"


@frappe.whitelist()
def phase27a_apply_doctype_control(reference_doctype: str):
    _phase27a_require_admin()

    if not reference_doctype:
        frappe.throw("reference_doctype is required.")

    if not frappe.db.exists(PHASE27A_DTC_DT, reference_doctype):
        frappe.throw("Signature DocType Control not found.")

    control = frappe.get_doc(PHASE27A_DTC_DT, reference_doctype)

    actions = []

    if int(control.enabled or 0):
        if globals().get("phase26k_enable_doctype"):
            enabled = phase26k_enable_doctype(
                reference_doctype,
                workflow_mode=control.workflow_mode or "Sequential",
                allow_external_requests=int(control.allow_external_requests or 0),
                add_to_external_systems=0,
            )
            actions.append({"phase26k_enable_doctype": enabled})

        if frappe.db.exists("DocType", "Internal Signature Policy"):
            policy, action = _phase27a_find_or_create_policy(reference_doctype)
            meta = frappe.get_meta("Internal Signature Policy")

            values = {
                "reference_doctype": reference_doctype,
                "is_active": 1,
                "ac_footer_fieldname": "ac_footer",
                "workflow_mode": control.workflow_mode or "Sequential",
                "allow_saved_signature": int(control.allow_saved_signature or 0),
                "allow_direction": 1 if int(control.allow_direction_text or 0) or int(control.allow_direction_drawing or 0) else 0,
                "allow_direction_text": int(control.allow_direction_text or 0),
                "allow_direction_drawing": int(control.allow_direction_drawing or 0),
                "allow_reject": int(control.allow_reject or 0),
                "require_signature_profile": int(control.require_signature_profile or 0),
                "allow_external_requests": int(control.allow_external_requests or 0),
            }

            for field, value in values.items():
                if meta.has_field(field):
                    setattr(policy, field, value)

            if action == "created":
                policy.insert(ignore_permissions=True)
            else:
                policy.save(ignore_permissions=True)

            actions.append({"policy": policy.name, "action": action})

        if int(control.show_signature_button or 0):
            if globals().get("phase26n_install_classic_client_script"):
                actions.append({"classic_ux": phase26n_install_classic_client_script(reference_doctype)})
        else:
            if frappe.db.exists("DocType", "Client Script"):
                cs = frappe.db.exists("Client Script", f"Surhan Classic Signature UX - {reference_doctype}")
                if cs:
                    frappe.db.set_value("Client Script", cs, "enabled", 0, update_modified=True)
                    actions.append({"classic_ux_disabled": cs})

    else:
        policy_name = _phase27a_get_policy_for_doctype(reference_doctype)

        if policy_name:
            if frappe.get_meta("Internal Signature Policy").has_field("is_active"):
                frappe.db.set_value("Internal Signature Policy", policy_name, "is_active", 0, update_modified=True)
                actions.append({"policy_disabled": policy_name})

        if frappe.db.exists("DocType", "Client Script"):
            prefixes = [
                "Surhan Classic Signature UX - ",
                "Surhan Internal Signature Buttons - ",
                "Surhan Signed Print View - ",
                "Surhan Internal Certificate PDF - ",
            ]

            disabled = []

            for prefix in prefixes:
                cs = frappe.db.exists("Client Script", prefix + reference_doctype)
                if cs:
                    frappe.db.set_value("Client Script", cs, "enabled", 0, update_modified=True)
                    disabled.append(cs)

            actions.append({"client_scripts_disabled": disabled})

    control.last_applied_at = now_datetime()
    control.last_applied_by = frappe.session.user
    control.applied_status = _phase27a_json_dumps(actions)[:1000]
    control.save(ignore_permissions=True)

    frappe.db.commit()
    frappe.clear_cache(doctype=reference_doctype)

    return {
        "ok": True,
        "phase": "27A",
        "reference_doctype": reference_doctype,
        "enabled": bool(control.enabled),
        "actions": actions,
    }


@frappe.whitelist()
def phase27a_apply_all_doctype_controls():
    _phase27a_require_admin()

    rows = frappe.get_all(
        PHASE27A_DTC_DT,
        fields=["reference_doctype"],
        limit_page_length=500,
    )

    results = []

    for r in rows:
        try:
            results.append(phase27a_apply_doctype_control(r.reference_doctype))
        except Exception as exc:
            results.append({
                "ok": False,
                "reference_doctype": r.reference_doctype,
                "error": str(exc),
            })

    return {
        "ok": True,
        "phase": "27A",
        "count": len(results),
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase27a_refresh_control_center():
    _phase27a_require_admin()

    install = phase27a_install_admin_control_center()
    data = phase27a_admin_control_data()

    return {
        "ok": True,
        "phase": "27A",
        "install": install,
        "data": data,
        "ready": True,
    }


@frappe.whitelist()
def phase27a_export_admin_control_snapshot_json():
    data = phase27a_admin_control_data()
    sha = _phase27a_sha256(data)
    content = _phase27a_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27a-signature-admin-control-snapshot-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27A",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "counts": data.get("counts"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27a_admin_control_health():
    install = phase27a_install_admin_control_center()
    data = phase27a_admin_control_data()
    export = phase27a_export_admin_control_snapshot_json()

    return {
        "ok": True,
        "phase": "27A",
        "install": install,
        "counts": data.get("counts"),
        "setup_steps": data.get("setup_steps"),
        "routes": data.get("routes"),
        "export": export,
        "ready": True,
    }


# Phase 27A-FIX3: unify Admin Control Center under existing Surhan Signature module.
PHASE27A_OFFICIAL_MODULE = "Surhan Signature"






@frappe.whitelist()
def phase27a_fix3_install_admin_control_center():
    """
    Install Admin Control Center using the existing Surhan Signature module.
    """
    install = phase27a_install_admin_control_center()
    data = phase27a_admin_control_data()

    return {
        "ok": True,
        "phase_fix": "27A-FIX3",
        "official_module": PHASE27A_OFFICIAL_MODULE,
        "install": install,
        "counts": data.get("counts"),
        "setup_steps": data.get("setup_steps"),
        "routes": data.get("routes"),
        "ready": True,
    }


@frappe.whitelist()
def phase27a_fix3_cleanup_wrong_signing_module_preview():
    """
    Preview only. Does not delete anything.
    Shows whether anything still references the wrong 'Signing' Module Def.
    """
    doctypes = frappe.get_all(
        "DocType",
        filters={"module": "Signing"},
        fields=["name", "module", "custom"],
        limit_page_length=500,
    )

    workspaces = []
    if frappe.db.exists("DocType", "Workspace"):
        try:
            workspaces = frappe.get_all(
                "Workspace",
                filters={"module": "Signing"},
                fields=["name", "title", "module"],
                limit_page_length=100,
            )
        except Exception:
            workspaces = []

    return {
        "ok": True,
        "phase_fix": "27A-FIX3",
        "wrong_module": "Signing",
        "doctype_references": doctypes,
        "workspace_references": workspaces,
        "can_remove_module_def_later": bool(not doctypes and not workspaces),
    }


# Phase 27A-FIX4: real filesystem module path for official Surhan Signature module.
PHASE27A_OFFICIAL_MODULE = "Surhan Signature"


def _phase27a_module():
    module_name = PHASE27A_OFFICIAL_MODULE

    try:
        if frappe.db.exists("Module Def", module_name):
            frappe.db.set_value("Module Def", module_name, "app_name", "surhan_signature", update_modified=False)
        else:
            doc = frappe.new_doc("Module Def")
            doc.module_name = module_name
            doc.app_name = "surhan_signature"
            doc.insert(ignore_permissions=True)

        frappe.db.commit()
    except Exception:
        pass

    return module_name


def _phase27a_ensure_doctype(name, fields, issingle=0, autoname=None, title_field=None):
    """
    FIX4:
    Use the official existing module 'Surhan Signature'.
    The real module package now exists at:
    surhan_signature/surhan_signature/
    so standard DocTypes can be exported correctly in developer mode.
    """
    module = _phase27a_module()

    if frappe.db.exists("DocType", name):
        doc = frappe.get_doc("DocType", name)
        action = "updated"

        doc.module = module
        doc.custom = 0
        doc.issingle = int(issingle or 0)
        doc.is_submittable = 0
        doc.track_changes = 1
        doc.allow_rename = 0

        if autoname:
            doc.autoname = autoname

        if title_field and hasattr(doc, "title_field"):
            doc.title_field = title_field

        existing_fields = {df.fieldname for df in doc.fields if df.fieldname}

        for f in fields:
            if f.get("fieldname") and f.get("fieldname") in existing_fields:
                continue
            doc.append("fields", f)

        existing_roles = {p.role for p in doc.permissions if p.role}

        for p in _phase27a_role_permissions():
            if p.get("role") not in existing_roles:
                doc.append("permissions", p)

        doc.save(ignore_permissions=True)

    else:
        doc = frappe.new_doc("DocType")
        doc.name = name
        doc.module = module
        doc.custom = 0
        doc.issingle = int(issingle or 0)
        doc.is_submittable = 0
        doc.track_changes = 1
        doc.allow_rename = 0

        if autoname:
            doc.autoname = autoname

        if title_field and hasattr(doc, "title_field"):
            doc.title_field = title_field

        for f in fields:
            doc.append("fields", f)

        for p in _phase27a_role_permissions():
            doc.append("permissions", p)

        doc.insert(ignore_permissions=True)
        action = "created"

    frappe.db.commit()

    try:
        frappe.clear_cache(doctype=name)
        frappe.db.updatedb(name)
    except Exception:
        pass

    return {
        "doctype": name,
        "action": action,
        "module": module,
        "custom": False,
    }


@frappe.whitelist()
def phase27a_fix4_install_admin_control_center():
    install = phase27a_install_admin_control_center()
    data = phase27a_admin_control_data()

    return {
        "ok": True,
        "phase_fix": "27A-FIX4",
        "official_module": PHASE27A_OFFICIAL_MODULE,
        "install": install,
        "counts": data.get("counts"),
        "setup_steps": data.get("setup_steps"),
        "routes": data.get("routes"),
        "ready": True,
    }


@frappe.whitelist()
def phase27a_fix4_module_diagnostics():
    import os

    app_pkg = frappe.get_app_path("surhan_signature")
    official_path = os.path.join(app_pkg, "surhan_signature")

    return {
        "ok": True,
        "phase_fix": "27A-FIX4",
        "module_def_surhan_signature": frappe.db.exists("Module Def", "Surhan Signature"),
        "module_def_signing": frappe.db.exists("Module Def", "Signing"),
        "app_path": app_pkg,
        "official_module_path": official_path,
        "official_module_path_exists": os.path.isdir(official_path),
        "modules_txt_exists": os.path.exists(os.path.join(app_pkg, "modules.txt")),
        "modules_txt": open(os.path.join(app_pkg, "modules.txt")).read() if os.path.exists(os.path.join(app_pkg, "modules.txt")) else "",
        "doctype_refs_signing": frappe.get_all("DocType", filters={"module": "Signing"}, pluck="name", limit_page_length=500),
        "doctype_refs_surhan_signature": frappe.get_all("DocType", filters={"module": "Surhan Signature"}, pluck="name", limit_page_length=500),
    }


# Phase 27A-FIX5: unify old Signing DocTypes into Surhan Signature and create safe Workspace.
PHASE27A_OFFICIAL_MODULE = "Surhan Signature"


def _phase27a_fix5_module_refs(module_name):
    refs = {
        "doctype_refs": [],
        "workspace_refs": [],
    }

    try:
        refs["doctype_refs"] = frappe.get_all(
            "DocType",
            filters={"module": module_name},
            fields=["name", "module", "custom"],
            limit_page_length=1000,
        )
    except Exception:
        refs["doctype_refs"] = []

    if frappe.db.exists("DocType", "Workspace"):
        try:
            meta = frappe.get_meta("Workspace")
            if meta.has_field("module"):
                refs["workspace_refs"] = frappe.get_all(
                    "Workspace",
                    filters={"module": module_name},
                    fields=["name", "title", "module"],
                    limit_page_length=200,
                )
        except Exception:
            refs["workspace_refs"] = []

    return refs


def _phase27a_fix5_ensure_official_module():
    module_name = PHASE27A_OFFICIAL_MODULE

    if frappe.db.exists("Module Def", module_name):
        frappe.db.set_value(
            "Module Def",
            module_name,
            "app_name",
            "surhan_signature",
            update_modified=False,
        )
    else:
        doc = frappe.new_doc("Module Def")
        doc.module_name = module_name
        doc.app_name = "surhan_signature"
        doc.insert(ignore_permissions=True)

    frappe.db.commit()

    return module_name


@frappe.whitelist()
def phase27a_fix5_migrate_signing_doctypes_to_surhan_signature():
    _phase27a_require_admin()

    module = _phase27a_fix5_ensure_official_module()

    refs = _phase27a_fix5_module_refs("Signing")
    moved = []
    failed = []

    for r in refs.get("doctype_refs") or []:
        dt = r.get("name")

        try:
            doc = frappe.get_doc("DocType", dt)
            doc.module = module
            doc.save(ignore_permissions=True)
            frappe.db.commit()

            try:
                frappe.clear_cache(doctype=dt)
                frappe.db.updatedb(dt)
            except Exception:
                pass

            moved.append({
                "doctype": dt,
                "from": "Signing",
                "to": module,
                "custom": bool(r.get("custom")),
                "method": "save",
            })

        except Exception as exc:
            try:
                frappe.db.set_value(
                    "DocType",
                    dt,
                    "module",
                    module,
                    update_modified=False,
                )
                frappe.db.commit()
                frappe.clear_cache(doctype=dt)

                moved.append({
                    "doctype": dt,
                    "from": "Signing",
                    "to": module,
                    "custom": bool(r.get("custom")),
                    "method": "db_set_value_fallback",
                    "save_error": str(exc),
                })

            except Exception as exc2:
                failed.append({
                    "doctype": dt,
                    "error": str(exc2),
                    "previous_error": str(exc),
                })

    return {
        "ok": True,
        "phase_fix": "27A-FIX5",
        "moved_count": len(moved),
        "failed_count": len(failed),
        "moved": moved,
        "failed": failed,
    }


def _phase27a_workspace_doctype_links():
    candidates = [
        ("Signature System Settings", "System Settings"),
        ("Signature DocType Control", "DocType Controls"),
        ("Signature Employee Control", "Employee Controls"),
        ("Employee Signature Profile", "Employee Signature Profiles"),
        ("Internal Signature Policy", "Signature Policies"),
        ("Internal Signature Permission", "Signature Permissions"),
        ("Document Signature Request", "Signature Requests"),
        ("Internal Signature Certificate", "Certificates"),
        ("Internal Signature External System", "External Systems"),
        ("Internal Signature External Request", "External Requests"),
        ("E-Sign Settings", "E-Sign Settings"),
        ("E-Sign Envelope", "E-Sign Envelopes"),
        ("E-Sign Certificate", "E-Sign Certificates"),
        ("E-Sign Risk Assessment", "Risk Assessment"),
    ]

    return [
        {"doctype": dt, "label": label}
        for dt, label in candidates
        if frappe.db.exists("DocType", dt)
    ]


def _phase27a_create_workspace():
    """
    FIX5:
    Workspace links must point to real Desk resources.
    Website routes like /signature-admin-control are NOT valid Workspace Link To values.
    Therefore this workspace uses only valid DocType links.
    The web Admin Control Center remains available through /signature-admin-control.
    """
    if not frappe.db.exists("DocType", "Workspace"):
        return {
            "ok": False,
            "created": False,
            "reason": "Workspace DocType not found.",
        }

    module = _phase27a_fix5_ensure_official_module()
    title = "Surhan Signature"

    try:
        existing = frappe.db.exists("Workspace", title)

        if existing:
            ws = frappe.get_doc("Workspace", existing)
            action = "updated"
        else:
            ws = frappe.new_doc("Workspace")
            action = "created"

        meta = frappe.get_meta("Workspace")

        if meta.has_field("title"):
            ws.title = title

        if meta.has_field("label"):
            ws.label = title

        if meta.has_field("module"):
            ws.module = module

        if meta.has_field("public"):
            ws.public = 1

        if meta.has_field("is_standard"):
            ws.is_standard = 0

        if meta.has_field("icon"):
            ws.icon = "signature"

        if meta.has_field("sequence_id"):
            ws.sequence_id = 10

        if meta.has_field("content"):
            ws.content = _phase27a_json.dumps(
                [
                    {
                        "id": "surhan-signature-header",
                        "type": "header",
                        "data": {
                            "text": "Surhan Signature Control Center",
                            "col": 12,
                        },
                    },
                    {
                        "id": "surhan-signature-note",
                        "type": "paragraph",
                        "data": {
                            "text": "Use /signature-admin-control as the main admin screen. This workspace groups all signature DocTypes in one place.",
                            "col": 12,
                        },
                    },
                ],
                ensure_ascii=False,
            )

        if hasattr(ws, "links"):
            ws.set("links", [])

            for idx, item in enumerate(_phase27a_workspace_doctype_links(), start=1):
                try:
                    ws.append("links", {
                        "label": item["label"],
                        "type": "Link",
                        "link_type": "DocType",
                        "link_to": item["doctype"],
                        "idx": idx,
                    })
                except Exception:
                    pass

        if existing:
            ws.save(ignore_permissions=True)
        else:
            ws.insert(ignore_permissions=True)

        frappe.db.commit()

        return {
            "ok": True,
            "action": action,
            "workspace": ws.name,
            "title": title,
            "module": module,
            "link_count": len(getattr(ws, "links", []) or []),
            "workspace_url": "/app/workspace/surhan-signature",
            "admin_control_url": "/signature-admin-control",
        }

    except Exception as exc:
        frappe.db.rollback()

        return {
            "ok": False,
            "created": False,
            "error": str(exc),
            "fallback": "/signature-admin-control",
        }


@frappe.whitelist()
def phase27a_fix5_cleanup_signing_module_if_unused():
    _phase27a_require_admin()

    refs = _phase27a_fix5_module_refs("Signing")

    has_refs = bool((refs.get("doctype_refs") or []) or (refs.get("workspace_refs") or []))

    if has_refs:
        return {
            "ok": True,
            "phase_fix": "27A-FIX5",
            "deleted": False,
            "reason": "Signing still has references.",
            "refs": refs,
        }

    if not frappe.db.exists("Module Def", "Signing"):
        return {
            "ok": True,
            "phase_fix": "27A-FIX5",
            "deleted": False,
            "reason": "Module Def Signing does not exist.",
            "refs": refs,
        }

    try:
        frappe.delete_doc(
            "Module Def",
            "Signing",
            ignore_permissions=True,
            force=True,
        )
        frappe.db.commit()

        return {
            "ok": True,
            "phase_fix": "27A-FIX5",
            "deleted": True,
            "module": "Signing",
            "refs": refs,
        }

    except Exception as exc:
        frappe.db.rollback()

        return {
            "ok": False,
            "phase_fix": "27A-FIX5",
            "deleted": False,
            "error": str(exc),
            "refs": refs,
        }


@frappe.whitelist()
def phase27a_fix5_diagnostics():
    import os

    app_pkg = frappe.get_app_path("surhan_signature")
    official_path = os.path.join(app_pkg, "surhan_signature")
    modules_txt_path = os.path.join(app_pkg, "modules.txt")

    return {
        "ok": True,
        "phase_fix": "27A-FIX5",
        "module_def_surhan_signature": frappe.db.exists("Module Def", "Surhan Signature"),
        "module_def_signing": frappe.db.exists("Module Def", "Signing"),
        "official_module_path": official_path,
        "official_module_path_exists": os.path.isdir(official_path),
        "modules_txt": open(modules_txt_path).read() if os.path.exists(modules_txt_path) else "",
        "refs_signing": _phase27a_fix5_module_refs("Signing"),
        "refs_surhan_signature": _phase27a_fix5_module_refs("Surhan Signature"),
        "workspace_exists": frappe.db.exists("Workspace", "Surhan Signature") if frappe.db.exists("DocType", "Workspace") else None,
        "admin_control_route": "/signature-admin-control",
    }


@frappe.whitelist()
def phase27a_fix5_unify_control_center():
    _phase27a_require_admin()

    migrate = phase27a_fix5_migrate_signing_doctypes_to_surhan_signature()
    install = phase27a_install_admin_control_center()
    workspace = _phase27a_create_workspace()
    cleanup = phase27a_fix5_cleanup_signing_module_if_unused()
    diagnostics = phase27a_fix5_diagnostics()
    data = phase27a_admin_control_data()

    return {
        "ok": True,
        "phase_fix": "27A-FIX5",
        "migrate": migrate,
        "install": install,
        "workspace": workspace,
        "cleanup": cleanup,
        "diagnostics": diagnostics,
        "counts": data.get("counts"),
        "setup_steps": data.get("setup_steps"),
        "routes": data.get("routes"),
        "ready": bool(workspace.get("ok") and not migrate.get("failed")),
    }


# Phase 27B: Admin-only employee signature manager.
import base64 as _phase27b_base64
import hashlib as _phase27b_hashlib
import json as _phase27b_json
import re as _phase27b_re


PHASE27B_PROFILE_DT = "Employee Signature Profile"
PHASE27B_VERSION_DT = "Employee Signature Profile Version"
PHASE27B_EMP_CONTROL_DT = "Signature Employee Control"
PHASE27B_PERMISSION_DT = "Internal Signature Permission"
PHASE27B_SETTINGS_DT = "Signature System Settings"


def _phase27b_json_dumps(data):
    return _phase27b_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27b_sha256_bytes(data: bytes):
    return _phase27b_hashlib.sha256(data).hexdigest()


def _phase27b_sha256_text(data):
    if not isinstance(data, str):
        data = _phase27b_json_dumps(data)
    return _phase27b_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27b_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase27b_require_admin():
    if not _phase27b_is_admin():
        frappe.throw("Only Signature Administrators can manage employee signatures.")


def _phase27b_has_dt(dt):
    return frappe.db.exists("DocType", dt)


def _phase27b_has_field(dt, fieldname):
    try:
        return frappe.get_meta(dt).has_field(fieldname)
    except Exception:
        return False


def _phase27b_set(doc, fieldname, value):
    try:
        if frappe.get_meta(doc.doctype).has_field(fieldname):
            setattr(doc, fieldname, value)
            return True
    except Exception:
        pass

    return False


def _phase27b_bool(value):
    return 1 if str(value).lower() in {"1", "true", "yes", "on"} or value is True else 0


def _phase27b_clean(value, max_len=500):
    value = (value or "").strip()

    if len(value) > max_len:
        frappe.throw(f"Value is too long. Maximum allowed length is {max_len} characters.")

    return value


def _phase27b_identity(user=None, employee=None):
    user = user or frappe.session.user

    identity = {
        "user": user,
        "employee": employee,
        "full_name": None,
        "designation": None,
        "department": None,
    }

    if globals().get("_phase26c_identity_from_employee_or_user"):
        try:
            found = _phase26c_identity_from_employee_or_user(user=user, employee=employee)
            if found:
                identity.update({k: v for k, v in found.items() if v is not None})
        except Exception:
            pass

    if employee and frappe.db.exists("DocType", "Employee") and frappe.db.exists("Employee", employee):
        try:
            emp = frappe.get_doc("Employee", employee)
            identity["employee"] = employee
            identity["full_name"] = identity.get("full_name") or emp.get("employee_name")
            identity["designation"] = identity.get("designation") or emp.get("designation")
            identity["department"] = identity.get("department") or emp.get("department")

            if not identity.get("user") and emp.get("user_id"):
                identity["user"] = emp.get("user_id")
        except Exception:
            pass

    if user and frappe.db.exists("DocType", "User") and frappe.db.exists("User", user):
        try:
            u = frappe.get_doc("User", user)
            identity["full_name"] = identity.get("full_name") or u.get("full_name") or user
        except Exception:
            pass

    return identity


def _phase27b_profile_public_id(user, signature_hash):
    return _phase27b_sha256_text({
        "user": user,
        "signature_hash": signature_hash,
        "site": frappe.local.site,
    })[:24]


def _phase27b_decode_signature_data(signature_data_url):
    signature_data_url = (signature_data_url or "").strip()

    if not signature_data_url:
        frappe.throw("Signature image is required.")

    if len(signature_data_url) > 3_000_000:
        frappe.throw("Signature image is too large.")

    if signature_data_url.startswith("data:image/png;base64,"):
        encoded = signature_data_url.split(",", 1)[1]
        ext = "png"
        mime = "image/png"
        raw = _phase27b_base64.b64decode(encoded)

    elif signature_data_url.startswith("data:image/jpeg;base64,"):
        encoded = signature_data_url.split(",", 1)[1]
        ext = "jpg"
        mime = "image/jpeg"
        raw = _phase27b_base64.b64decode(encoded)

    elif signature_data_url.startswith("<svg") or signature_data_url.startswith("<?xml"):
        raw = signature_data_url.encode("utf-8")
        ext = "svg"
        mime = "image/svg+xml"

    else:
        try:
            raw = _phase27b_base64.b64decode(signature_data_url)
            ext = "png"
            mime = "image/png"
        except Exception:
            frappe.throw("Unsupported signature image format.")

    if len(raw) < 50:
        frappe.throw("Signature image is empty or invalid.")

    if len(raw) > 2_000_000:
        frappe.throw("Signature image exceeds maximum allowed size.")

    if ext == "png" and not raw.startswith(b"\x89PNG"):
        # Do not hard fail old canvases, but reject obvious non-images.
        if raw[:5].lower() in [b"<html", b"<scri"]:
            frappe.throw("Invalid PNG signature image.")

    return {
        "raw": raw,
        "ext": ext,
        "mime": mime,
        "sha256": _phase27b_sha256_bytes(raw),
    }


def _phase27b_safe_user_slug(user):
    return _phase27b_re.sub(r"[^a-zA-Z0-9_.-]+", "-", user or "user").strip("-").lower()[:80] or "user"


def _phase27b_save_signature_file(user, decoded, version_no):
    from frappe.utils.file_manager import save_file

    fname = f"{_phase27b_safe_user_slug(user)}-admin-signature-v{version_no}-{decoded['sha256'][:12]}.{decoded['ext']}"

    file_doc = save_file(
        fname=fname,
        content=decoded["raw"],
        dt=PHASE27B_PROFILE_DT,
        dn=user,
        is_private=1,
    )

    return file_doc.file_url


def _phase27b_next_version(user):
    if frappe.db.exists(PHASE27B_PROFILE_DT, user):
        try:
            profile = frappe.get_doc(PHASE27B_PROFILE_DT, user)
            active = int(profile.get("active_version") or 0)
            return active + 1
        except Exception:
            pass

    if frappe.db.exists("DocType", PHASE27B_VERSION_DT):
        try:
            return int(frappe.db.count(PHASE27B_VERSION_DT, {"profile": user}) or 0) + 1
        except Exception:
            return 1

    return 1


def _phase27b_upsert_profile(user, identity, file_url, signature_hash, public_id, version_no, values):
    if not frappe.db.exists("DocType", PHASE27B_PROFILE_DT):
        frappe.throw("Employee Signature Profile DocType is not installed.")

    existing = frappe.db.exists(PHASE27B_PROFILE_DT, user)

    if existing:
        doc = frappe.get_doc(PHASE27B_PROFILE_DT, existing)
        action = "updated"
    else:
        doc = frappe.new_doc(PHASE27B_PROFILE_DT)
        doc.name = user
        action = "created"

    mappings = {
        "user": identity.get("user"),
        "employee_user": identity.get("user"),
        "employee": identity.get("employee"),
        "full_name": values.get("full_name") or identity.get("full_name"),
        "designation": values.get("designation") or identity.get("designation"),
        "department": values.get("department") or identity.get("department"),
        "signature_png": file_url,
        "signature_image": file_url,
        "signature_file": file_url,
        "signature_hash": signature_hash,
        "signature_public_id": public_id,
        "active_version": version_no,
        "is_active": _phase27b_bool(values.get("is_active", 1)),
        "allow_stored_signature_apply": _phase27b_bool(values.get("can_use_saved_signature", 1)),
        "allow_direction_drawing": _phase27b_bool(values.get("can_draw_direction", 0)),
        "signature_locked": _phase27b_bool(values.get("signature_locked", 0)),
        "admin_registered_by": frappe.session.user,
        "admin_registered_at": now_datetime(),
        "registration_source": "Admin Control Center",
    }

    for fieldname, value in mappings.items():
        _phase27b_set(doc, fieldname, value)

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()

    return {
        "profile": doc.name,
        "action": action,
    }


def _phase27b_create_profile_version(user, identity, file_url, signature_hash, public_id, version_no):
    if not frappe.db.exists("DocType", PHASE27B_VERSION_DT):
        return {
            "ok": True,
            "created": False,
            "reason": "Version DocType is not installed.",
        }

    doc = frappe.new_doc(PHASE27B_VERSION_DT)
    doc.name = f"{user}-v{version_no}-{public_id[:8]}"

    fields = {
        "profile": user,
        "employee_signature_profile": user,
        "signature_profile": user,
        "employee_user": identity.get("user"),
        "user": identity.get("user"),
        "employee": identity.get("employee"),
        "full_name": identity.get("full_name"),
        "designation": identity.get("designation"),
        "department": identity.get("department"),
        "version": version_no,
        "version_no": version_no,
        "signature_png": file_url,
        "signature_image": file_url,
        "signature_file": file_url,
        "signature_hash": signature_hash,
        "signature_public_id": public_id,
        "is_active": 1,
        "created_by_user": frappe.session.user,
        "admin_registered_by": frappe.session.user,
        "registered_at": now_datetime(),
        "created_at": now_datetime(),
    }

    for fieldname, value in fields.items():
        _phase27b_set(doc, fieldname, value)

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {
        "ok": True,
        "created": True,
        "version_doc": doc.name,
    }


def _phase27b_find_permission_doc(user):
    if not frappe.db.exists("DocType", PHASE27B_PERMISSION_DT):
        return None

    meta = frappe.get_meta(PHASE27B_PERMISSION_DT)

    for fieldname in ["user", "employee_user", "signature_user", "target_user", "requested_user"]:
        if meta.has_field(fieldname):
            rows = frappe.get_all(
                PHASE27B_PERMISSION_DT,
                filters={fieldname: user},
                pluck="name",
                limit=1,
            )
            if rows:
                return rows[0]

    if frappe.db.exists(PHASE27B_PERMISSION_DT, user):
        return user

    return None


def _phase27b_upsert_employee_control(user, identity, values, signature_hash=None):
    if not frappe.db.exists("DocType", PHASE27B_EMP_CONTROL_DT):
        return {
            "ok": False,
            "reason": "Signature Employee Control DocType is not installed.",
        }

    existing = frappe.db.exists(PHASE27B_EMP_CONTROL_DT, user)

    if existing:
        doc = frappe.get_doc(PHASE27B_EMP_CONTROL_DT, existing)
        action = "updated"
    else:
        doc = frappe.new_doc(PHASE27B_EMP_CONTROL_DT)
        doc.employee_user = user
        action = "created"

    mappings = {
        "employee_user": user,
        "employee": values.get("employee") or identity.get("employee"),
        "full_name": values.get("full_name") or identity.get("full_name") or user,
        "designation": values.get("designation") or identity.get("designation"),
        "department": values.get("department") or identity.get("department"),
        "is_active": _phase27b_bool(values.get("is_active", 1)),
        "signature_profile": user if frappe.db.exists(PHASE27B_PROFILE_DT, user) else "",
        "signature_status": "Registered" if signature_hash or frappe.db.get_value(PHASE27B_PROFILE_DT, user, "signature_hash") else "Missing Signature",
        "signature_hash_prefix": (signature_hash or frappe.db.get_value(PHASE27B_PROFILE_DT, user, "signature_hash") or "")[:18],
        "admin_only_signature_registration": 1,
        "can_receive_requests": _phase27b_bool(values.get("can_receive_requests", 1)),
        "can_use_saved_signature": _phase27b_bool(values.get("can_use_saved_signature", 1)),
        "can_draw_direction": _phase27b_bool(values.get("can_draw_direction", 0)),
        "can_write_direction_text": _phase27b_bool(values.get("can_write_direction_text", 0)),
        "can_reject": _phase27b_bool(values.get("can_reject", 0)),
        "can_override_sequence": _phase27b_bool(values.get("can_override_sequence", 0)),
        "can_manage_external_requests": _phase27b_bool(values.get("can_manage_external_requests", 0)),
        "can_view_signature_audit": _phase27b_bool(values.get("can_view_signature_audit", 0)),
        "max_sequence_level": int(values.get("max_sequence_level") or 1),
        "last_applied_at": now_datetime(),
        "last_applied_by": frappe.session.user,
    }

    for fieldname, value in mappings.items():
        _phase27b_set(doc, fieldname, value)

    if existing:
        doc.save(ignore_permissions=True)
    else:
        doc.insert(ignore_permissions=True)

    frappe.db.commit()

    return {
        "ok": True,
        "control": doc.name,
        "action": action,
    }


@frappe.whitelist()
def phase27b_apply_employee_control_permissions(employee_user: str, cmd=None):
    _phase27b_require_admin()

    employee_user = _phase27b_clean(employee_user, 140)

    if not employee_user:
        frappe.throw("employee_user is required.")

    if not frappe.db.exists(PHASE27B_EMP_CONTROL_DT, employee_user):
        identity = _phase27b_identity(user=employee_user)
        _phase27b_upsert_employee_control(employee_user, identity, {}, None)

    control = frappe.get_doc(PHASE27B_EMP_CONTROL_DT, employee_user)
    identity = _phase27b_identity(user=employee_user, employee=control.get("employee"))

    if not frappe.db.exists("DocType", PHASE27B_PERMISSION_DT):
        return {
            "ok": False,
            "reason": "Internal Signature Permission DocType is not installed.",
        }

    existing = _phase27b_find_permission_doc(employee_user)

    if existing:
        perm = frappe.get_doc(PHASE27B_PERMISSION_DT, existing)
        action = "updated"
    else:
        perm = frappe.new_doc(PHASE27B_PERMISSION_DT)
        try:
            perm.name = employee_user
        except Exception:
            pass
        action = "created"

    values = {
        "user": employee_user,
        "employee_user": employee_user,
        "signature_user": employee_user,
        "target_user": employee_user,
        "requested_user": employee_user,
        "employee": identity.get("employee"),
        "full_name": identity.get("full_name"),
        "designation": identity.get("designation"),
        "department": identity.get("department"),
        "is_active": int(control.get("is_active") or 0),
        "can_receive_requests": int(control.get("can_receive_requests") or 0),
        "can_use_saved_signature": int(control.get("can_use_saved_signature") or 0),
        "can_draw_direction": int(control.get("can_draw_direction") or 0),
        "can_write_direction_text": int(control.get("can_write_direction_text") or 0),
        "can_reject": int(control.get("can_reject") or 0),
        "can_override_sequence": int(control.get("can_override_sequence") or 0),
        "can_manage_external_requests": int(control.get("can_manage_external_requests") or 0),
        "can_view_signature_audit": int(control.get("can_view_signature_audit") or 0),
        "max_sequence_level": int(control.get("max_sequence_level") or 1),
        "source": "Signature Employee Control",
    }

    for fieldname, value in values.items():
        _phase27b_set(perm, fieldname, value)

    if existing:
        perm.save(ignore_permissions=True)
    else:
        perm.insert(ignore_permissions=True)

    control.last_applied_at = now_datetime()
    control.last_applied_by = frappe.session.user
    control.save(ignore_permissions=True)

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "27B",
        "permission": perm.name,
        "action": action,
        "employee_user": employee_user,
    }


@frappe.whitelist()
def phase27b_admin_register_employee_signature(
    employee_user: str,
    employee: str = None,
    full_name: str = None,
    designation: str = None,
    department: str = None,
    signature_data_url: str = None,
    is_active: int = 1,
    can_receive_requests: int = 1,
    can_use_saved_signature: int = 1,
    can_draw_direction: int = 0,
    can_write_direction_text: int = 0,
    can_reject: int = 0,
    can_override_sequence: int = 0,
    can_manage_external_requests: int = 0,
    can_view_signature_audit: int = 0,
    max_sequence_level: int = 1,
    signature_locked: int = 0,
    admin_notes: str = None,
    cmd=None,
):
    _phase27b_require_admin()

    employee_user = _phase27b_clean(employee_user, 140)
    employee = _phase27b_clean(employee, 140)
    full_name = _phase27b_clean(full_name, 220)
    designation = _phase27b_clean(designation, 220)
    department = _phase27b_clean(department, 220)
    admin_notes = _phase27b_clean(admin_notes, 1200)

    if not employee_user:
        frappe.throw("employee_user is required.")

    if not frappe.db.exists("User", employee_user):
        frappe.throw(f"User does not exist: {employee_user}")

    values = {
        "employee": employee,
        "full_name": full_name,
        "designation": designation,
        "department": department,
        "is_active": is_active,
        "can_receive_requests": can_receive_requests,
        "can_use_saved_signature": can_use_saved_signature,
        "can_draw_direction": can_draw_direction,
        "can_write_direction_text": can_write_direction_text,
        "can_reject": can_reject,
        "can_override_sequence": can_override_sequence,
        "can_manage_external_requests": can_manage_external_requests,
        "can_view_signature_audit": can_view_signature_audit,
        "max_sequence_level": max_sequence_level,
        "signature_locked": signature_locked,
        "admin_notes": admin_notes,
    }

    identity = _phase27b_identity(user=employee_user, employee=employee)
    decoded = _phase27b_decode_signature_data(signature_data_url)
    version_no = _phase27b_next_version(employee_user)
    file_url = _phase27b_save_signature_file(employee_user, decoded, version_no)
    public_id = _phase27b_profile_public_id(employee_user, decoded["sha256"])

    profile = _phase27b_upsert_profile(
        employee_user,
        identity,
        file_url,
        decoded["sha256"],
        public_id,
        version_no,
        values,
    )

    version = _phase27b_create_profile_version(
        employee_user,
        identity,
        file_url,
        decoded["sha256"],
        public_id,
        version_no,
    )

    control = _phase27b_upsert_employee_control(
        employee_user,
        identity,
        values,
        signature_hash=decoded["sha256"],
    )

    permission = phase27b_apply_employee_control_permissions(employee_user)

    try:
        if frappe.db.exists("DocType", PHASE27B_SETTINGS_DT):
            settings = frappe.get_single(PHASE27B_SETTINGS_DT)
            if _phase27b_has_field(PHASE27B_SETTINGS_DT, "admin_only_employee_signatures"):
                settings.admin_only_employee_signatures = 1
            settings.last_applied_at = now_datetime()
            settings.last_applied_by = frappe.session.user
            settings.save(ignore_permissions=True)
            frappe.db.commit()
    except Exception:
        pass

    try:
        log_audit(
            "internal_signature.admin_employee_signature_registered",
            {
                "employee_user": employee_user,
                "employee": identity.get("employee"),
                "signature_hash": decoded["sha256"],
                "signature_public_id": public_id,
                "version_no": version_no,
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27B",
        "employee_user": employee_user,
        "employee": identity.get("employee"),
        "full_name": values.get("full_name") or identity.get("full_name"),
        "signature_hash": decoded["sha256"],
        "signature_hash_prefix": decoded["sha256"][:18],
        "signature_public_id": public_id,
        "signature_file": file_url,
        "version_no": version_no,
        "profile": profile,
        "version": version,
        "control": control,
        "permission": permission,
        "ready": True,
    }


@frappe.whitelist()
def phase27b_seed_employee_controls_from_employees(limit: int = 500, cmd=None):
    _phase27b_require_admin()

    users = {}

    if frappe.db.exists("DocType", "Employee"):
        meta = frappe.get_meta("Employee")
        fields = ["name", "employee_name", "designation", "department"]

        if meta.has_field("user_id"):
            fields.append("user_id")
        if meta.has_field("status"):
            fields.append("status")

        rows = frappe.get_all(
            "Employee",
            fields=fields,
            limit_page_length=int(limit or 500),
            order_by="employee_name asc",
        )

        for r in rows:
            user = r.get("user_id")
            if not user:
                continue

            if r.get("status") and r.get("status") not in ["Active", ""]:
                continue

            users[user] = {
                "employee": r.name,
                "full_name": r.get("employee_name"),
                "designation": r.get("designation"),
                "department": r.get("department"),
            }

    if frappe.db.exists("DocType", PHASE27B_PROFILE_DT):
        for p in frappe.get_all(PHASE27B_PROFILE_DT, fields=["name"], limit_page_length=1000):
            users.setdefault(p.name, {})

    results = []

    for user, info in sorted(users.items()):
        try:
            identity = _phase27b_identity(user=user, employee=info.get("employee"))

            values = {
                "employee": info.get("employee") or identity.get("employee"),
                "full_name": info.get("full_name") or identity.get("full_name"),
                "designation": info.get("designation") or identity.get("designation"),
                "department": info.get("department") or identity.get("department"),
                "is_active": 1,
                "can_receive_requests": 1,
                "can_use_saved_signature": 1,
                "can_draw_direction": 0,
                "can_write_direction_text": 0,
                "can_reject": 0,
                "can_override_sequence": 0,
                "can_manage_external_requests": 0,
                "can_view_signature_audit": 0,
                "max_sequence_level": 1,
            }

            control = _phase27b_upsert_employee_control(user, identity, values)
            results.append({
                "ok": True,
                "user": user,
                "control": control,
            })

        except Exception as exc:
            results.append({
                "ok": False,
                "user": user,
                "error": str(exc),
            })

    return {
        "ok": True,
        "phase": "27B",
        "count": len(results),
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase27b_employee_signature_admin_data(query: str = None, limit: int = 200):
    _phase27b_require_admin()

    if not frappe.db.exists("DocType", PHASE27B_EMP_CONTROL_DT):
        if globals().get("phase27a_install_admin_control_center"):
            phase27a_install_admin_control_center()

    if frappe.db.exists("DocType", PHASE27B_EMP_CONTROL_DT) and frappe.db.count(PHASE27B_EMP_CONTROL_DT) == 0:
        phase27b_seed_employee_controls_from_employees(limit=limit)

    filters = {}

    rows = frappe.get_all(
        PHASE27B_EMP_CONTROL_DT,
        fields=[
            "name",
            "employee_user",
            "employee",
            "full_name",
            "designation",
            "department",
            "is_active",
            "signature_profile",
            "signature_status",
            "signature_hash_prefix",
            "admin_only_signature_registration",
            "can_receive_requests",
            "can_use_saved_signature",
            "can_draw_direction",
            "can_write_direction_text",
            "can_reject",
            "can_override_sequence",
            "can_manage_external_requests",
            "can_view_signature_audit",
            "max_sequence_level",
            "last_applied_at",
            "last_applied_by",
        ],
        filters=filters,
        order_by="full_name asc",
        limit_page_length=int(limit or 200),
    )

    q = (query or "").strip().lower()
    if q:
        rows = [
            r for r in rows
            if q in str(r.get("employee_user") or "").lower()
            or q in str(r.get("employee") or "").lower()
            or q in str(r.get("full_name") or "").lower()
            or q in str(r.get("department") or "").lower()
        ]

    return {
        "ok": True,
        "phase": "27B",
        "count": len(rows),
        "items": rows,
        "routes": {
            "admin_employee_signatures": "/signature-admin-employee-signatures",
            "admin_control": "/signature-admin-control",
            "employee_control": "/app/signature-employee-control",
            "signature_profile_list": "/app/employee-signature-profile",
        },
        "ready": True,
    }


@frappe.whitelist()
def phase27b_restrict_employee_signature_profile_permissions(cmd=None):
    _phase27b_require_admin()

    changed = []

    for dt in [PHASE27B_PROFILE_DT, PHASE27B_VERSION_DT]:
        if not frappe.db.exists("DocType", dt):
            continue

        doc = frappe.get_doc("DocType", dt)

        doc.set("permissions", [])

        admin_roles = [
            "System Manager",
            "Internal Signature Administrator",
            "Internal Signature Manager",
        ]

        idx = 1

        for role in admin_roles:
            if not frappe.db.exists("Role", role):
                continue

            doc.append("permissions", {
                "role": role,
                "read": 1,
                "write": 1,
                "create": 1,
                "delete": 1 if role in {"System Manager", "Internal Signature Administrator"} else 0,
                "export": 1,
                "report": 1,
                "share": 1,
                "print": 1,
                "email": 0,
                "idx": idx,
            })
            idx += 1

        if frappe.db.exists("Role", "Internal Signature Auditor"):
            doc.append("permissions", {
                "role": "Internal Signature Auditor",
                "read": 1,
                "write": 0,
                "create": 0,
                "delete": 0,
                "export": 1,
                "report": 1,
                "share": 0,
                "print": 1,
                "email": 0,
                "idx": idx,
            })

        doc.save(ignore_permissions=True)
        frappe.db.commit()
        frappe.clear_cache(doctype=dt)

        changed.append(dt)

    if frappe.db.exists("DocType", PHASE27B_SETTINGS_DT):
        settings = frappe.get_single(PHASE27B_SETTINGS_DT)
        if _phase27b_has_field(PHASE27B_SETTINGS_DT, "admin_only_employee_signatures"):
            settings.admin_only_employee_signatures = 1
        if _phase27b_has_field(PHASE27B_SETTINGS_DT, "last_applied_at"):
            settings.last_applied_at = now_datetime()
        if _phase27b_has_field(PHASE27B_SETTINGS_DT, "last_applied_by"):
            settings.last_applied_by = frappe.session.user
        settings.save(ignore_permissions=True)
        frappe.db.commit()

    return {
        "ok": True,
        "phase": "27B",
        "changed_doctypes": changed,
        "admin_only_employee_signatures": True,
    }


@frappe.whitelist()
def phase27b_admin_employee_signature_health():
    restrict = phase27b_restrict_employee_signature_profile_permissions()
    seed = phase27b_seed_employee_controls_from_employees(limit=500)
    data = phase27b_employee_signature_admin_data(limit=500)

    registered = [
        r for r in data.get("items") or []
        if r.get("signature_status") == "Registered"
    ]

    return {
        "ok": True,
        "phase": "27B",
        "restrict": restrict,
        "seed_count": seed.get("count"),
        "employee_controls_count": data.get("count"),
        "registered_signature_count": len(registered),
        "routes": data.get("routes"),
        "ready": True,
    }


@frappe.whitelist()
def phase27b_export_admin_employee_signature_snapshot_json():
    data = phase27b_employee_signature_admin_data(limit=500)
    health = phase27b_admin_employee_signature_health()

    payload = {
        "data": data,
        "health": health,
    }

    sha = _phase27b_sha256_text(payload)
    content = _phase27b_json_dumps(payload).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27b-admin-employee-signatures-snapshot-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27B",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "employee_controls_count": data.get("count"),
        "registered_signature_count": health.get("registered_signature_count"),
        "routes": data.get("routes"),
    }


# Phase 27C: Enforce Signature DocType Control rules in UI and server-side actions.
import json as _phase27c_json
import hashlib as _phase27c_hashlib


PHASE27C_DTC_DT = "Signature DocType Control"
PHASE27C_SETTINGS_DT = "Signature System Settings"


def _phase27c_json_dumps(data):
    return _phase27c_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27c_sha256(data):
    if not isinstance(data, str):
        data = _phase27c_json_dumps(data)
    return _phase27c_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27c_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase27c_require_admin():
    if not _phase27c_is_admin():
        frappe.throw("Only Signature Administrators can manage DocType signature controls.")


def _phase27c_bool(v):
    return bool(int(v or 0)) if str(v).strip() not in ["", "None"] else False


def _phase27c_system_enabled():
    if not frappe.db.exists("DocType", PHASE27C_SETTINGS_DT):
        return True

    try:
        settings = frappe.get_single(PHASE27C_SETTINGS_DT)

        if hasattr(settings, "system_enabled"):
            return bool(int(settings.system_enabled or 0))

        return True

    except Exception:
        return True


def _phase27c_get_control(reference_doctype):
    if not frappe.db.exists("DocType", PHASE27C_DTC_DT):
        return None

    if not reference_doctype:
        return None

    name = frappe.db.exists(PHASE27C_DTC_DT, reference_doctype)

    if not name:
        rows = frappe.get_all(
            PHASE27C_DTC_DT,
            filters={"reference_doctype": reference_doctype},
            pluck="name",
            limit=1,
        )
        name = rows[0] if rows else None

    if not name:
        return None

    try:
        return frappe.get_doc(PHASE27C_DTC_DT, name)
    except Exception:
        return None


def _phase27c_control_gate(reference_doctype):
    """
    Central policy gate used by UI context and server actions.
    """
    if not _phase27c_system_enabled():
        return {
            "allowed": False,
            "reason": "Signature system is disabled.",
            "enabled": False,
            "show_signature_button": False,
            "allow_saved_signature": False,
            "allow_direction_text": False,
            "allow_direction_drawing": False,
            "allow_direction": False,
            "allow_reject": False,
            "allow_external_requests": False,
        }

    control = _phase27c_get_control(reference_doctype)

    if not control:
        return {
            "allowed": False,
            "reason": f"No Signature DocType Control found for {reference_doctype}.",
            "enabled": False,
            "show_signature_button": False,
            "allow_saved_signature": False,
            "allow_direction_text": False,
            "allow_direction_drawing": False,
            "allow_direction": False,
            "allow_reject": False,
            "allow_external_requests": False,
        }

    enabled = _phase27c_bool(control.get("enabled"))
    show_button = _phase27c_bool(control.get("show_signature_button"))

    allow_direction_text = _phase27c_bool(control.get("allow_direction_text"))
    allow_direction_drawing = _phase27c_bool(control.get("allow_direction_drawing"))

    gate = {
        "allowed": bool(enabled and show_button),
        "reason": None,
        "control": control.name,
        "reference_doctype": reference_doctype,
        "enabled": enabled,
        "show_signature_button": show_button,
        "workflow_mode": control.get("workflow_mode") or "Sequential",
        "allow_saved_signature": _phase27c_bool(control.get("allow_saved_signature")),
        "allow_direction_text": allow_direction_text,
        "allow_direction_drawing": allow_direction_drawing,
        "allow_direction": bool(allow_direction_text or allow_direction_drawing),
        "allow_reject": _phase27c_bool(control.get("allow_reject")),
        "allow_external_requests": _phase27c_bool(control.get("allow_external_requests")),
        "require_signature_profile": _phase27c_bool(control.get("require_signature_profile")),
        "auto_generate_certificate": _phase27c_bool(control.get("auto_generate_certificate")),
        "auto_generate_signed_pdf": _phase27c_bool(control.get("auto_generate_signed_pdf")),
    }

    if not enabled:
        gate["reason"] = f"Signature is disabled for {reference_doctype}."

    elif not show_button:
        gate["reason"] = f"Signature button is hidden for {reference_doctype}."

    return gate


def _phase27c_apply_gate_to_context(ctx, gate):
    ctx = ctx or {}

    ctx["doctype_control_gate"] = gate

    if not gate.get("allowed"):
        ctx["has_signature_action"] = False
        ctx["allowed_actions"] = {}
        ctx["signature_button_hidden_by_control"] = True
        ctx["control_block_reason"] = gate.get("reason")

        first = ctx.get("first_pending") or {}
        first["allowed_actions"] = {}
        ctx["first_pending"] = first

        return ctx

    allowed = dict(ctx.get("allowed_actions") or {})

    allowed["saved_signature"] = bool(allowed.get("saved_signature") and gate.get("allow_saved_signature"))
    allowed["direction"] = bool(allowed.get("direction") and gate.get("allow_direction"))
    allowed["reject"] = bool(allowed.get("reject") and gate.get("allow_reject"))

    ctx["allowed_actions"] = allowed

    first = ctx.get("first_pending")

    if first:
        first["allowed_actions"] = allowed
        first["can_use_saved_signature"] = 1 if gate.get("allow_saved_signature") and first.get("can_use_saved_signature") else 0
        first["can_draw_direction"] = 1 if gate.get("allow_direction_drawing") and first.get("can_draw_direction") else 0
        first["can_write_direction_text"] = 1 if gate.get("allow_direction_text") and first.get("can_write_direction_text") else 0
        first["can_reject"] = 1 if gate.get("allow_reject") and first.get("can_reject") else 0
        ctx["first_pending"] = first

    ctx["has_signature_action"] = bool(ctx.get("has_signature_action") and any(allowed.values()))
    ctx["signature_button_hidden_by_control"] = False

    return ctx


if not globals().get("_phase27c_original_phase26n_get_classic_signature_context") and globals().get("phase26n_get_classic_signature_context"):
    _phase27c_original_phase26n_get_classic_signature_context = phase26n_get_classic_signature_context


@frappe.whitelist()
def phase26n_get_classic_signature_context(reference_doctype: str, reference_name: str):
    """
    Override Phase 26N context:
    Classic Signature UX now respects Signature DocType Control.
    """
    if globals().get("_phase27c_original_phase26n_get_classic_signature_context"):
        ctx = _phase27c_original_phase26n_get_classic_signature_context(reference_doctype, reference_name)
    else:
        ctx = get_document_signature_form_context(
            reference_doctype=reference_doctype,
            reference_name=reference_name,
            auto_sync=0,
        )

    gate = _phase27c_control_gate(reference_doctype)
    ctx = _phase27c_apply_gate_to_context(ctx, gate)
    ctx["phase"] = "27C"

    return ctx


def _phase27c_get_request_doc(request_name):
    if globals().get("_phase26d_get_request"):
        return _phase26d_get_request(request_name)

    if not frappe.db.exists(PHASE26C_REQUEST_DT, request_name):
        frappe.throw(f"Signature request not found: {request_name}")

    return frappe.get_doc(PHASE26C_REQUEST_DT, request_name)


def _phase27c_require_action_allowed(request_name, action, payload=None):
    req = _phase27c_get_request_doc(request_name)
    gate = _phase27c_control_gate(req.reference_doctype)

    if not gate.get("enabled"):
        frappe.throw(gate.get("reason") or "Signature is disabled for this DocType.")

    if action == "accept" and not gate.get("allow_saved_signature"):
        frappe.throw("Saved signature is disabled for this DocType by Signature DocType Control.")

    if action == "reject" and not gate.get("allow_reject"):
        frappe.throw("Reject / Return is disabled for this DocType by Signature DocType Control.")

    if action == "direction":
        payload = payload or {}
        has_text = bool((payload.get("direction_text") or payload.get("guidance_text") or "").strip())
        has_drawing = bool((payload.get("direction_svg") or "").strip())

        if not gate.get("allow_direction"):
            frappe.throw("Direction is disabled for this DocType by Signature DocType Control.")

        if has_text and not gate.get("allow_direction_text"):
            frappe.throw("Direction text is disabled for this DocType.")

        if has_drawing and not gate.get("allow_direction_drawing"):
            frappe.throw("Direction drawing is disabled for this DocType.")

    return {
        "request": req,
        "gate": gate,
    }


if not globals().get("_phase27c_original_phase26n_accept_signature_request") and globals().get("phase26n_accept_signature_request"):
    _phase27c_original_phase26n_accept_signature_request = phase26n_accept_signature_request


@frappe.whitelist()
def phase26n_accept_signature_request(request_name: str, note: str = None):
    _phase27c_require_action_allowed(request_name, "accept")

    if globals().get("_phase27c_original_phase26n_accept_signature_request"):
        result = _phase27c_original_phase26n_accept_signature_request(request_name, note)
    else:
        result = apply_saved_signature_request(request_name)

    result["phase"] = "27C"
    result["doctype_control_enforced"] = True

    return result


if not globals().get("_phase27c_original_phase26n_refuse_signature_request") and globals().get("phase26n_refuse_signature_request"):
    _phase27c_original_phase26n_refuse_signature_request = phase26n_refuse_signature_request


@frappe.whitelist()
def phase26n_refuse_signature_request(request_name: str, reason: str = None):
    _phase27c_require_action_allowed(request_name, "reject")

    if globals().get("_phase27c_original_phase26n_refuse_signature_request"):
        result = _phase27c_original_phase26n_refuse_signature_request(request_name, reason)
    else:
        result = reject_document_signature_request(request_name=request_name, reason=reason or "Rejected by signer.")

    result["phase"] = "27C"
    result["doctype_control_enforced"] = True

    return result


if not globals().get("_phase27c_original_phase26n_linear_guidance_signature_request") and globals().get("phase26n_linear_guidance_signature_request"):
    _phase27c_original_phase26n_linear_guidance_signature_request = phase26n_linear_guidance_signature_request


@frappe.whitelist()
def phase26n_linear_guidance_signature_request(request_name: str, guidance_text: str = None, direction_svg: str = None):
    _phase27c_require_action_allowed(
        request_name,
        "direction",
        {
            "guidance_text": guidance_text,
            "direction_svg": direction_svg,
        },
    )

    if globals().get("_phase27c_original_phase26n_linear_guidance_signature_request"):
        result = _phase27c_original_phase26n_linear_guidance_signature_request(request_name, guidance_text, direction_svg)
    else:
        result = apply_direction_signature_request(
            request_name=request_name,
            direction_text=guidance_text,
            direction_svg=direction_svg,
        )

    result["phase"] = "27C"
    result["doctype_control_enforced"] = True

    return result


@frappe.whitelist()
def phase27c_apply_doctype_control_client_scripts():
    _phase27c_require_admin()

    if not frappe.db.exists("DocType", PHASE27C_DTC_DT):
        frappe.throw("Signature DocType Control is not installed.")

    rows = frappe.get_all(
        PHASE27C_DTC_DT,
        fields=["reference_doctype", "enabled", "show_signature_button"],
        limit_page_length=1000,
        order_by="reference_doctype asc",
    )

    results = []

    for r in rows:
        dt = r.reference_doctype

        if not dt or not frappe.db.exists("DocType", dt):
            results.append({
                "reference_doctype": dt,
                "ok": False,
                "reason": "DocType not found.",
            })
            continue

        try:
            should_enable = bool(int(r.enabled or 0) and int(r.show_signature_button or 0))

            cs_name = f"Surhan Classic Signature UX - {dt}"

            if should_enable:
                if globals().get("phase26n_install_classic_client_script"):
                    res = phase26n_install_classic_client_script(dt)
                    results.append({
                        "reference_doctype": dt,
                        "ok": True,
                        "action": "enabled_or_installed",
                        "client_script": res.get("client_script"),
                    })
                else:
                    results.append({
                        "reference_doctype": dt,
                        "ok": False,
                        "reason": "phase26n_install_classic_client_script not found.",
                    })

            else:
                if frappe.db.exists("DocType", "Client Script"):
                    cs = frappe.db.exists("Client Script", cs_name)

                    if cs:
                        frappe.db.set_value("Client Script", cs, "enabled", 0, update_modified=True)
                        results.append({
                            "reference_doctype": dt,
                            "ok": True,
                            "action": "disabled",
                            "client_script": cs,
                        })
                    else:
                        results.append({
                            "reference_doctype": dt,
                            "ok": True,
                            "action": "already_absent",
                            "client_script": cs_name,
                        })

                else:
                    results.append({
                        "reference_doctype": dt,
                        "ok": True,
                        "action": "client_script_doctype_missing",
                    })

            frappe.clear_cache(doctype=dt)

        except Exception as exc:
            results.append({
                "reference_doctype": dt,
                "ok": False,
                "error": str(exc),
            })

    frappe.db.commit()

    return {
        "ok": True,
        "phase": "27C",
        "count": len(results),
        "enabled_count": len([x for x in results if x.get("action") == "enabled_or_installed"]),
        "disabled_count": len([x for x in results if x.get("action") == "disabled"]),
        "failed": [x for x in results if not x.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase27c_gate_preview(reference_doctype: str):
    _phase27c_require_admin()

    gate = _phase27c_control_gate(reference_doctype)

    cs_state = None

    if frappe.db.exists("DocType", "Client Script"):
        cs = frappe.db.exists("Client Script", f"Surhan Classic Signature UX - {reference_doctype}")

        if cs:
            cs_state = {
                "client_script": cs,
                "enabled": bool(frappe.db.get_value("Client Script", cs, "enabled")),
            }

    return {
        "ok": True,
        "phase": "27C",
        "reference_doctype": reference_doctype,
        "gate": gate,
        "client_script": cs_state,
        "ready": True,
    }


@frappe.whitelist()
def phase27c_control_enforcement_health():
    _phase27c_require_admin()

    applied = phase27c_apply_doctype_control_client_scripts()

    previews = []

    for dt in ["Task", "Purchase Order", "Sales Order", "Leave Application", "Internal Signature Demo Document"]:
        if frappe.db.exists("DocType", dt):
            try:
                previews.append(phase27c_gate_preview(dt))
            except Exception as exc:
                previews.append({
                    "reference_doctype": dt,
                    "ok": False,
                    "error": str(exc),
                })

    return {
        "ok": True,
        "phase": "27C",
        "applied": applied,
        "previews": previews,
        "ready": bool(not applied.get("failed")),
    }


@frappe.whitelist()
def phase27c_export_control_enforcement_snapshot_json():
    health = phase27c_control_enforcement_health()
    sha = _phase27c_sha256(health)
    content = _phase27c_json_dumps(health).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27c-doctype-control-enforcement-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27C",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "ready": health.get("ready"),
        "enabled_count": (health.get("applied") or {}).get("enabled_count"),
        "disabled_count": (health.get("applied") or {}).get("disabled_count"),
    }


# Phase 27D: Signature Setup Wizard and one-click admin diagnostics.
import json as _phase27d_json
import hashlib as _phase27d_hashlib


def _phase27d_json_dumps(data):
    return _phase27d_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27d_sha256(data):
    if not isinstance(data, str):
        data = _phase27d_json_dumps(data)
    return _phase27d_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27d_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
    }))


def _phase27d_require_admin():
    if not _phase27d_is_admin():
        frappe.throw("Only Signature Administrators can access the Signature Setup Wizard.")


def _phase27d_fn_exists(name):
    return callable(globals().get(name))


def _phase27d_safe_call(fn_name, *args, **kwargs):
    fn = globals().get(fn_name)

    if not callable(fn):
        return {
            "ok": False,
            "available": False,
            "function": fn_name,
            "error": f"{fn_name} is not installed.",
        }

    try:
        result = fn(*args, **kwargs)

        if isinstance(result, dict):
            result.setdefault("ok", True)
            result["available"] = True
            result["function"] = fn_name
            return result

        return {
            "ok": True,
            "available": True,
            "function": fn_name,
            "result": result,
        }

    except Exception as exc:
        return {
            "ok": False,
            "available": True,
            "function": fn_name,
            "error": str(exc),
        }




def _phase27d_has_page(route):
    try:
        import os
        app_path = frappe.get_app_path("surhan_signature")
        route = str(route or "").strip("/").replace("-", "_")
        html_path = os.path.join(app_path, "www", route.replace("_", "-") + ".html")
        py_path = os.path.join(app_path, "www", route.replace("_", "-") + ".py")
        return os.path.exists(html_path) and os.path.exists(py_path)
    except Exception:
        return False




def _phase27d_status_counts(dt, fieldname):
    if not frappe.db.exists("DocType", dt):
        return {}

    try:
        if not frappe.get_meta(dt).has_field(fieldname):
            return {}

        rows = frappe.db.sql(
            f"""
            SELECT `{fieldname}` AS status_value, COUNT(`name`) AS count_value
            FROM `tab{dt}`
            GROUP BY `{fieldname}`
            """,
            as_dict=True,
        )

        return {
            (r.get("status_value") or "Blank"): int(r.get("count_value") or 0)
            for r in rows
        }

    except Exception:
        return {}


def _phase27d_step_definitions():
    return [
        {
            "key": "workspace",
            "title": "1. Workspace and Module",
            "description": "Unify all signature objects under Surhan Signature workspace and module.",
            "repair_function": "phase27a_fix5_unify_control_center",
            "health_function": "phase27a_admin_control_health",
            "route": "/app/workspace/surhan-signature",
        },
        {
            "key": "admin_control",
            "title": "2. Admin Control Center",
            "description": "Check the central control screen and administrative DocTypes.",
            "repair_function": "phase27a_refresh_control_center",
            "health_function": "phase27a_admin_control_data",
            "route": "/signature-admin-control",
        },
        {
            "key": "employee_signatures",
            "title": "3. Employee Signatures",
            "description": "Check admin-only employee signature registration and permissions.",
            "repair_function": "phase27b_admin_employee_signature_health",
            "health_function": "phase27b_employee_signature_admin_data",
            "route": "/signature-admin-employee-signatures",
        },
        {
            "key": "doctype_controls",
            "title": "4. DocType Controls",
            "description": "Apply DocType signature rules and button visibility.",
            "repair_function": "phase27c_control_enforcement_health",
            "health_function": "phase27c_control_enforcement_health",
            "route": "/signature-admin-control",
        },
        {
            "key": "requests",
            "title": "5. Signature Requests",
            "description": "Check internal signature requests, pending actions, signed requests, and rejected requests.",
            "repair_function": None,
            "health_function": None,
            "route": "/app/document-signature-request",
        },
        {
            "key": "certificates",
            "title": "6. Certificates and PDFs",
            "description": "Check internal certificates, verification links, and signed PDFs.",
            "repair_function": None,
            "health_function": None,
            "route": "/app/internal-signature-certificate",
        },
        {
            "key": "external_gateway",
            "title": "7. External Gateway",
            "description": "Check external systems, external requests, gateway security, and callbacks.",
            "repair_function": "phase26j_external_console_health",
            "health_function": "phase26j_external_console_health",
            "route": "/external-signature-console",
        },
        {
            "key": "production_readiness",
            "title": "8. Production Readiness",
            "description": "Check final blockers and warnings before production deployment.",
            "repair_function": "phase26o_production_readiness_report",
            "health_function": "phase26o_production_readiness_report",
            "route": "/signature-production-readiness",
        },
    ]




@frappe.whitelist()
def phase27d_setup_wizard_data():
    _phase27d_require_admin()

    steps = [_phase27d_evaluate_step(s) for s in _phase27d_step_definitions()]
    ready_count = sum(1 for s in steps if s.get("ready"))
    attention_count = sum(1 for s in steps if s.get("status") == "Needs Attention")

    data = {
        "ok": True,
        "phase": "27D",
        "generated_at": str(now_datetime()),
        "ready_count": ready_count,
        "attention_count": attention_count,
        "total_steps": len(steps),
        "overall_ready": attention_count == 0,
        "steps": steps,
        "counts": _phase27d_basic_counts(),
        "routes": {
            "setup_wizard": "/signature-setup-wizard",
            "admin_control": "/signature-admin-control",
            "admin_employee_signatures": "/signature-admin-employee-signatures",
            "workspace": "/app/workspace/surhan-signature",
            "production_readiness": "/signature-production-readiness",
            "external_console": "/external-signature-console",
        },
    }

    return data


@frappe.whitelist()
def phase27d_run_setup_step(step_key: str):
    _phase27d_require_admin()

    step_key = (step_key or "").strip()

    step = None

    for s in _phase27d_step_definitions():
        if s.get("key") == step_key:
            step = s
            break

    if not step:
        frappe.throw(f"Unknown setup step: {step_key}")

    before = _phase27d_evaluate_step(step)

    repair_function = step.get("repair_function")
    repair = None

    if repair_function:
        if repair_function == "phase26o_production_readiness_report":
            repair = _phase27d_safe_call(repair_function, run_cleanup=0)
        else:
            repair = _phase27d_safe_call(repair_function)

    after = _phase27d_evaluate_step(step)

    return {
        "ok": True,
        "phase": "27D",
        "step_key": step_key,
        "before": before,
        "repair": repair,
        "after": after,
        "ready": after.get("ready"),
    }


@frappe.whitelist()
def phase27d_run_full_setup_wizard():
    _phase27d_require_admin()

    results = []

    for step in _phase27d_step_definitions():
        key = step.get("key")

        if key in {"requests", "certificates"}:
            results.append({
                "step_key": key,
                "skipped_repair": True,
                "after": _phase27d_evaluate_step(step),
            })
            continue

        try:
            results.append(phase27d_run_setup_step(key))
        except Exception as exc:
            results.append({
                "ok": False,
                "step_key": key,
                "error": str(exc),
            })

    data = phase27d_setup_wizard_data()

    return {
        "ok": True,
        "phase": "27D",
        "results": results,
        "wizard": data,
        "ready": data.get("overall_ready"),
    }


@frappe.whitelist()
def phase27d_export_setup_wizard_snapshot_json():
    data = phase27d_setup_wizard_data()
    sha = _phase27d_sha256(data)
    content = _phase27d_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27d-signature-setup-wizard-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27D",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "overall_ready": data.get("overall_ready"),
        "ready_count": data.get("ready_count"),
        "attention_count": data.get("attention_count"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27d_setup_wizard_health():
    data = phase27d_setup_wizard_data()
    export = phase27d_export_setup_wizard_snapshot_json()

    return {
        "ok": True,
        "phase": "27D",
        "overall_ready": data.get("overall_ready"),
        "ready_count": data.get("ready_count"),
        "attention_count": data.get("attention_count"),
        "total_steps": data.get("total_steps"),
        "steps": data.get("steps"),
        "routes": data.get("routes"),
        "export": export,
        "ready": True,
    }


# Phase 27D-FIX1: safe Single DocType counting + final Signing module cleanup.








def _phase27d_fix1_refs_for_module(module_name):
    refs = {
        "doctype_refs": [],
        "workspace_refs": [],
    }

    try:
        refs["doctype_refs"] = frappe.get_all(
            "DocType",
            filters={"module": module_name},
            fields=["name", "module", "custom"],
            limit_page_length=1000,
        )
    except Exception:
        refs["doctype_refs"] = []

    try:
        if frappe.db.exists("DocType", "Workspace") and frappe.get_meta("Workspace").has_field("module"):
            refs["workspace_refs"] = frappe.get_all(
                "Workspace",
                filters={"module": module_name},
                fields=["name", "title", "module"],
                limit_page_length=500,
            )
    except Exception:
        refs["workspace_refs"] = []

    return refs


@frappe.whitelist()
def phase27d_fix1_cleanup_signing_references():
    _phase27d_require_admin()

    official_module = "Surhan Signature"
    wrong_module = "Signing"

    if not frappe.db.exists("Module Def", official_module):
        doc = frappe.new_doc("Module Def")
        doc.module_name = official_module
        doc.app_name = "surhan_signature"
        doc.insert(ignore_permissions=True)
    else:
        frappe.db.set_value(
            "Module Def",
            official_module,
            "app_name",
            "surhan_signature",
            update_modified=False,
        )

    frappe.db.commit()

    before = _phase27d_fix1_refs_for_module(wrong_module)
    moved_doctypes = []
    moved_workspaces = []
    failed = []

    for r in before.get("doctype_refs") or []:
        dt = r.get("name")

        try:
            frappe.db.set_value(
                "DocType",
                dt,
                "module",
                official_module,
                update_modified=False,
            )
            frappe.clear_cache(doctype=dt)
            moved_doctypes.append(dt)
        except Exception as exc:
            failed.append({
                "type": "DocType",
                "name": dt,
                "error": str(exc),
            })

    for r in before.get("workspace_refs") or []:
        ws = r.get("name")

        try:
            frappe.db.set_value(
                "Workspace",
                ws,
                "module",
                official_module,
                update_modified=False,
            )
            moved_workspaces.append(ws)
        except Exception as exc:
            failed.append({
                "type": "Workspace",
                "name": ws,
                "error": str(exc),
            })

    frappe.db.commit()

    after_move = _phase27d_fix1_refs_for_module(wrong_module)
    deleted_signing = False
    delete_error = None

    if not (after_move.get("doctype_refs") or after_move.get("workspace_refs")):
        if frappe.db.exists("Module Def", wrong_module):
            try:
                frappe.delete_doc(
                    "Module Def",
                    wrong_module,
                    ignore_permissions=True,
                    force=True,
                )
                frappe.db.commit()
                deleted_signing = True
            except Exception as exc:
                frappe.db.rollback()
                delete_error = str(exc)

    final = _phase27d_fix1_refs_for_module(wrong_module)

    return {
        "ok": True,
        "phase_fix": "27D-FIX1",
        "before": before,
        "moved_doctypes": moved_doctypes,
        "moved_workspaces": moved_workspaces,
        "failed": failed,
        "deleted_signing": deleted_signing,
        "delete_error": delete_error,
        "after": final,
        "module_def_signing": frappe.db.exists("Module Def", wrong_module),
        "ready": bool(
            not failed
            and not final.get("doctype_refs")
            and not final.get("workspace_refs")
            and not frappe.db.exists("Module Def", wrong_module)
        ),
    }


def _phase27d_evaluate_step(step):
    """
    FIX1 override:
    Same wizard evaluation, but using safe counts for Single DocTypes.
    """
    key = step.get("key")

    result = {
        "key": key,
        "title": step.get("title"),
        "description": step.get("description"),
        "route": step.get("route"),
        "available": True,
        "ready": False,
        "status": "Needs Check",
        "summary": {},
        "repair_function": step.get("repair_function"),
        "health_function": step.get("health_function"),
    }

    counts = _phase27d_basic_counts()

    if key == "workspace":
        refs_signing = []
        refs_surhan = []

        try:
            refs_signing = frappe.get_all("DocType", filters={"module": "Signing"}, pluck="name", limit_page_length=1000)
            refs_surhan = frappe.get_all("DocType", filters={"module": "Surhan Signature"}, pluck="name", limit_page_length=1000)
        except Exception:
            pass

        result["summary"] = {
            "module_def_surhan_signature": frappe.db.exists("Module Def", "Surhan Signature"),
            "module_def_signing": frappe.db.exists("Module Def", "Signing"),
            "refs_signing_count": len(refs_signing),
            "refs_surhan_signature_count": len(refs_surhan),
            "workspace_exists": frappe.db.exists("Workspace", "Surhan Signature") if frappe.db.exists("DocType", "Workspace") else None,
        }

        result["ready"] = bool(
            result["summary"]["module_def_surhan_signature"]
            and not result["summary"]["module_def_signing"]
            and result["summary"]["refs_signing_count"] == 0
            and result["summary"]["workspace_exists"]
        )

    elif key == "admin_control":
        result["summary"] = {
            "settings_dt": frappe.db.exists("DocType", "Signature System Settings"),
            "doctype_control_dt": frappe.db.exists("DocType", "Signature DocType Control"),
            "employee_control_dt": frappe.db.exists("DocType", "Signature Employee Control"),
            "admin_page_exists": _phase27d_has_page("signature-admin-control"),
            "counts": counts,
        }

        result["ready"] = bool(
            result["summary"]["settings_dt"]
            and result["summary"]["doctype_control_dt"]
            and result["summary"]["employee_control_dt"]
            and result["summary"]["admin_page_exists"]
        )

    elif key == "employee_signatures":
        result["summary"] = {
            "employee_controls": counts["signature_employee_controls"],
            "profiles": counts["employee_signature_profiles"],
            "admin_page_exists": _phase27d_has_page("signature-admin-employee-signatures"),
            "registered": 0,
        }

        try:
            if frappe.db.exists("DocType", "Signature Employee Control"):
                result["summary"]["registered"] = frappe.db.count("Signature Employee Control", {"signature_status": "Registered"})
        except Exception:
            pass

        result["ready"] = bool(
            result["summary"]["admin_page_exists"]
            and result["summary"]["employee_controls"] > 0
            and result["summary"]["registered"] > 0
        )

    elif key == "doctype_controls":
        enabled = 0
        scripts = 0

        try:
            if frappe.db.exists("DocType", "Signature DocType Control"):
                enabled = frappe.db.count("Signature DocType Control", {"enabled": 1})
            if frappe.db.exists("DocType", "Client Script"):
                scripts = frappe.db.count("Client Script", {"name": ["like", "Surhan Classic Signature UX -%"], "enabled": 1})
        except Exception:
            pass

        result["summary"] = {
            "doctype_controls": counts["signature_doctype_controls"],
            "enabled_doctypes": enabled,
            "enabled_classic_scripts": scripts,
        }
        result["ready"] = bool(enabled > 0 and scripts > 0)

    elif key == "requests":
        result["summary"] = {
            "count": counts["document_signature_requests"],
            "status_counts": _phase27d_status_counts("Document Signature Request", "status"),
        }
        result["ready"] = counts["document_signature_requests"] > 0

    elif key == "certificates":
        result["summary"] = {
            "count": counts["internal_signature_certificates"],
            "certificate_status_counts": _phase27d_status_counts("Internal Signature Certificate", "certificate_status"),
        }
        result["ready"] = counts["internal_signature_certificates"] > 0

    elif key == "external_gateway":
        result["summary"] = {
            "external_systems": counts["external_systems"],
            "external_requests": counts["external_requests"],
            "console_function_available": _phase27d_fn_exists("phase26j_external_console_health"),
        }
        result["ready"] = bool(_phase27d_fn_exists("phase26j_external_console_health"))

    elif key == "production_readiness":
        result["summary"] = {
            "production_readiness_function_available": _phase27d_fn_exists("phase26o_production_readiness_report"),
            "readiness_page_exists": _phase27d_has_page("signature-production-readiness"),
        }

        if _phase27d_fn_exists("phase26o_production_readiness_report"):
            report = _phase27d_safe_call("phase26o_production_readiness_report", run_cleanup=0)
            result["summary"]["readiness"] = report.get("readiness")
            result["summary"]["blockers"] = report.get("blockers")
            result["summary"]["warnings"] = report.get("warnings")
            result["ready"] = bool((report.get("readiness") or {}).get("staging_ready"))
        else:
            result["ready"] = True
            result["status"] = "Optional"

    if result["ready"]:
        result["status"] = "Ready"
    elif result["status"] != "Optional":
        result["status"] = "Needs Attention"

    return result


@frappe.whitelist()
def phase27d_fix1_cleanup_and_health():
    _phase27d_require_admin()

    cleanup = phase27d_fix1_cleanup_signing_references()
    data = phase27d_setup_wizard_data()
    export = phase27d_export_setup_wizard_snapshot_json()

    return {
        "ok": True,
        "phase_fix": "27D-FIX1",
        "cleanup": cleanup,
        "overall_ready": data.get("overall_ready"),
        "ready_count": data.get("ready_count"),
        "attention_count": data.get("attention_count"),
        "total_steps": data.get("total_steps"),
        "steps": data.get("steps"),
        "export": export,
        "routes": data.get("routes"),
        "ready": bool(data.get("overall_ready")),
    }


# Phase 27D-FIX2: robust table counts for Setup Wizard.
import re as _phase27d_fix2_re


def _phase27d_fix2_safe_identifier(value):
    value = str(value or "")

    if not _phase27d_fix2_re.match(r"^[A-Za-z0-9 _.-]+$", value):
        frappe.throw(f"Unsafe identifier: {value}")

    return value


def _phase27d_is_single_doctype(dt):
    try:
        if not frappe.db.exists("DocType", dt):
            return False

        return bool(int(frappe.db.get_value("DocType", dt, "issingle") or 0))
    except Exception:
        return False


def _phase27d_table_exists_for_doctype(dt):
    """
    FIX2:
    Avoid frappe.db.table_exists ambiguity.
    Check the physical table directly.
    """
    if not frappe.db.exists("DocType", dt):
        return False

    if _phase27d_is_single_doctype(dt):
        return True

    table = "tab" + _phase27d_fix2_safe_identifier(dt)

    try:
        return bool(frappe.db.sql("SHOW TABLES LIKE %s", (table,)))
    except Exception:
        return False


def _phase27d_count(dt, filters=None):
    """
    FIX2:
    Safe raw SQL count.
    Supports the filters used by this wizard:
    - equality
    - ["like", value]
    """
    if not frappe.db.exists("DocType", dt):
        return 0

    if _phase27d_is_single_doctype(dt):
        return 1

    if not _phase27d_table_exists_for_doctype(dt):
        return 0

    dt = _phase27d_fix2_safe_identifier(dt)
    table = "tab" + dt

    where = []
    values = []

    filters = filters or {}

    for fieldname, value in filters.items():
        fieldname = _phase27d_fix2_safe_identifier(fieldname)

        if isinstance(value, (list, tuple)) and len(value) >= 2:
            op = str(value[0]).lower()

            if op == "like":
                where.append(f"`{fieldname}` LIKE %s")
                values.append(value[1])

            elif op == "in":
                items = list(value[1] or [])
                if not items:
                    return 0
                where.append(f"`{fieldname}` IN ({', '.join(['%s'] * len(items))})")
                values.extend(items)

            else:
                where.append(f"`{fieldname}` = %s")
                values.append(value[1])
        else:
            where.append(f"`{fieldname}` = %s")
            values.append(value)

    sql = f"SELECT COUNT(*) AS count_value FROM `{table}`"

    if where:
        sql += " WHERE " + " AND ".join(where)

    try:
        return int((frappe.db.sql(sql, tuple(values))[0][0]) or 0)
    except Exception:
        return 0


def _phase27d_basic_counts():
    return {
        "signature_system_settings": _phase27d_count("Signature System Settings"),
        "signature_doctype_controls": _phase27d_count("Signature DocType Control"),
        "signature_employee_controls": _phase27d_count("Signature Employee Control"),
        "employee_signature_profiles": _phase27d_count("Employee Signature Profile"),
        "document_signature_requests": _phase27d_count("Document Signature Request"),
        "internal_signature_certificates": _phase27d_count("Internal Signature Certificate"),
        "external_systems": _phase27d_count("Internal Signature External System"),
        "external_requests": _phase27d_count("Internal Signature External Request"),
        "classic_signature_client_scripts": _phase27d_count(
            "Client Script",
            {"name": ["like", "Surhan Classic Signature UX -%"]},
        ) if frappe.db.exists("DocType", "Client Script") else 0,
    }


@frappe.whitelist()
def phase27d_fix2_count_diagnostics():
    _phase27d_require_admin()

    doctypes = [
        "Signature System Settings",
        "Signature DocType Control",
        "Signature Employee Control",
        "Employee Signature Profile",
        "Document Signature Request",
        "Internal Signature Certificate",
        "Internal Signature External System",
        "Internal Signature External Request",
        "Client Script",
    ]

    rows = []

    for dt in doctypes:
        rows.append({
            "doctype": dt,
            "exists": bool(frappe.db.exists("DocType", dt)),
            "issingle": _phase27d_is_single_doctype(dt),
            "table_exists": _phase27d_table_exists_for_doctype(dt),
            "count": _phase27d_count(dt),
        })

    return {
        "ok": True,
        "phase_fix": "27D-FIX2",
        "rows": rows,
        "basic_counts": _phase27d_basic_counts(),
    }


@frappe.whitelist()
def phase27d_fix2_health():
    _phase27d_require_admin()

    diagnostics = phase27d_fix2_count_diagnostics()
    data = phase27d_setup_wizard_data()
    export = phase27d_export_setup_wizard_snapshot_json()

    return {
        "ok": True,
        "phase_fix": "27D-FIX2",
        "diagnostics": diagnostics,
        "overall_ready": data.get("overall_ready"),
        "ready_count": data.get("ready_count"),
        "attention_count": data.get("attention_count"),
        "total_steps": data.get("total_steps"),
        "steps": data.get("steps"),
        "export": export,
        "routes": data.get("routes"),
        "ready": bool(data.get("overall_ready")),
    }


# Phase 27E: Signature Operations Center.
import json as _phase27e_json
import hashlib as _phase27e_hashlib
import re as _phase27e_re


PHASE27E_REQ_DT = "Document Signature Request"
PHASE27E_CERT_DT = "Internal Signature Certificate"
PHASE27E_EXT_REQ_DT = "Internal Signature External Request"
PHASE27E_EXT_SYS_DT = "Internal Signature External System"


def _phase27e_json_dumps(data):
    return _phase27e_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27e_sha256(data):
    if not isinstance(data, str):
        data = _phase27e_json_dumps(data)
    return _phase27e_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27e_safe_identifier(value):
    value = str(value or "")
    if not _phase27e_re.match(r"^[A-Za-z0-9 _.-]+$", value):
        frappe.throw(f"Unsafe identifier: {value}")
    return value


def _phase27e_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
    }))


def _phase27e_require_admin():
    if not _phase27e_is_admin():
        frappe.throw("Only Signature Administrators or Auditors can access Signature Operations Center.")


def _phase27e_dt_exists(dt):
    return bool(frappe.db.exists("DocType", dt))


def _phase27e_has_field(dt, fieldname):
    try:
        return bool(_phase27e_dt_exists(dt) and frappe.get_meta(dt).has_field(fieldname))
    except Exception:
        return False


def _phase27e_table_exists(dt):
    if not _phase27e_dt_exists(dt):
        return False

    table = "tab" + _phase27e_safe_identifier(dt)

    try:
        return bool(frappe.db.sql("SHOW TABLES LIKE %s", (table,)))
    except Exception:
        return False


def _phase27e_count(dt, filters=None):
    if not _phase27e_dt_exists(dt):
        return 0

    try:
        if bool(int(frappe.db.get_value("DocType", dt, "issingle") or 0)):
            return 1
    except Exception:
        pass

    if not _phase27e_table_exists(dt):
        return 0

    table = "tab" + _phase27e_safe_identifier(dt)
    filters = filters or {}

    where = []
    values = []

    for fieldname, value in filters.items():
        fieldname = _phase27e_safe_identifier(fieldname)

        if isinstance(value, (list, tuple)) and len(value) >= 2:
            op = str(value[0]).lower()

            if op == "in":
                items = list(value[1] or [])
                if not items:
                    return 0
                where.append(f"`{fieldname}` IN ({', '.join(['%s'] * len(items))})")
                values.extend(items)

            elif op == "like":
                where.append(f"`{fieldname}` LIKE %s")
                values.append(value[1])

            else:
                where.append(f"`{fieldname}` = %s")
                values.append(value[1])
        else:
            where.append(f"`{fieldname}` = %s")
            values.append(value)

    sql = f"SELECT COUNT(*) FROM `{table}`"

    if where:
        sql += " WHERE " + " AND ".join(where)

    try:
        return int(frappe.db.sql(sql, tuple(values))[0][0] or 0)
    except Exception:
        return 0


def _phase27e_status_counts(dt, fieldname):
    if not _phase27e_dt_exists(dt) or not _phase27e_has_field(dt, fieldname) or not _phase27e_table_exists(dt):
        return {}

    dt = _phase27e_safe_identifier(dt)
    fieldname = _phase27e_safe_identifier(fieldname)
    table = "tab" + dt

    try:
        rows = frappe.db.sql(
            f"""
            SELECT `{fieldname}` AS status_value, COUNT(*) AS count_value
            FROM `{table}`
            GROUP BY `{fieldname}`
            ORDER BY COUNT(*) DESC
            """,
            as_dict=True,
        )

        return {
            (r.get("status_value") or "Blank"): int(r.get("count_value") or 0)
            for r in rows
        }
    except Exception:
        return {}


def _phase27e_existing_fields(dt, candidates):
    if not _phase27e_dt_exists(dt):
        return []

    meta = frappe.get_meta(dt)

    fields = []

    for f in candidates:
        if f == "name" or meta.has_field(f):
            fields.append(f)

    return fields


def _phase27e_get_many(dt, fields, filters=None, limit=20, order_by="modified desc"):
    if not _phase27e_dt_exists(dt):
        return []

    fields = _phase27e_existing_fields(dt, fields)

    if "name" not in fields:
        fields.insert(0, "name")

    try:
        return frappe.get_all(
            dt,
            fields=fields,
            filters=filters or {},
            order_by=order_by,
            limit_page_length=int(limit or 20),
        )
    except Exception as exc:
        return [{"error": str(exc), "doctype": dt}]


def _phase27e_pending_filters():
    if not _phase27e_has_field(PHASE27E_REQ_DT, "status"):
        return {}

    return {"status": ["in", ["Pending", "Waiting", "In Progress"]]}


@frappe.whitelist()
def phase27e_operations_summary():
    _phase27e_require_admin()

    request_status_counts = _phase27e_status_counts(PHASE27E_REQ_DT, "status")
    cert_status_counts = _phase27e_status_counts(PHASE27E_CERT_DT, "certificate_status")
    external_status_counts = _phase27e_status_counts(PHASE27E_EXT_REQ_DT, "status")
    callback_status_counts = _phase27e_status_counts(PHASE27E_EXT_REQ_DT, "callback_status")

    summary = {
        "ok": True,
        "phase": "27E",
        "generated_at": str(now_datetime()),
        "counts": {
            "signature_requests": _phase27e_count(PHASE27E_REQ_DT),
            "pending_requests": sum(int(request_status_counts.get(k, 0) or 0) for k in ["Pending", "Waiting", "In Progress"]),
            "signed_requests": int(request_status_counts.get("Signed", 0) or 0),
            "rejected_requests": int(request_status_counts.get("Rejected", 0) or 0) + int(request_status_counts.get("Returned", 0) or 0),
            "certificates": _phase27e_count(PHASE27E_CERT_DT),
            "valid_certificates": int(cert_status_counts.get("Valid", 0) or 0),
            "external_systems": _phase27e_count(PHASE27E_EXT_SYS_DT),
            "external_requests": _phase27e_count(PHASE27E_EXT_REQ_DT),
            "enabled_doctypes": _phase27e_count("Signature DocType Control", {"enabled": 1}) if _phase27e_dt_exists("Signature DocType Control") else 0,
            "registered_employee_signatures": _phase27e_count("Signature Employee Control", {"signature_status": "Registered"}) if _phase27e_dt_exists("Signature Employee Control") else 0,
        },
        "status_counts": {
            "signature_requests": request_status_counts,
            "certificates": cert_status_counts,
            "external_requests": external_status_counts,
            "callbacks": callback_status_counts,
        },
        "routes": {
            "operations_center": "/signature-operations-center",
            "setup_wizard": "/signature-setup-wizard",
            "admin_control": "/signature-admin-control",
            "admin_employee_signatures": "/signature-admin-employee-signatures",
            "signature_requests": "/app/document-signature-request",
            "certificates": "/app/internal-signature-certificate",
            "external_console": "/external-signature-console",
            "workspace": "/app/workspace/surhan-signature",
        },
        "ready": True,
    }

    return summary


@frappe.whitelist()
def phase27e_pending_requests(limit: int = 50):
    _phase27e_require_admin()

    fields = [
        "name",
        "status",
        "reference_doctype",
        "reference_name",
        "signer_user",
        "employee_user",
        "requested_user",
        "full_name",
        "sequence_no",
        "created_at",
        "completed_at",
        "modified",
    ]

    rows = _phase27e_get_many(
        PHASE27E_REQ_DT,
        fields,
        filters=_phase27e_pending_filters(),
        limit=limit,
        order_by="modified desc",
    )

    return {
        "ok": True,
        "phase": "27E",
        "count": len(rows),
        "items": rows,
    }


@frappe.whitelist()
def phase27e_recent_requests(limit: int = 50):
    _phase27e_require_admin()

    fields = [
        "name",
        "status",
        "reference_doctype",
        "reference_name",
        "signer_user",
        "employee_user",
        "requested_user",
        "full_name",
        "sequence_no",
        "completed_at",
        "modified",
    ]

    rows = _phase27e_get_many(
        PHASE27E_REQ_DT,
        fields,
        limit=limit,
        order_by="modified desc",
    )

    return {
        "ok": True,
        "phase": "27E",
        "count": len(rows),
        "items": rows,
    }


@frappe.whitelist()
def phase27e_certificate_overview(limit: int = 50):
    _phase27e_require_admin()

    fields = [
        "name",
        "reference_doctype",
        "reference_name",
        "certificate_status",
        "verification_code",
        "verification_url",
        "signed_pdf",
        "signed_pdf_sha256",
        "modified",
    ]

    rows = _phase27e_get_many(
        PHASE27E_CERT_DT,
        fields,
        limit=limit,
        order_by="modified desc",
    )

    missing_pdf = []

    for r in rows:
        if not r.get("signed_pdf") or not r.get("signed_pdf_sha256"):
            missing_pdf.append(r)

    return {
        "ok": True,
        "phase": "27E",
        "count": len(rows),
        "missing_pdf_count": len(missing_pdf),
        "missing_pdf": missing_pdf,
        "items": rows,
    }


@frappe.whitelist()
def phase27e_external_gateway_overview(limit: int = 50):
    _phase27e_require_admin()

    fields = [
        "name",
        "external_request_id",
        "system_id",
        "status",
        "callback_status",
        "reference_doctype",
        "reference_name",
        "internal_request",
        "verification_url",
        "signed_pdf_sha256",
        "modified",
    ]

    rows = _phase27e_get_many(
        PHASE27E_EXT_REQ_DT,
        fields,
        limit=limit,
        order_by="modified desc",
    )

    return {
        "ok": True,
        "phase": "27E",
        "count": len(rows),
        "items": rows,
    }


@frappe.whitelist()
def phase27e_generate_missing_certificates(limit: int = 20):
    _phase27e_require_admin()

    if not callable(globals().get("generate_internal_signature_certificate")):
        return {
            "ok": False,
            "phase": "27E",
            "error": "generate_internal_signature_certificate is not available.",
        }

    signed_requests = _phase27e_get_many(
        PHASE27E_REQ_DT,
        [
            "name",
            "status",
            "reference_doctype",
            "reference_name",
        ],
        filters={"status": "Signed"} if _phase27e_has_field(PHASE27E_REQ_DT, "status") else {},
        limit=limit,
        order_by="modified desc",
    )

    results = []

    for r in signed_requests:
        reference_doctype = r.get("reference_doctype")
        reference_name = r.get("reference_name")

        if not reference_doctype or not reference_name:
            results.append({
                "request": r.get("name"),
                "ok": False,
                "reason": "Missing reference_doctype or reference_name.",
            })
            continue

        already_has_valid = False

        if _phase27e_dt_exists(PHASE27E_CERT_DT):
            filters = {}

            if _phase27e_has_field(PHASE27E_CERT_DT, "reference_doctype"):
                filters["reference_doctype"] = reference_doctype

            if _phase27e_has_field(PHASE27E_CERT_DT, "reference_name"):
                filters["reference_name"] = reference_name

            if filters:
                certs = frappe.get_all(
                    PHASE27E_CERT_DT,
                    filters=filters,
                    fields=_phase27e_existing_fields(PHASE27E_CERT_DT, ["name", "certificate_status", "signed_pdf", "signed_pdf_sha256"]),
                    limit_page_length=10,
                )

                for c in certs:
                    if c.get("certificate_status") == "Valid" and c.get("signed_pdf") and c.get("signed_pdf_sha256"):
                        already_has_valid = True
                        break

        if already_has_valid:
            results.append({
                "request": r.get("name"),
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "ok": True,
                "action": "already_valid",
            })
            continue

        try:
            generated = generate_internal_signature_certificate(reference_doctype, reference_name)

            results.append({
                "request": r.get("name"),
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "ok": True,
                "action": "generated",
                "result": generated,
            })

        except TypeError:
            try:
                generated = generate_internal_signature_certificate(
                    reference_doctype=reference_doctype,
                    reference_name=reference_name,
                )

                results.append({
                    "request": r.get("name"),
                    "reference_doctype": reference_doctype,
                    "reference_name": reference_name,
                    "ok": True,
                    "action": "generated_keyword",
                    "result": generated,
                })
            except Exception as exc:
                results.append({
                    "request": r.get("name"),
                    "reference_doctype": reference_doctype,
                    "reference_name": reference_name,
                    "ok": False,
                    "error": str(exc),
                })

        except Exception as exc:
            results.append({
                "request": r.get("name"),
                "reference_doctype": reference_doctype,
                "reference_name": reference_name,
                "ok": False,
                "error": str(exc),
            })

    return {
        "ok": True,
        "phase": "27E",
        "checked": len(signed_requests),
        "generated_count": len([r for r in results if r.get("action") in ["generated", "generated_keyword"]]),
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase27e_retry_external_callbacks(limit: int = 20):
    _phase27e_require_admin()

    if not callable(globals().get("phase26j_retry_external_callback")):
        return {
            "ok": False,
            "phase": "27E",
            "error": "phase26j_retry_external_callback is not available.",
        }

    filters = {}

    if _phase27e_has_field(PHASE27E_EXT_REQ_DT, "callback_status"):
        filters["callback_status"] = ["in", ["Failed", "Error", "Not Sent"]]

    rows = _phase27e_get_many(
        PHASE27E_EXT_REQ_DT,
        ["name", "external_request_id", "status", "callback_status"],
        filters=filters,
        limit=limit,
        order_by="modified desc",
    )

    results = []

    for r in rows:
        name = r.get("name")

        try:
            res = phase26j_retry_external_callback(name)

            results.append({
                "external_request": name,
                "ok": True,
                "result": res,
            })

        except TypeError:
            try:
                res = phase26j_retry_external_callback(external_request=name)

                results.append({
                    "external_request": name,
                    "ok": True,
                    "result": res,
                })

            except Exception as exc:
                results.append({
                    "external_request": name,
                    "ok": False,
                    "error": str(exc),
                })

        except Exception as exc:
            results.append({
                "external_request": name,
                "ok": False,
                "error": str(exc),
            })

    return {
        "ok": True,
        "phase": "27E",
        "checked": len(rows),
        "retried_count": len([r for r in results if r.get("ok")]),
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
    }


@frappe.whitelist()
def phase27e_operations_data(cmd=None):
    _phase27e_require_admin()

    return {
        "ok": True,
        "phase": "27E",
        "summary": phase27e_operations_summary(),
        "pending_requests": phase27e_pending_requests(limit=30),
        "recent_requests": phase27e_recent_requests(limit=30),
        "certificates": phase27e_certificate_overview(limit=30),
        "external_gateway": phase27e_external_gateway_overview(limit=30),
        "ready": True,
    }


@frappe.whitelist()
def phase27e_export_operations_snapshot_json():
    _phase27e_require_admin()

    data = phase27e_operations_data()
    sha = _phase27e_sha256(data)
    content = _phase27e_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27e-signature-operations-center-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27E",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "ready": data.get("ready"),
        "counts": (data.get("summary") or {}).get("counts"),
        "routes": (data.get("summary") or {}).get("routes"),
    }


@frappe.whitelist()
def phase27e_operations_center_health():
    data = phase27e_operations_data()
    export = phase27e_export_operations_snapshot_json()

    return {
        "ok": True,
        "phase": "27E",
        "summary": data.get("summary"),
        "export": export,
        "ready": True,
    }


# Phase 27F: Admin Audit Trail with hash chain.
import json as _phase27f_json
import hashlib as _phase27f_hashlib


PHASE27F_AUDIT_DT = "Signature Admin Audit Log"


def _phase27f_json_dumps(data):
    return _phase27f_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27f_sha256(data):
    if not isinstance(data, str):
        data = _phase27f_json_dumps(data)
    return _phase27f_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27f_is_admin_or_auditor():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
    }))


def _phase27f_require_admin_or_auditor():
    if not _phase27f_is_admin_or_auditor():
        frappe.throw("Only Signature Administrators or Auditors can access admin audit logs.")


def _phase27f_require_admin():
    if frappe.session.user == "Administrator":
        return

    roles = set(frappe.get_roles() or [])

    if not roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }):
        frappe.throw("Only Signature Administrators can write admin audit logs.")


def _phase27f_request_context():
    ctx = {
        "ip_address": None,
        "user_agent": None,
        "route": None,
        "request_id": None,
    }

    try:
        req = getattr(frappe.local, "request", None)

        if req:
            ctx["ip_address"] = getattr(req, "remote_addr", None)
            ctx["user_agent"] = req.headers.get("User-Agent")
            ctx["route"] = getattr(req, "path", None)
            ctx["request_id"] = req.headers.get("X-Request-ID") or req.headers.get("X-Frappe-Request-ID")
    except Exception:
        pass

    return ctx


def _phase27f_has_field(dt, fieldname):
    try:
        return bool(frappe.db.exists("DocType", dt) and frappe.get_meta(dt).has_field(fieldname))
    except Exception:
        return False


def _phase27f_set(doc, fieldname, value):
    try:
        if frappe.get_meta(doc.doctype).has_field(fieldname):
            setattr(doc, fieldname, value)
            return True
    except Exception:
        pass

    return False


def _phase27f_admin_permissions():
    perms = []

    for role in ["System Manager", "Internal Signature Administrator", "Internal Signature Manager"]:
        if frappe.db.exists("Role", role):
            perms.append({
                "role": role,
                "read": 1,
                "write": 0,
                "create": 0,
                "delete": 0,
                "export": 1,
                "report": 1,
                "share": 0,
                "print": 1,
                "email": 0,
            })

    if frappe.db.exists("Role", "Internal Signature Auditor"):
        perms.append({
            "role": "Internal Signature Auditor",
            "read": 1,
            "write": 0,
            "create": 0,
            "delete": 0,
            "export": 1,
            "report": 1,
            "share": 0,
            "print": 1,
            "email": 0,
        })

    return perms




def _phase27f_latest_hash():
    if not frappe.db.exists("DocType", PHASE27F_AUDIT_DT):
        return ""

    try:
        rows = frappe.get_all(
            PHASE27F_AUDIT_DT,
            fields=["entry_hash"],
            order_by="creation desc",
            limit_page_length=1,
        )

        return rows[0].get("entry_hash") if rows else ""
    except Exception:
        return ""




def _phase27f_doc_snapshot(dt, name):
    try:
        if dt and name and frappe.db.exists(dt, name):
            doc = frappe.get_doc(dt, name)
            data = doc.as_dict()
            for key in ["doctype", "owner", "creation", "modified", "modified_by", "docstatus", "idx"]:
                data.pop(key, None)
            return data
    except Exception:
        pass

    return {}


def _phase27f_target_from_kwargs(kwargs):
    kwargs = kwargs or {}

    return {
        "target_doctype": kwargs.get("doctype") or kwargs.get("reference_doctype") or kwargs.get("target_doctype"),
        "target_name": kwargs.get("name") or kwargs.get("reference_name") or kwargs.get("target_name") or kwargs.get("employee_user") or kwargs.get("request_name"),
        "reference_doctype": kwargs.get("reference_doctype"),
        "reference_name": kwargs.get("reference_name"),
    }


@frappe.whitelist()
def phase27f_install_admin_audit_trail():
    _phase27f_require_admin()

    install = _phase27f_ensure_audit_doctype()

    audit = phase27f_write_admin_audit(
        action="phase27f.install_admin_audit_trail",
        category="System",
        target_doctype=PHASE27F_AUDIT_DT,
        target_name=PHASE27F_AUDIT_DT,
        payload={"install": install},
        result={"installed": True},
        success=True,
        severity="Info",
    )

    return {
        "ok": True,
        "phase": "27F",
        "install": install,
        "audit": audit,
        "ready": True,
    }


def _phase27f_wrap_function(function_name, action_name, category="Admin"):
    original_name = f"_phase27f_original_{function_name}"

    if globals().get(original_name):
        return False

    original = globals().get(function_name)

    if not callable(original):
        return False

    globals()[original_name] = original

    def wrapper(*args, **kwargs):
        target = _phase27f_target_from_kwargs(kwargs)

        if args and not target.get("target_name"):
            try:
                target["target_name"] = str(args[0])
            except Exception:
                pass

        before = {}

        if target.get("target_doctype") and target.get("target_name"):
            before = _phase27f_doc_snapshot(target.get("target_doctype"), target.get("target_name"))

        payload = {
            "args": [str(a) for a in args],
            "kwargs": kwargs,
        }

        try:
            result = original(*args, **kwargs)

            after = {}

            if target.get("target_doctype") and target.get("target_name"):
                after = _phase27f_doc_snapshot(target.get("target_doctype"), target.get("target_name"))

            audit = phase27f_write_admin_audit(
                action=action_name,
                category=category,
                target_doctype=target.get("target_doctype"),
                target_name=target.get("target_name"),
                reference_doctype=target.get("reference_doctype"),
                reference_name=target.get("reference_name"),
                payload=payload,
                before=before,
                after=after,
                result=result if isinstance(result, dict) else {"result": str(result)},
                success=True,
                severity="Info",
            )

            if isinstance(result, dict):
                result.setdefault("admin_audit", audit)

            return result

        except Exception as exc:
            phase27f_write_admin_audit(
                action=action_name,
                category=category,
                target_doctype=target.get("target_doctype"),
                target_name=target.get("target_name"),
                reference_doctype=target.get("reference_doctype"),
                reference_name=target.get("reference_name"),
                payload=payload,
                before=before,
                after={},
                result={},
                success=False,
                error_message=str(exc),
                severity="Error",
            )
            raise

    wrapper.__name__ = function_name
    wrapper.__doc__ = getattr(original, "__doc__", None)
    globals()[function_name] = frappe.whitelist()(wrapper)

    return True


@frappe.whitelist()
def phase27f_apply_admin_audit_wrappers():
    _phase27f_require_admin()

    _phase27f_ensure_audit_doctype()

    targets = [
        ("phase27a_update_doctype_control", "admin.update_doctype_control", "DocType Control"),
        ("phase27a_apply_doctype_control", "admin.apply_doctype_control", "DocType Control"),
        ("phase27a_apply_all_doctype_controls", "admin.apply_all_doctype_controls", "DocType Control"),
        ("phase27a_refresh_control_center", "admin.refresh_control_center", "Admin Control"),
        ("phase27b_admin_register_employee_signature", "admin.register_employee_signature", "Employee Signature"),
        ("phase27b_apply_employee_control_permissions", "admin.apply_employee_control_permissions", "Employee Permission"),
        ("phase27b_restrict_employee_signature_profile_permissions", "admin.restrict_signature_profile_permissions", "Employee Signature"),
        ("phase27c_apply_doctype_control_client_scripts", "admin.apply_doctype_control_client_scripts", "DocType Control"),
        ("phase27d_run_setup_step", "admin.run_setup_step", "Setup Wizard"),
        ("phase27d_run_full_setup_wizard", "admin.run_full_setup_wizard", "Setup Wizard"),
        ("phase27e_generate_missing_certificates", "operations.generate_missing_certificates", "Operations"),
        ("phase27e_retry_external_callbacks", "operations.retry_external_callbacks", "Operations"),
    ]

    wrapped = []
    missing = []

    for fn, action, category in targets:
        if _phase27f_wrap_function(fn, action, category):
            wrapped.append(fn)
        else:
            if not callable(globals().get(fn)):
                missing.append(fn)

    audit = phase27f_write_admin_audit(
        action="phase27f.apply_admin_audit_wrappers",
        category="System",
        payload={"wrapped": wrapped, "missing": missing},
        result={"wrapped_count": len(wrapped), "missing_count": len(missing)},
        success=True,
    )

    return {
        "ok": True,
        "phase": "27F",
        "wrapped_count": len(wrapped),
        "wrapped": wrapped,
        "missing": missing,
        "audit": audit,
        "ready": True,
    }


@frappe.whitelist()
def phase27f_admin_audit_logs(limit: int = 100, action: str = None, actor: str = None, success=None):
    _phase27f_require_admin_or_auditor()

    if not frappe.db.exists("DocType", PHASE27F_AUDIT_DT):
        _phase27f_ensure_audit_doctype()

    filters = {}

    if action:
        filters["action"] = ["like", f"%{action}%"]

    if actor:
        filters["actor"] = actor

    if success is not None and str(success) != "":
        filters["success"] = 1 if str(success).lower() in {"1", "true", "yes"} else 0

    fields = [
        "name",
        "audit_time",
        "actor",
        "category",
        "action",
        "severity",
        "target_doctype",
        "target_name",
        "success",
        "error_message",
        "previous_hash",
        "entry_hash",
        "creation",
    ]

    rows = frappe.get_all(
        PHASE27F_AUDIT_DT,
        fields=fields,
        filters=filters,
        order_by="creation desc",
        limit_page_length=int(limit or 100),
    )

    return {
        "ok": True,
        "phase": "27F",
        "count": len(rows),
        "items": rows,
        "routes": {
            "admin_audit": "/signature-admin-audit",
            "audit_list": "/app/signature-admin-audit-log",
            "operations_center": "/signature-operations-center",
            "setup_wizard": "/signature-setup-wizard",
            "admin_control": "/signature-admin-control",
        },
    }


@frappe.whitelist()
def phase27f_verify_admin_audit_hash_chain(limit: int = 500):
    _phase27f_require_admin_or_auditor()

    if not frappe.db.exists("DocType", PHASE27F_AUDIT_DT):
        return {
            "ok": False,
            "error": "Audit DocType is not installed.",
        }

    rows = frappe.get_all(
        PHASE27F_AUDIT_DT,
        fields=["name", "previous_hash", "entry_hash", "hash_payload_json", "creation"],
        order_by="creation asc",
        limit_page_length=int(limit or 500),
    )

    issues = []
    previous = ""

    for r in rows:
        expected_previous = previous
        actual_previous = r.get("previous_hash") or ""

        if actual_previous != expected_previous:
            issues.append({
                "name": r.get("name"),
                "issue": "previous_hash_mismatch",
                "expected": expected_previous,
                "actual": actual_previous,
            })

        payload_json = r.get("hash_payload_json") or ""

        try:
            payload = _phase27f_json.loads(payload_json)
            recomputed = _phase27f_sha256(payload)
        except Exception as exc:
            recomputed = None
            issues.append({
                "name": r.get("name"),
                "issue": "invalid_hash_payload_json",
                "error": str(exc),
            })

        if recomputed and recomputed != r.get("entry_hash"):
            issues.append({
                "name": r.get("name"),
                "issue": "entry_hash_mismatch",
                "expected": recomputed,
                "actual": r.get("entry_hash"),
            })

        previous = r.get("entry_hash") or previous

    return {
        "ok": True,
        "phase": "27F",
        "checked": len(rows),
        "issues_count": len(issues),
        "issues": issues,
        "valid": len(issues) == 0,
    }


@frappe.whitelist()
def phase27f_export_admin_audit_snapshot_json():
    _phase27f_require_admin_or_auditor()

    logs = phase27f_admin_audit_logs(limit=200)
    verify = phase27f_verify_admin_audit_hash_chain(limit=1000)

    payload = {
        "logs": logs,
        "verify": verify,
    }

    sha = _phase27f_sha256(payload)
    content = _phase27f_json_dumps(payload).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27f-admin-audit-trail-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27F",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "audit_count": logs.get("count"),
        "hash_chain_valid": verify.get("valid"),
        "routes": logs.get("routes"),
    }


@frappe.whitelist()
def phase27f_admin_audit_health():
    install = phase27f_install_admin_audit_trail()
    wrappers = phase27f_apply_admin_audit_wrappers()
    logs = phase27f_admin_audit_logs(limit=20)
    verify = phase27f_verify_admin_audit_hash_chain(limit=1000)
    export = phase27f_export_admin_audit_snapshot_json()

    return {
        "ok": True,
        "phase": "27F",
        "install": install,
        "wrappers": wrappers,
        "logs_count": logs.get("count"),
        "hash_chain_valid": verify.get("valid"),
        "issues_count": verify.get("issues_count"),
        "export": export,
        "routes": logs.get("routes"),
        "ready": bool(verify.get("valid")),
    }


# Phase 27F-FIX1: fix Signature Admin Audit Log autoname and duplicate literal names.
import time as _phase27f_fix1_time


def _phase27f_fix1_make_audit_name():
    try:
        from frappe.model.naming import make_autoname

        for pattern in [
            "SAAL-.YYYY.-.#####",
            "SAAL-.YY.-.#####",
        ]:
            try:
                name = make_autoname(pattern)

                if name and not frappe.db.exists(PHASE27F_AUDIT_DT, name):
                    return name
            except Exception:
                pass
    except Exception:
        pass

    suffix = _phase27f_sha256({
        "time": str(now_datetime()),
        "user": frappe.session.user,
        "tick": _phase27f_fix1_time.time(),
    })[:10]

    return f"SAAL-{now_datetime().strftime('%Y%m%d-%H%M%S')}-{suffix}"


def _phase27f_fix1_repair_bad_literal_name():
    bad_name = "SAAL-.YYYY.-.#####"

    if not frappe.db.exists("DocType", PHASE27F_AUDIT_DT):
        return {
            "ok": True,
            "repaired": False,
            "reason": "Audit DocType not found.",
        }

    if not frappe.db.exists(PHASE27F_AUDIT_DT, bad_name):
        return {
            "ok": True,
            "repaired": False,
            "reason": "No bad literal audit name found.",
        }

    new_name = _phase27f_fix1_make_audit_name()

    try:
        frappe.rename_doc(
            PHASE27F_AUDIT_DT,
            bad_name,
            new_name,
            force=True,
            ignore_permissions=True,
            merge=False,
        )
        frappe.db.commit()

        return {
            "ok": True,
            "repaired": True,
            "method": "rename_doc",
            "old_name": bad_name,
            "new_name": new_name,
        }

    except Exception as exc:
        try:
            table = "tab" + PHASE27F_AUDIT_DT

            frappe.db.sql(
                f"UPDATE `{table}` SET name=%s WHERE name=%s",
                (new_name, bad_name),
            )
            frappe.db.commit()

            return {
                "ok": True,
                "repaired": True,
                "method": "sql_update",
                "old_name": bad_name,
                "new_name": new_name,
                "rename_error": str(exc),
            }

        except Exception as exc2:
            frappe.db.rollback()

            return {
                "ok": False,
                "repaired": False,
                "old_name": bad_name,
                "attempted_new_name": new_name,
                "rename_error": str(exc),
                "sql_error": str(exc2),
            }


def _phase27f_ensure_audit_doctype():
    """
    FIX1:
    Keep DocType standard, but set autoname to Prompt because the writer now generates names explicitly.
    This prevents Frappe from storing the pattern string as the document name.
    """
    module = "Surhan Signature"

    if not frappe.db.exists("Module Def", module):
        m = frappe.new_doc("Module Def")
        m.module_name = module
        m.app_name = "surhan_signature"
        m.insert(ignore_permissions=True)
        frappe.db.commit()

    fields = [
        {"fieldname": "audit_time", "label": "Audit Time", "fieldtype": "Datetime", "reqd": 1, "in_list_view": 1},
        {"fieldname": "actor", "label": "Actor", "fieldtype": "Link", "options": "User", "in_list_view": 1},
        {"fieldname": "category", "label": "Category", "fieldtype": "Data", "in_list_view": 1},
        {"fieldname": "action", "label": "Action", "fieldtype": "Data", "reqd": 1, "in_list_view": 1},
        {"fieldname": "severity", "label": "Severity", "fieldtype": "Select", "options": "Info\nWarning\nError\nCritical", "default": "Info", "in_list_view": 1},
        {"fieldname": "target_section", "label": "Target", "fieldtype": "Section Break"},
        {"fieldname": "target_doctype", "label": "Target DocType", "fieldtype": "Data", "in_list_view": 1},
        {"fieldname": "target_name", "label": "Target Name", "fieldtype": "Data", "in_list_view": 1},
        {"fieldname": "reference_doctype", "label": "Reference DocType", "fieldtype": "Data"},
        {"fieldname": "reference_name", "label": "Reference Name", "fieldtype": "Data"},
        {"fieldname": "request_section", "label": "Request Context", "fieldtype": "Section Break"},
        {"fieldname": "source_route", "label": "Source Route", "fieldtype": "Data"},
        {"fieldname": "ip_address", "label": "IP Address", "fieldtype": "Data"},
        {"fieldname": "user_agent", "label": "User Agent", "fieldtype": "Small Text"},
        {"fieldname": "request_id", "label": "Request ID", "fieldtype": "Data"},
        {"fieldname": "result_section", "label": "Result", "fieldtype": "Section Break"},
        {"fieldname": "success", "label": "Success", "fieldtype": "Check", "default": 1, "in_list_view": 1},
        {"fieldname": "error_message", "label": "Error Message", "fieldtype": "Small Text"},
        {"fieldname": "payload_json", "label": "Payload JSON", "fieldtype": "Code", "options": "JSON"},
        {"fieldname": "before_json", "label": "Before JSON", "fieldtype": "Code", "options": "JSON"},
        {"fieldname": "after_json", "label": "After JSON", "fieldtype": "Code", "options": "JSON"},
        {"fieldname": "result_json", "label": "Result JSON", "fieldtype": "Code", "options": "JSON"},
        {"fieldname": "hash_section", "label": "Hash Chain", "fieldtype": "Section Break"},
        {"fieldname": "previous_hash", "label": "Previous Hash", "fieldtype": "Data"},
        {"fieldname": "entry_hash", "label": "Entry Hash", "fieldtype": "Data", "in_list_view": 1},
        {"fieldname": "hash_payload_json", "label": "Hash Payload JSON", "fieldtype": "Code", "options": "JSON"},
    ]

    if frappe.db.exists("DocType", PHASE27F_AUDIT_DT):
        doc = frappe.get_doc("DocType", PHASE27F_AUDIT_DT)
        action = "updated"
        doc.module = module
        doc.custom = 0
        doc.is_submittable = 0
        doc.track_changes = 0
        doc.allow_rename = 0
        doc.autoname = "Prompt"

        existing = {df.fieldname for df in doc.fields if df.fieldname}

        for f in fields:
            if f.get("fieldname") not in existing:
                doc.append("fields", f)

        doc.set("permissions", [])

        for p in _phase27f_admin_permissions():
            doc.append("permissions", p)

        doc.save(ignore_permissions=True)

    else:
        doc = frappe.new_doc("DocType")
        doc.name = PHASE27F_AUDIT_DT
        doc.module = module
        doc.custom = 0
        doc.is_submittable = 0
        doc.track_changes = 0
        doc.allow_rename = 0
        doc.autoname = "Prompt"

        for f in fields:
            doc.append("fields", f)

        for p in _phase27f_admin_permissions():
            doc.append("permissions", p)

        doc.insert(ignore_permissions=True)
        action = "created"

    frappe.db.commit()

    try:
        frappe.clear_cache(doctype=PHASE27F_AUDIT_DT)
        frappe.db.updatedb(PHASE27F_AUDIT_DT)
    except Exception:
        pass

    repair = _phase27f_fix1_repair_bad_literal_name()

    return {
        "ok": True,
        "doctype": PHASE27F_AUDIT_DT,
        "action": action,
        "autoname": "Prompt",
        "bad_name_repair": repair,
    }


def phase27f_write_admin_audit(
    action,
    category="Admin",
    target_doctype=None,
    target_name=None,
    reference_doctype=None,
    reference_name=None,
    payload=None,
    before=None,
    after=None,
    result=None,
    success=True,
    error_message=None,
    severity="Info",
):
    """
    FIX1:
    Explicitly generate a unique audit log name before insert.
    """
    try:
        if not frappe.db.exists("DocType", PHASE27F_AUDIT_DT):
            _phase27f_ensure_audit_doctype()

        ctx = _phase27f_request_context()
        previous_hash = _phase27f_latest_hash()

        payload = payload or {}
        before = before or {}
        after = after or {}
        result = result or {}

        audit_time = now_datetime()

        hash_payload = {
            "audit_time": str(audit_time),
            "actor": frappe.session.user,
            "category": category,
            "action": action,
            "target_doctype": target_doctype,
            "target_name": target_name,
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
            "payload": payload,
            "before": before,
            "after": after,
            "result": result,
            "success": bool(success),
            "error_message": error_message,
            "previous_hash": previous_hash,
            "site": frappe.local.site,
        }

        entry_hash = _phase27f_sha256(hash_payload)

        doc = frappe.new_doc(PHASE27F_AUDIT_DT)
        doc.name = _phase27f_fix1_make_audit_name()

        # Double safety
        while frappe.db.exists(PHASE27F_AUDIT_DT, doc.name):
            doc.name = _phase27f_fix1_make_audit_name()

        values = {
            "audit_time": audit_time,
            "actor": frappe.session.user,
            "category": category,
            "action": action,
            "severity": severity or ("Error" if not success else "Info"),
            "target_doctype": target_doctype,
            "target_name": target_name,
            "reference_doctype": reference_doctype,
            "reference_name": reference_name,
            "source_route": ctx.get("route"),
            "ip_address": ctx.get("ip_address"),
            "user_agent": ctx.get("user_agent"),
            "request_id": ctx.get("request_id"),
            "success": 1 if success else 0,
            "error_message": error_message,
            "payload_json": _phase27f_json_dumps(payload),
            "before_json": _phase27f_json_dumps(before),
            "after_json": _phase27f_json_dumps(after),
            "result_json": _phase27f_json_dumps(result),
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
            "hash_payload_json": _phase27f_json_dumps(hash_payload),
        }

        for fieldname, value in values.items():
            _phase27f_set(doc, fieldname, value)

        doc.insert(ignore_permissions=True)
        frappe.db.commit()

        return {
            "ok": True,
            "audit_log": doc.name,
            "entry_hash": entry_hash,
            "previous_hash": previous_hash,
        }

    except Exception as exc:
        try:
            frappe.db.rollback()
        except Exception:
            pass

        return {
            "ok": False,
            "error": str(exc),
        }


@frappe.whitelist()
def phase27f_fix1_health():
    install = phase27f_install_admin_audit_trail()
    wrappers = phase27f_apply_admin_audit_wrappers()

    test_audit = phase27f_write_admin_audit(
        action="phase27f.fix1_test_unique_audit_name",
        category="System",
        payload={"purpose": "verify unique audit naming"},
        result={"unique_name_test": True},
        success=True,
        severity="Info",
    )

    logs = phase27f_admin_audit_logs(limit=20)
    verify = phase27f_verify_admin_audit_hash_chain(limit=1000)
    export = phase27f_export_admin_audit_snapshot_json()

    bad_exists = frappe.db.exists(PHASE27F_AUDIT_DT, "SAAL-.YYYY.-.#####") if frappe.db.exists("DocType", PHASE27F_AUDIT_DT) else None

    return {
        "ok": True,
        "phase_fix": "27F-FIX1",
        "install": install,
        "wrappers": wrappers,
        "test_audit": test_audit,
        "bad_literal_name_exists": bad_exists,
        "logs_count": logs.get("count"),
        "hash_chain_valid": verify.get("valid"),
        "issues_count": verify.get("issues_count"),
        "export": export,
        "routes": logs.get("routes"),
        "ready": bool(
            test_audit.get("ok")
            and verify.get("valid")
            and not bad_exists
        ),
    }


# Phase 27G: Signature Inbox + ERPNext ToDo notifications.
import json as _phase27g_json
import hashlib as _phase27g_hashlib


PHASE27G_REQ_DT = "Document Signature Request"
PHASE27G_TODO_DT = "ToDo"


def _phase27g_json_dumps(data):
    return _phase27g_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27g_sha256(data):
    if not isinstance(data, str):
        data = _phase27g_json_dumps(data)
    return _phase27g_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27g_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase27g_has_dt(dt):
    return bool(frappe.db.exists("DocType", dt))


def _phase27g_has_field(dt, fieldname):
    try:
        return bool(_phase27g_has_dt(dt) and frappe.get_meta(dt).has_field(fieldname))
    except Exception:
        return False


def _phase27g_existing_fields(dt, fields):
    if not _phase27g_has_dt(dt):
        return []

    meta = frappe.get_meta(dt)
    out = []

    for f in fields:
        if f == "name" or meta.has_field(f):
            out.append(f)

    return out


def _phase27g_get_signer_from_row(row):
    for fieldname in [
        "signer_user",
        "employee_user",
        "requested_user",
        "user",
        "assigned_to",
        "allocated_to",
    ]:
        if row.get(fieldname):
            return row.get(fieldname)

    return None


def _phase27g_pending_statuses():
    return ["Pending", "In Progress"]


def _phase27g_active_request_filters(user=None):
    filters = {}

    if _phase27g_has_field(PHASE27G_REQ_DT, "status"):
        filters["status"] = ["in", _phase27g_pending_statuses()]

    if user:
        meta = frappe.get_meta(PHASE27G_REQ_DT)
        or_filters = []

        for fieldname in ["signer_user", "employee_user", "requested_user", "user", "assigned_to", "allocated_to"]:
            if meta.has_field(fieldname):
                or_filters.append([PHASE27G_REQ_DT, fieldname, "=", user])

        return filters, or_filters

    return filters, None


def _phase27g_request_fields():
    return _phase27g_existing_fields(PHASE27G_REQ_DT, [
        "name",
        "status",
        "reference_doctype",
        "reference_name",
        "signer_user",
        "employee_user",
        "requested_user",
        "user",
        "assigned_to",
        "allocated_to",
        "full_name",
        "sequence_no",
        "created_at",
        "completed_at",
        "modified",
    ])


def _phase27g_get_requests(user=None, active_only=True, limit=100):
    if not _phase27g_has_dt(PHASE27G_REQ_DT):
        return []

    fields = _phase27g_request_fields()

    if active_only:
        filters, or_filters = _phase27g_active_request_filters(user=user)
    else:
        filters = {}
        or_filters = None

        if user:
            meta = frappe.get_meta(PHASE27G_REQ_DT)
            or_filters = []

            for fieldname in ["signer_user", "employee_user", "requested_user", "user", "assigned_to", "allocated_to"]:
                if meta.has_field(fieldname):
                    or_filters.append([PHASE27G_REQ_DT, fieldname, "=", user])

    try:
        rows = frappe.get_all(
            PHASE27G_REQ_DT,
            fields=fields,
            filters=filters,
            or_filters=or_filters,
            order_by="modified desc",
            limit_page_length=int(limit or 100),
        )

        for r in rows:
            r["signer"] = _phase27g_get_signer_from_row(r)
            r["action_url"] = f"/document-sign-action?request={r.get('name')}"
            if r.get("reference_doctype") and r.get("reference_name"):
                r["document_url"] = f"/app/{frappe.scrub(r.get('reference_doctype')).replace('_', '-')}/{r.get('reference_name')}"

        return rows

    except Exception as exc:
        return [{
            "error": str(exc),
            "doctype": PHASE27G_REQ_DT,
        }]


def _phase27g_todo_description(row):
    return (
        f"Signature required for {row.get('reference_doctype') or ''} "
        f"{row.get('reference_name') or ''}. "
        f"Open: /document-sign-action?request={row.get('name')}"
    ).strip()


def _phase27g_open_todo_exists(request_name, allocated_to):
    if not _phase27g_has_dt(PHASE27G_TODO_DT):
        return None

    filters = {
        "reference_type": PHASE27G_REQ_DT,
        "reference_name": request_name,
    }

    if _phase27g_has_field(PHASE27G_TODO_DT, "allocated_to"):
        filters["allocated_to"] = allocated_to

    if _phase27g_has_field(PHASE27G_TODO_DT, "status"):
        filters["status"] = ["!=", "Closed"]

    try:
        rows = frappe.get_all(
            PHASE27G_TODO_DT,
            filters=filters,
            pluck="name",
            limit_page_length=1,
        )

        return rows[0] if rows else None

    except Exception:
        return None




def _phase27g_close_todos_for_request(request_name, reason="Signature request completed"):
    if not _phase27g_has_dt(PHASE27G_TODO_DT):
        return []

    filters = {
        "reference_type": PHASE27G_REQ_DT,
        "reference_name": request_name,
    }

    try:
        todos = frappe.get_all(
            PHASE27G_TODO_DT,
            filters=filters,
            fields=_phase27g_existing_fields(PHASE27G_TODO_DT, ["name", "status", "description"]),
            limit_page_length=100,
        )
    except Exception:
        return []

    closed = []

    for t in todos:
        try:
            if t.get("status") == "Closed":
                continue

            doc = frappe.get_doc(PHASE27G_TODO_DT, t.get("name"))

            if _phase27g_has_field(PHASE27G_TODO_DT, "status"):
                doc.status = "Closed"

            if _phase27g_has_field(PHASE27G_TODO_DT, "description"):
                doc.description = (doc.description or "") + f"\n\nClosed automatically: {reason}"

            doc.save(ignore_permissions=True)
            closed.append(doc.name)

        except Exception:
            pass

    frappe.db.commit()

    return closed


@frappe.whitelist()
def phase27g_signature_inbox_data(limit: int = 100, cmd=None):
    user = frappe.session.user

    rows = _phase27g_get_requests(user=user, active_only=False, limit=limit)
    active = [r for r in rows if r.get("status") in _phase27g_pending_statuses()]

    return {
        "ok": True,
        "phase": "27G",
        "user": user,
        "pending_count": len(active),
        "total_count": len(rows),
        "pending": active,
        "recent": rows,
        "routes": {
            "signature_inbox": "/signature-inbox",
            "signature_dashboard": "/signature-dashboard",
            "operations_center": "/signature-operations-center",
            "admin_control": "/signature-admin-control",
        },
        "ready": True,
    }


@frappe.whitelist()
def phase27g_signature_badge_count():
    user = frappe.session.user
    rows = _phase27g_get_requests(user=user, active_only=True, limit=500)

    return {
        "ok": True,
        "phase": "27G",
        "user": user,
        "pending_count": len(rows),
        "ready": True,
    }


@frappe.whitelist()
def phase27g_sync_signature_todos(scope: str = "me", limit: int = 500):
    scope = (scope or "me").strip().lower()

    if scope == "all" and not _phase27g_is_admin():
        frappe.throw("Only administrators can sync ToDos for all users.")

    if scope == "all":
        rows = _phase27g_get_requests(user=None, active_only=True, limit=limit)
    else:
        rows = _phase27g_get_requests(user=frappe.session.user, active_only=True, limit=limit)

    results = []

    for r in rows:
        signer = _phase27g_get_signer_from_row(r)

        if not signer:
            results.append({
                "ok": False,
                "request": r.get("name"),
                "reason": "No signer user found.",
            })
            continue

        try:
            results.append(_phase27g_create_todo_for_request(r, signer))
        except Exception as exc:
            results.append({
                "ok": False,
                "request": r.get("name"),
                "allocated_to": signer,
                "error": str(exc),
            })

    try:
        if callable(globals().get("phase27f_write_admin_audit")) and scope == "all":
            phase27f_write_admin_audit(
                action="notifications.sync_signature_todos",
                category="Notifications",
                payload={"scope": scope, "limit": limit},
                result={"count": len(results)},
                success=True,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27G",
        "scope": scope,
        "checked": len(rows),
        "created_count": len([r for r in results if r.get("action") == "created"]),
        "already_exists_count": len([r for r in results if r.get("action") == "already_exists"]),
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
        "ready": True,
    }




def _phase27g_wrap_action_function(function_name):
    original_name = f"_phase27g_original_{function_name}"

    if globals().get(original_name):
        return False

    original = globals().get(function_name)

    if not callable(original):
        return False

    globals()[original_name] = original

    def wrapper(*args, **kwargs):
        request_name = kwargs.get("request_name") or kwargs.get("request") or None

        if not request_name and args:
            request_name = args[0]

        result = original(*args, **kwargs)

        try:
            if request_name:
                req_status = None

                if frappe.db.exists(PHASE27G_REQ_DT, request_name):
                    req_status = frappe.db.get_value(PHASE27G_REQ_DT, request_name, "status")

                if req_status and req_status not in _phase27g_pending_statuses():
                    closed = _phase27g_close_todos_for_request(
                        request_name,
                        reason=f"Request status is {req_status}",
                    )

                    if isinstance(result, dict):
                        result["closed_signature_todos"] = closed
        except Exception:
            pass

        return result

    wrapper.__name__ = function_name
    wrapper.__doc__ = getattr(original, "__doc__", None)
    globals()[function_name] = frappe.whitelist()(wrapper)

    return True


@frappe.whitelist()
def phase27g_apply_action_wrappers():
    wrapped = []

    for fn in [
        "phase26n_accept_signature_request",
        "phase26n_refuse_signature_request",
        "phase26n_linear_guidance_signature_request",
        "apply_saved_signature_request",
        "reject_document_signature_request",
        "apply_direction_signature_request",
    ]:
        if _phase27g_wrap_action_function(fn):
            wrapped.append(fn)

    return {
        "ok": True,
        "phase": "27G",
        "wrapped": wrapped,
        "wrapped_count": len(wrapped),
        "ready": True,
    }


@frappe.whitelist()
def phase27g_export_signature_inbox_snapshot_json():
    data = phase27g_signature_inbox_data(limit=200)
    badge = phase27g_signature_badge_count()

    payload = {
        "inbox": data,
        "badge": badge,
    }

    sha = _phase27g_sha256(payload)
    content = _phase27g_json_dumps(payload).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27g-signature-inbox-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27G",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "pending_count": badge.get("pending_count"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27g_signature_inbox_health():
    wrappers = phase27g_apply_action_wrappers()

    if _phase27g_is_admin():
        sync = phase27g_sync_signature_todos(scope="all", limit=500)
    else:
        sync = phase27g_sync_signature_todos(scope="me", limit=500)

    close = phase27g_close_completed_signature_todos(limit=1000)
    data = phase27g_signature_inbox_data(limit=200)
    export = phase27g_export_signature_inbox_snapshot_json()

    return {
        "ok": True,
        "phase": "27G",
        "wrappers": wrappers,
        "sync": sync,
        "close": close,
        "pending_count": data.get("pending_count"),
        "total_count": data.get("total_count"),
        "export": export,
        "routes": data.get("routes"),
        "ready": True,
    }


# Phase 27G-FIX1: fix ToDo creation date by using frappe.utils.nowdate safely.
def _phase27g_fix1_today():
    try:
        from frappe.utils import nowdate as _nowdate
        return _nowdate()
    except Exception:
        try:
            return frappe.utils.nowdate()
        except Exception:
            return str(now_datetime()).split(" ")[0]


def _phase27g_create_todo_for_request(row, allocated_to):
    """
    FIX1:
    Use safe nowdate helper instead of undefined nowdate().
    """
    if not _phase27g_has_dt(PHASE27G_TODO_DT):
        return {
            "ok": False,
            "reason": "ToDo DocType does not exist.",
        }

    existing = _phase27g_open_todo_exists(row.get("name"), allocated_to)

    if existing:
        return {
            "ok": True,
            "action": "already_exists",
            "todo": existing,
            "request": row.get("name"),
            "allocated_to": allocated_to,
        }

    todo = frappe.new_doc(PHASE27G_TODO_DT)

    values = {
        "allocated_to": allocated_to,
        "assigned_by": frappe.session.user,
        "reference_type": PHASE27G_REQ_DT,
        "reference_name": row.get("name"),
        "description": _phase27g_todo_description(row),
        "priority": "Medium",
        "status": "Open",
        "date": _phase27g_fix1_today(),
    }

    for fieldname, value in values.items():
        if _phase27g_has_field(PHASE27G_TODO_DT, fieldname):
            setattr(todo, fieldname, value)

    todo.insert(ignore_permissions=True)
    frappe.db.commit()

    return {
        "ok": True,
        "action": "created",
        "todo": todo.name,
        "request": row.get("name"),
        "allocated_to": allocated_to,
    }


@frappe.whitelist()
def phase27g_fix1_sync_todos_health():
    wrappers = phase27g_apply_action_wrappers()

    if _phase27g_is_admin():
        sync = phase27g_sync_signature_todos(scope="all", limit=500)
    else:
        sync = phase27g_sync_signature_todos(scope="me", limit=500)

    close = phase27g_close_completed_signature_todos(limit=1000)
    data = phase27g_signature_inbox_data(limit=200)
    export = phase27g_export_signature_inbox_snapshot_json()

    failed = sync.get("failed") or []

    return {
        "ok": True,
        "phase_fix": "27G-FIX1",
        "wrappers": wrappers,
        "sync": sync,
        "close": close,
        "pending_count": data.get("pending_count"),
        "total_count": data.get("total_count"),
        "export": export,
        "routes": data.get("routes"),
        "ready": len(failed) == 0,
    }


# Phase 27H: automatic signature ToDo notifications via doc_events + scheduler.
import json as _phase27h_json
import hashlib as _phase27h_hashlib


def _phase27h_json_dumps(data):
    return _phase27h_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27h_sha256(data):
    if not isinstance(data, str):
        data = _phase27h_json_dumps(data)
    return _phase27h_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27h_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase27h_require_admin():
    if not _phase27h_is_admin():
        frappe.throw("Only Signature Administrators can manage notification scheduler.")


def _phase27h_todo_counts():
    if not frappe.db.exists("DocType", "ToDo"):
        return {
            "todo_doctype_exists": False,
            "open_signature_todos": 0,
            "closed_signature_todos": 0,
            "total_signature_todos": 0,
        }

    filters_base = {
        "reference_type": "Document Signature Request",
    }

    total = frappe.db.count("ToDo", filters_base)

    open_count = 0
    closed_count = 0

    try:
        open_count = frappe.db.count("ToDo", {
            "reference_type": "Document Signature Request",
            "status": ["!=", "Closed"],
        })
    except Exception:
        pass

    try:
        closed_count = frappe.db.count("ToDo", {
            "reference_type": "Document Signature Request",
            "status": "Closed",
        })
    except Exception:
        pass

    return {
        "todo_doctype_exists": True,
        "open_signature_todos": int(open_count or 0),
        "closed_signature_todos": int(closed_count or 0),
        "total_signature_todos": int(total or 0),
    }






def _phase27h_run_as_administrator(fn, *args, **kwargs):
    previous_user = getattr(frappe.session, "user", None)

    try:
        frappe.set_user("Administrator")
        return fn(*args, **kwargs)

    finally:
        try:
            if previous_user:
                frappe.set_user(previous_user)
        except Exception:
            pass


def phase27h_scheduled_signature_notifications():
    """
    Scheduler entrypoint. Runs hourly.
    """
    def _run():
        phase27g_apply_action_wrappers()
        sync = phase27g_sync_signature_todos(scope="all", limit=1000)
        close = phase27g_close_completed_signature_todos(limit=1000)

        result = {
            "ok": True,
            "phase": "27H",
            "source": "scheduler",
            "sync": sync,
            "close": close,
            "todo_counts": _phase27h_todo_counts(),
            "request_counts": _phase27h_request_counts(),
            "ready": True,
        }

        try:
            if callable(globals().get("phase27f_write_admin_audit")):
                phase27f_write_admin_audit(
                    action="notifications.scheduler_sync",
                    category="Notifications",
                    payload={"source": "scheduler"},
                    result=result,
                    success=True,
                )
        except Exception:
            pass

        return result

    return _phase27h_run_as_administrator(_run)


@frappe.whitelist()
def phase27h_run_notifications_now():
    _phase27h_require_admin()

    result = phase27h_scheduled_signature_notifications()

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            phase27f_write_admin_audit(
                action="notifications.manual_run",
                category="Notifications",
                payload={"source": "manual"},
                result=result,
                success=True,
            )
    except Exception:
        pass

    return result


@frappe.whitelist()
def phase27h_notifications_center_data():
    _phase27h_require_admin()

    data = {
        "ok": True,
        "phase": "27H",
        "generated_at": str(now_datetime()),
        "todo_counts": _phase27h_todo_counts(),
        "request_counts": _phase27h_request_counts(),
        "inbox": phase27g_signature_inbox_data(limit=100),
        "routes": {
            "notifications_center": "/signature-notifications-center",
            "signature_inbox": "/signature-inbox",
            "todo_list": "/app/todo",
            "operations_center": "/signature-operations-center",
            "admin_audit": "/signature-admin-audit",
            "admin_control": "/signature-admin-control",
        },
        "ready": True,
    }

    return data


@frappe.whitelist()
def phase27h_export_notifications_snapshot_json():
    _phase27h_require_admin()

    data = phase27h_notifications_center_data()
    sha = _phase27h_sha256(data)
    content = _phase27h_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27h-signature-notifications-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27H",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "todo_counts": data.get("todo_counts"),
        "request_counts": data.get("request_counts"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27h_notifications_scheduler_health():
    _phase27h_require_admin()

    run = phase27h_run_notifications_now()
    data = phase27h_notifications_center_data()
    export = phase27h_export_notifications_snapshot_json()

    return {
        "ok": True,
        "phase": "27H",
        "run": run,
        "data": data,
        "export": export,
        "ready": True,
    }


# Phase 27H-FIX1: treat Directed as completed for ToDo closure and notification counts.

def _phase27h_completed_statuses():
    return [
        "Signed",
        "Rejected",
        "Returned",
        "Cancelled",
        "Completed",
        "Directed",
        "Direction",
        "Direction Written",
    ]


def phase27h_on_signature_request_update(doc, method=None):
    """
    FIX1:
    Close ToDo also when request status becomes Directed.
    """
    try:
        if not doc or getattr(doc, "doctype", None) != "Document Signature Request":
            return

        row = doc.as_dict()
        status = row.get("status")

        if status in ["Pending", "In Progress"]:
            signer = _phase27g_get_signer_from_row(row)

            if signer:
                _phase27g_create_todo_for_request(row, signer)

        elif status in _phase27h_completed_statuses():
            _phase27g_close_todos_for_request(
                row.get("name"),
                reason=f"Request status is {status}",
            )

    except Exception as exc:
        try:
            if callable(globals().get("phase27f_write_admin_audit")):
                phase27f_write_admin_audit(
                    action="notifications.doc_event_sync_failed",
                    category="Notifications",
                    target_doctype="Document Signature Request",
                    target_name=getattr(doc, "name", None),
                    payload={"method": method},
                    result={},
                    success=False,
                    error_message=str(exc),
                    severity="Error",
                )
        except Exception:
            pass


@frappe.whitelist()
def phase27g_close_completed_signature_todos(limit: int = 1000):
    """
    FIX1:
    Include Directed and direction-related statuses as completed/non-pending.
    """
    if not _phase27g_has_dt(PHASE27G_REQ_DT):
        return {
            "ok": False,
            "reason": "Document Signature Request not installed.",
        }

    fields = _phase27g_request_fields()

    filters = {}

    if _phase27g_has_field(PHASE27G_REQ_DT, "status"):
        filters["status"] = ["in", _phase27h_completed_statuses()]

    rows = frappe.get_all(
        PHASE27G_REQ_DT,
        fields=fields,
        filters=filters,
        order_by="modified desc",
        limit_page_length=int(limit or 1000),
    )

    results = []

    for r in rows:
        closed = _phase27g_close_todos_for_request(
            r.get("name"),
            reason=f"Request status is {r.get('status')}",
        )

        if closed:
            results.append({
                "request": r.get("name"),
                "status": r.get("status"),
                "closed_todos": closed,
            })

    try:
        if callable(globals().get("phase27f_write_admin_audit")) and _phase27g_is_admin():
            phase27f_write_admin_audit(
                action="notifications.close_completed_signature_todos",
                category="Notifications",
                payload={"limit": limit, "completed_statuses": _phase27h_completed_statuses()},
                result={"closed_requests": len(results)},
                success=True,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27G",
        "checked": len(rows),
        "closed_request_count": len(results),
        "results": results,
        "ready": True,
    }


def _phase27h_request_counts():
    """
    FIX1:
    Count Directed as completed, not orphan/unclassified.
    """
    if not frappe.db.exists("DocType", "Document Signature Request"):
        return {
            "request_doctype_exists": False,
            "pending_requests": 0,
            "completed_requests": 0,
            "total_requests": 0,
        }

    status_counts = {}

    try:
        rows = frappe.db.sql(
            """
            SELECT status, COUNT(name) AS count_value
            FROM `tabDocument Signature Request`
            GROUP BY status
            """,
            as_dict=True,
        )

        status_counts = {
            r.get("status") or "Blank": int(r.get("count_value") or 0)
            for r in rows
        }
    except Exception:
        status_counts = {}

    pending = sum(status_counts.get(s, 0) for s in ["Pending", "In Progress", "Waiting"])
    completed = sum(status_counts.get(s, 0) for s in _phase27h_completed_statuses())

    return {
        "request_doctype_exists": True,
        "pending_requests": pending,
        "completed_requests": completed,
        "total_requests": sum(status_counts.values()),
        "status_counts": status_counts,
    }


@frappe.whitelist()
def phase27h_fix1_directed_todo_close_health():
    _phase27h_require_admin()

    run = phase27h_run_notifications_now()
    close = phase27g_close_completed_signature_todos(limit=1000)
    data = phase27h_notifications_center_data()
    export = phase27h_export_notifications_snapshot_json()

    todo_counts = data.get("todo_counts") or {}
    request_counts = data.get("request_counts") or {}

    return {
        "ok": True,
        "phase_fix": "27H-FIX1",
        "run": run,
        "close": close,
        "todo_counts": todo_counts,
        "request_counts": request_counts,
        "export": export,
        "routes": data.get("routes"),
        "ready": bool(
            int(todo_counts.get("open_signature_todos") or 0)
            == int(request_counts.get("pending_requests") or 0)
        ),
    }


# Phase 27I: Signature Delegation and Reassignment Center.
import json as _phase27i_json
import hashlib as _phase27i_hashlib


PHASE27I_DELEGATION_DT = "Signature Delegation Rule"
PHASE27I_REQ_DT = "Document Signature Request"


def _phase27i_json_dumps(data):
    return _phase27i_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27i_sha256(data):
    if not isinstance(data, str):
        data = _phase27i_json_dumps(data)
    return _phase27i_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27i_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection({
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }))


def _phase27i_require_admin():
    if not _phase27i_is_admin():
        frappe.throw("Only Signature Administrators can manage signature delegation.")


def _phase27i_has_dt(dt):
    return bool(frappe.db.exists("DocType", dt))


def _phase27i_has_field(dt, fieldname):
    try:
        return bool(_phase27i_has_dt(dt) and frappe.get_meta(dt).has_field(fieldname))
    except Exception:
        return False


def _phase27i_existing_fields(dt, fields):
    if not _phase27i_has_dt(dt):
        return []

    meta = frappe.get_meta(dt)
    out = []

    for f in fields:
        if f == "name" or meta.has_field(f):
            out.append(f)

    return out


def _phase27i_make_name(prefix="SDR"):
    try:
        from frappe.model.naming import make_autoname
        name = make_autoname(f"{prefix}-.YYYY.-.#####")

        if name:
            return name
    except Exception:
        pass

    return f"{prefix}-{_phase27i_sha256({'now': str(now_datetime()), 'user': frappe.session.user})[:12]}"


def _phase27i_permissions():
    perms = []

    for role in ["System Manager", "Internal Signature Administrator", "Internal Signature Manager"]:
        if frappe.db.exists("Role", role):
            perms.append({
                "role": role,
                "read": 1,
                "write": 1,
                "create": 1,
                "delete": 1,
                "export": 1,
                "report": 1,
                "share": 0,
                "print": 1,
                "email": 0,
            })

    if frappe.db.exists("Role", "Internal Signature Auditor"):
        perms.append({
            "role": "Internal Signature Auditor",
            "read": 1,
            "write": 0,
            "create": 0,
            "delete": 0,
            "export": 1,
            "report": 1,
            "share": 0,
            "print": 1,
            "email": 0,
        })

    return perms


def _phase27i_ensure_delegation_doctype():
    module = "Surhan Signature"

    if not frappe.db.exists("Module Def", module):
        m = frappe.new_doc("Module Def")
        m.module_name = module
        m.app_name = "surhan_signature"
        m.insert(ignore_permissions=True)
        frappe.db.commit()

    fields = [
        {"fieldname": "enabled", "label": "Enabled", "fieldtype": "Check", "default": 1, "in_list_view": 1},
        {"fieldname": "delegator_user", "label": "Delegator User", "fieldtype": "Link", "options": "User", "reqd": 1, "in_list_view": 1},
        {"fieldname": "delegate_user", "label": "Delegate User", "fieldtype": "Link", "options": "User", "reqd": 1, "in_list_view": 1},
        {"fieldname": "date_section", "label": "Validity", "fieldtype": "Section Break"},
        {"fieldname": "from_date", "label": "From Date", "fieldtype": "Date", "reqd": 1, "in_list_view": 1},
        {"fieldname": "to_date", "label": "To Date", "fieldtype": "Date", "reqd": 1, "in_list_view": 1},
        {"fieldname": "scope_section", "label": "Scope", "fieldtype": "Section Break"},
        {"fieldname": "applies_to_doctype", "label": "Applies To DocType", "fieldtype": "Link", "options": "DocType", "description": "Leave blank to apply to all signature-enabled DocTypes.", "in_list_view": 1},
        {"fieldname": "reason", "label": "Reason", "fieldtype": "Small Text"},
        {"fieldname": "audit_section", "label": "Audit", "fieldtype": "Section Break"},
        {"fieldname": "created_by_user", "label": "Created By User", "fieldtype": "Link", "options": "User"},
        {"fieldname": "last_applied_at", "label": "Last Applied At", "fieldtype": "Datetime"},
        {"fieldname": "last_result_json", "label": "Last Result JSON", "fieldtype": "Code", "options": "JSON"},
    ]

    if frappe.db.exists("DocType", PHASE27I_DELEGATION_DT):
        doc = frappe.get_doc("DocType", PHASE27I_DELEGATION_DT)
        action = "updated"

        doc.module = module
        doc.custom = 0
        doc.is_submittable = 0
        doc.track_changes = 1
        doc.allow_rename = 0
        doc.autoname = "Prompt"

        existing = {df.fieldname for df in doc.fields if df.fieldname}

        for f in fields:
            if f.get("fieldname") not in existing:
                doc.append("fields", f)

        doc.set("permissions", [])

        for p in _phase27i_permissions():
            doc.append("permissions", p)

        doc.save(ignore_permissions=True)

    else:
        doc = frappe.new_doc("DocType")
        doc.name = PHASE27I_DELEGATION_DT
        doc.module = module
        doc.custom = 0
        doc.is_submittable = 0
        doc.track_changes = 1
        doc.allow_rename = 0
        doc.autoname = "Prompt"

        for f in fields:
            doc.append("fields", f)

        for p in _phase27i_permissions():
            doc.append("permissions", p)

        doc.insert(ignore_permissions=True)
        action = "created"

    frappe.db.commit()

    try:
        frappe.clear_cache(doctype=PHASE27I_DELEGATION_DT)
        frappe.db.updatedb(PHASE27I_DELEGATION_DT)
    except Exception:
        pass

    return {
        "ok": True,
        "doctype": PHASE27I_DELEGATION_DT,
        "action": action,
    }


def _phase27i_ensure_request_custom_fields():
    if not frappe.db.exists("DocType", PHASE27I_REQ_DT):
        return {
            "ok": False,
            "reason": "Document Signature Request DocType not found.",
        }

    fields = [
        {
            "fieldname": "delegation_section",
            "label": "Delegation",
            "fieldtype": "Section Break",
            "insert_after": "completed_at",
        },
        {
            "fieldname": "delegated_from",
            "label": "Delegated From",
            "fieldtype": "Link",
            "options": "User",
            "insert_after": "delegation_section",
        },
        {
            "fieldname": "delegated_to",
            "label": "Delegated To",
            "fieldtype": "Link",
            "options": "User",
            "insert_after": "delegated_from",
        },
        {
            "fieldname": "delegated_by",
            "label": "Delegated By",
            "fieldtype": "Link",
            "options": "User",
            "insert_after": "delegated_to",
        },
        {
            "fieldname": "delegated_at",
            "label": "Delegated At",
            "fieldtype": "Datetime",
            "insert_after": "delegated_by",
        },
        {
            "fieldname": "delegation_rule",
            "label": "Delegation Rule",
            "fieldtype": "Data",
            "insert_after": "delegated_at",
        },
        {
            "fieldname": "delegation_reason",
            "label": "Delegation Reason",
            "fieldtype": "Small Text",
            "insert_after": "delegation_rule",
        },
    ]

    created = []
    existing = []

    for f in fields:
        cf_name = f"{PHASE27I_REQ_DT}-{f['fieldname']}"

        if frappe.db.exists("Custom Field", cf_name):
            existing.append(cf_name)
            continue

        cf = frappe.new_doc("Custom Field")
        cf.dt = PHASE27I_REQ_DT
        cf.fieldname = f["fieldname"]
        cf.label = f["label"]
        cf.fieldtype = f["fieldtype"]
        cf.insert_after = f.get("insert_after")

        if f.get("options"):
            cf.options = f.get("options")

        cf.insert(ignore_permissions=True)
        created.append(cf.name)

    frappe.db.commit()
    frappe.clear_cache(doctype=PHASE27I_REQ_DT)

    return {
        "ok": True,
        "created": created,
        "existing": existing,
    }


@frappe.whitelist()
def phase27i_install_delegation_center():
    _phase27i_require_admin()

    delegation_dt = _phase27i_ensure_delegation_doctype()
    request_fields = _phase27i_ensure_request_custom_fields()

    audit = None

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            audit = phase27f_write_admin_audit(
                action="delegation.install_center",
                category="Delegation",
                payload={},
                result={
                    "delegation_dt": delegation_dt,
                    "request_fields": request_fields,
                },
                success=True,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27I",
        "delegation_dt": delegation_dt,
        "request_fields": request_fields,
        "audit": audit,
        "routes": {
            "delegation_center": "/signature-delegation-center",
            "delegation_list": "/app/signature-delegation-rule",
            "signature_inbox": "/signature-inbox",
            "notifications_center": "/signature-notifications-center",
            "admin_audit": "/signature-admin-audit",
        },
        "ready": True,
    }


def _phase27i_today():
    try:
        from frappe.utils import getdate, nowdate
        return getdate(nowdate())
    except Exception:
        return now_datetime().date()


def _phase27i_date(value):
    try:
        from frappe.utils import getdate
        return getdate(value)
    except Exception:
        return value


def _phase27i_rule_applies(rule, signer_user, reference_doctype):
    if not rule.get("enabled"):
        return False

    if rule.get("delegator_user") != signer_user:
        return False

    if rule.get("delegate_user") == signer_user:
        return False

    today = _phase27i_today()
    from_date = _phase27i_date(rule.get("from_date"))
    to_date = _phase27i_date(rule.get("to_date"))

    if from_date and today < from_date:
        return False

    if to_date and today > to_date:
        return False

    applies_to_doctype = rule.get("applies_to_doctype")

    if applies_to_doctype and reference_doctype and applies_to_doctype != reference_doctype:
        return False

    return True


def _phase27i_get_rules():
    if not frappe.db.exists("DocType", PHASE27I_DELEGATION_DT):
        return []

    fields = _phase27i_existing_fields(PHASE27I_DELEGATION_DT, [
        "name",
        "enabled",
        "delegator_user",
        "delegate_user",
        "from_date",
        "to_date",
        "applies_to_doctype",
        "reason",
        "last_applied_at",
        "modified",
    ])

    try:
        return frappe.get_all(
            PHASE27I_DELEGATION_DT,
            fields=fields,
            order_by="modified desc",
            limit_page_length=500,
        )
    except Exception:
        return []


def _phase27i_pending_requests(limit=1000):
    if not frappe.db.exists("DocType", PHASE27I_REQ_DT):
        return []

    fields = _phase27i_existing_fields(PHASE27I_REQ_DT, [
        "name",
        "status",
        "reference_doctype",
        "reference_name",
        "requested_user",
        "signer_user",
        "employee_user",
        "user",
        "assigned_to",
        "allocated_to",
        "full_name",
        "delegated_from",
        "delegated_to",
        "delegation_rule",
        "modified",
    ])

    filters = {}

    if _phase27i_has_field(PHASE27I_REQ_DT, "status"):
        filters["status"] = ["in", ["Pending", "In Progress", "Waiting"]]

    try:
        rows = frappe.get_all(
            PHASE27I_REQ_DT,
            fields=fields,
            filters=filters,
            order_by="modified desc",
            limit_page_length=int(limit or 1000),
        )

        for r in rows:
            try:
                r["signer"] = _phase27g_get_signer_from_row(r)
            except Exception:
                r["signer"] = r.get("requested_user") or r.get("signer_user") or r.get("employee_user")

        return rows

    except Exception as exc:
        return [{
            "error": str(exc),
        }]


def _phase27i_user_full_name(user):
    try:
        return frappe.db.get_value("User", user, "full_name") or user
    except Exception:
        return user


@frappe.whitelist()
def phase27i_create_delegation_rule(
    delegator_user: str,
    delegate_user: str,
    from_date: str,
    to_date: str,
    applies_to_doctype: str = None,
    reason: str = None,
    enabled: int = 1,
):
    _phase27i_require_admin()

    if not frappe.db.exists("DocType", PHASE27I_DELEGATION_DT):
        _phase27i_ensure_delegation_doctype()

    if not delegator_user or not delegate_user:
        frappe.throw("Delegator User and Delegate User are required.")

    if delegator_user == delegate_user:
        frappe.throw("Delegate User cannot be the same as Delegator User.")

    if not frappe.db.exists("User", delegator_user):
        frappe.throw(f"Delegator User not found: {delegator_user}")

    if not frappe.db.exists("User", delegate_user):
        frappe.throw(f"Delegate User not found: {delegate_user}")

    doc = frappe.new_doc(PHASE27I_DELEGATION_DT)
    doc.name = _phase27i_make_name("SDR")
    doc.enabled = 1 if int(enabled or 0) else 0
    doc.delegator_user = delegator_user
    doc.delegate_user = delegate_user
    doc.from_date = from_date
    doc.to_date = to_date
    doc.applies_to_doctype = applies_to_doctype or None
    doc.reason = reason or ""
    doc.created_by_user = frappe.session.user

    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    audit = None

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            audit = phase27f_write_admin_audit(
                action="delegation.create_rule",
                category="Delegation",
                target_doctype=PHASE27I_DELEGATION_DT,
                target_name=doc.name,
                payload={
                    "delegator_user": delegator_user,
                    "delegate_user": delegate_user,
                    "from_date": from_date,
                    "to_date": to_date,
                    "applies_to_doctype": applies_to_doctype,
                    "reason": reason,
                    "enabled": enabled,
                },
                result={"rule": doc.name},
                success=True,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27I",
        "rule": doc.name,
        "audit": audit,
        "ready": True,
    }


@frappe.whitelist()
def phase27i_reassign_signature_request(request_name: str, delegate_user: str, reason: str = None, delegation_rule: str = None):
    _phase27i_require_admin()

    if not frappe.db.exists(PHASE27I_REQ_DT, request_name):
        frappe.throw(f"Signature request not found: {request_name}")

    if not frappe.db.exists("User", delegate_user):
        frappe.throw(f"Delegate User not found: {delegate_user}")

    doc = frappe.get_doc(PHASE27I_REQ_DT, request_name)
    before = doc.as_dict()

    status = getattr(doc, "status", None)

    if status not in ["Pending", "In Progress", "Waiting"]:
        frappe.throw(f"Only pending signature requests can be reassigned. Current status: {status}")

    old_signer = None

    try:
        old_signer = _phase27g_get_signer_from_row(before)
    except Exception:
        old_signer = None

    old_signer = old_signer or getattr(doc, "requested_user", None) or getattr(doc, "signer_user", None)

    if old_signer == delegate_user:
        return {
            "ok": True,
            "phase": "27I",
            "request": request_name,
            "action": "already_assigned",
            "delegate_user": delegate_user,
            "ready": True,
        }

    meta = frappe.get_meta(PHASE27I_REQ_DT)

    for fieldname in ["delegated_from", "delegated_to", "delegated_by", "delegated_at", "delegation_rule", "delegation_reason"]:
        if not meta.has_field(fieldname):
            continue

        if fieldname == "delegated_from":
            setattr(doc, fieldname, old_signer)
        elif fieldname == "delegated_to":
            setattr(doc, fieldname, delegate_user)
        elif fieldname == "delegated_by":
            setattr(doc, fieldname, frappe.session.user)
        elif fieldname == "delegated_at":
            setattr(doc, fieldname, now_datetime())
        elif fieldname == "delegation_rule":
            setattr(doc, fieldname, delegation_rule or "")
        elif fieldname == "delegation_reason":
            setattr(doc, fieldname, reason or "")

    for fieldname in ["requested_user", "signer_user", "employee_user", "user", "assigned_to", "allocated_to"]:
        if meta.has_field(fieldname):
            current_value = getattr(doc, fieldname, None)
            if current_value == old_signer or fieldname in ["requested_user", "signer_user"]:
                setattr(doc, fieldname, delegate_user)

    if meta.has_field("full_name"):
        doc.full_name = _phase27i_user_full_name(delegate_user)

    doc.save(ignore_permissions=True)
    frappe.db.commit()

    after = doc.as_dict()

    closed_todos = []

    try:
        closed_todos = _phase27g_close_todos_for_request(request_name, reason=f"Request delegated to {delegate_user}")
    except Exception:
        closed_todos = []

    created_todo = None

    try:
        row = doc.as_dict()
        row["signer"] = delegate_user
        created_todo = _phase27g_create_todo_for_request(row, delegate_user)
    except Exception as exc:
        created_todo = {
            "ok": False,
            "error": str(exc),
        }

    audit = None

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            audit = phase27f_write_admin_audit(
                action="delegation.reassign_signature_request",
                category="Delegation",
                target_doctype=PHASE27I_REQ_DT,
                target_name=request_name,
                reference_doctype=getattr(doc, "reference_doctype", None),
                reference_name=getattr(doc, "reference_name", None),
                payload={
                    "request_name": request_name,
                    "old_signer": old_signer,
                    "delegate_user": delegate_user,
                    "reason": reason,
                    "delegation_rule": delegation_rule,
                },
                before=before,
                after=after,
                result={
                    "closed_todos": closed_todos,
                    "created_todo": created_todo,
                },
                success=True,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27I",
        "request": request_name,
        "old_signer": old_signer,
        "delegate_user": delegate_user,
        "closed_todos": closed_todos,
        "created_todo": created_todo,
        "audit": audit,
        "ready": bool(created_todo and created_todo.get("ok")),
    }


@frappe.whitelist()
def phase27i_apply_active_delegations(limit: int = 1000):
    _phase27i_require_admin()

    if not frappe.db.exists("DocType", PHASE27I_DELEGATION_DT):
        _phase27i_ensure_delegation_doctype()

    rules = _phase27i_get_rules()
    pending = _phase27i_pending_requests(limit=limit)

    results = []

    for req in pending:
        if req.get("error"):
            continue

        signer = req.get("signer")
        reference_doctype = req.get("reference_doctype")

        if not signer:
            continue

        for rule in rules:
            if not _phase27i_rule_applies(rule, signer, reference_doctype):
                continue

            try:
                res = phase27i_reassign_signature_request(
                    request_name=req.get("name"),
                    delegate_user=rule.get("delegate_user"),
                    reason=rule.get("reason") or "Applied by active delegation rule.",
                    delegation_rule=rule.get("name"),
                )

                results.append(res)

                try:
                    d = frappe.get_doc(PHASE27I_DELEGATION_DT, rule.get("name"))
                    if _phase27i_has_field(PHASE27I_DELEGATION_DT, "last_applied_at"):
                        d.last_applied_at = now_datetime()
                    if _phase27i_has_field(PHASE27I_DELEGATION_DT, "last_result_json"):
                        d.last_result_json = _phase27i_json_dumps(res)
                    d.save(ignore_permissions=True)
                    frappe.db.commit()
                except Exception:
                    pass

            except Exception as exc:
                results.append({
                    "ok": False,
                    "request": req.get("name"),
                    "rule": rule.get("name"),
                    "error": str(exc),
                })

            break

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            phase27f_write_admin_audit(
                action="delegation.apply_active_delegations",
                category="Delegation",
                payload={"limit": limit},
                result={
                    "checked_requests": len(pending),
                    "rules": len(rules),
                    "results": results,
                },
                success=True,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27I",
        "checked_requests": len(pending),
        "rules": len(rules),
        "applied_count": len([r for r in results if r.get("ok") and r.get("action") != "already_assigned"]),
        "failed": [r for r in results if not r.get("ok")],
        "results": results,
        "ready": True,
    }


def phase27i_scheduled_apply_delegations():
    def _run():
        try:
            return phase27i_apply_active_delegations(limit=1000)
        except Exception as exc:
            try:
                if callable(globals().get("phase27f_write_admin_audit")):
                    phase27f_write_admin_audit(
                        action="delegation.scheduler_failed",
                        category="Delegation",
                        payload={},
                        result={},
                        success=False,
                        error_message=str(exc),
                        severity="Error",
                    )
            except Exception:
                pass

            return {
                "ok": False,
                "phase": "27I",
                "error": str(exc),
            }

    previous_user = getattr(frappe.session, "user", None)

    try:
        frappe.set_user("Administrator")
        return _run()
    finally:
        try:
            if previous_user:
                frappe.set_user(previous_user)
        except Exception:
            pass


@frappe.whitelist()
def phase27i_delegation_center_data():
    _phase27i_require_admin()

    rules = _phase27i_get_rules()
    pending = _phase27i_pending_requests(limit=200)

    active_rules = []

    for r in rules:
        if r.get("enabled"):
            active_rules.append(r)

    data = {
        "ok": True,
        "phase": "27I",
        "generated_at": str(now_datetime()),
        "rules_count": len(rules),
        "active_rules_count": len(active_rules),
        "pending_requests_count": len([r for r in pending if not r.get("error")]),
        "rules": rules,
        "pending_requests": pending,
        "routes": {
            "delegation_center": "/signature-delegation-center",
            "delegation_list": "/app/signature-delegation-rule",
            "signature_inbox": "/signature-inbox",
            "notifications_center": "/signature-notifications-center",
            "operations_center": "/signature-operations-center",
            "admin_audit": "/signature-admin-audit",
            "admin_control": "/signature-admin-control",
        },
        "ready": True,
    }

    return data


@frappe.whitelist()
def phase27i_export_delegation_snapshot_json():
    _phase27i_require_admin()

    data = phase27i_delegation_center_data()
    sha = _phase27i_sha256(data)
    content = _phase27i_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27i-signature-delegation-center-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27I",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "rules_count": data.get("rules_count"),
        "active_rules_count": data.get("active_rules_count"),
        "pending_requests_count": data.get("pending_requests_count"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27i_delegation_center_health():
    install = phase27i_install_delegation_center()
    data = phase27i_delegation_center_data()
    apply_result = phase27i_apply_active_delegations(limit=1000)
    export = phase27i_export_delegation_snapshot_json()

    return {
        "ok": True,
        "phase": "27I",
        "install": install,
        "data": data,
        "apply_result": apply_result,
        "export": export,
        "ready": True,
    }


# Phase 27J: Page Access Hardening.
import json as _phase27j_json
import hashlib as _phase27j_hashlib
from pathlib import Path as _phase27j_Path


def _phase27j_json_dumps(data):
    return _phase27j_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27j_sha256(data):
    if not isinstance(data, str):
        data = _phase27j_json_dumps(data)
    return _phase27j_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27j_admin_roles():
    return [
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    ]


def _phase27j_auditor_roles():
    return [
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
    ]


def _phase27j_is_admin():
    if frappe.session.user == "Administrator":
        return True
    roles = set(frappe.get_roles() or [])
    return bool(roles.intersection(set(_phase27j_admin_roles())))


def _phase27j_require_admin():
    if not _phase27j_is_admin():
        frappe.throw("Only Signature Administrators can apply page access hardening.")


def _phase27j_page_matrix():
    return [
        {
            "route": "signature-admin-control",
            "title": "Admin Control Center",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "signature-admin-employee-signatures",
            "title": "Admin Employee Signatures",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "signature-setup-wizard",
            "title": "Setup Wizard",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "signature-operations-center",
            "title": "Operations Center",
            "mode": "auditor",
            "allowed_roles": _phase27j_auditor_roles(),
        },
        {
            "route": "signature-admin-audit",
            "title": "Admin Audit",
            "mode": "auditor",
            "allowed_roles": _phase27j_auditor_roles(),
        },
        {
            "route": "signature-notifications-center",
            "title": "Notifications Center",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "signature-delegation-center",
            "title": "Delegation Center",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "external-signature-console",
            "title": "External Gateway Console",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "signature-production-readiness",
            "title": "Production Readiness",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "internal-signature-rollout",
            "title": "Internal Signature Rollout",
            "mode": "admin",
            "allowed_roles": _phase27j_admin_roles(),
        },
        {
            "route": "signature-inbox",
            "title": "Signature Inbox",
            "mode": "authenticated",
            "allowed_roles": ["All authenticated users"],
        },
    ]


def _phase27j_page_guard_py(route, title, mode, allowed_roles):
    roles_json = _phase27j_json.dumps(allowed_roles, ensure_ascii=False)

    if mode == "authenticated":
        check_code = """
    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/{route}"
        raise frappe.Redirect
""".replace("{route}", route)

    else:
        check_code = """
    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/login?redirect-to=/{route}"
        raise frappe.Redirect

    if frappe.session.user != "Administrator":
        user_roles = set(frappe.get_roles() or [])
        allowed_roles = set({roles_json})
        if not user_roles.intersection(allowed_roles):
            frappe.local.flags.redirect_location = "/app"
            raise frappe.PermissionError("You are not allowed to access {title}.")
""".replace("{route}", route).replace("{title}", title).replace("{roles_json}", roles_json)

    return f'''import frappe


def get_context(context):
{check_code}
    context.no_cache = 1
    context.title = "{title}"

    try:
        context.csrf_token = frappe.sessions.get_csrf_token()
    except Exception:
        context.csrf_token = ""

    context.allowed_roles = {roles_json}
    context.access_mode = "{mode}"
'''


@frappe.whitelist()
def phase27j_apply_page_access_hardening():
    _phase27j_require_admin()

    app_pkg = _phase27j_Path(frappe.get_app_path("surhan_signature"))
    www_dir = app_pkg / "www"

    results = []

    for item in _phase27j_page_matrix():
        route = item.get("route")
        title = item.get("title")
        mode = item.get("mode")
        allowed_roles = item.get("allowed_roles") or []

        py_path = www_dir / f"{route}.py"
        html_path = www_dir / f"{route}.html"

        exists_before = py_path.exists()

        try:
            py_path.write_text(
                _phase27j_page_guard_py(route, title, mode, allowed_roles),
                encoding="utf-8",
            )

            results.append({
                "route": "/" + route,
                "title": title,
                "mode": mode,
                "allowed_roles": allowed_roles,
                "py_exists_before": exists_before,
                "py_written": True,
                "html_exists": html_path.exists(),
                "ok": True,
            })

        except Exception as exc:
            results.append({
                "route": "/" + route,
                "title": title,
                "mode": mode,
                "allowed_roles": allowed_roles,
                "py_exists_before": exists_before,
                "py_written": False,
                "html_exists": html_path.exists(),
                "ok": False,
                "error": str(exc),
            })

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            phase27f_write_admin_audit(
                action="access.apply_page_access_hardening",
                category="Access Control",
                payload={"matrix": _phase27j_page_matrix()},
                result={"results": results},
                success=not any(not r.get("ok") for r in results),
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27J",
        "results": results,
        "failed": [r for r in results if not r.get("ok")],
        "ready": not any(not r.get("ok") for r in results),
    }


@frappe.whitelist()
def phase27j_access_matrix_data():
    _phase27j_require_admin()

    app_pkg = _phase27j_Path(frappe.get_app_path("surhan_signature"))
    www_dir = app_pkg / "www"

    matrix = []

    for item in _phase27j_page_matrix():
        route = item.get("route")
        py_path = www_dir / f"{route}.py"
        html_path = www_dir / f"{route}.html"

        content = ""

        try:
            if py_path.exists():
                content = py_path.read_text(encoding="utf-8")
        except Exception:
            content = ""

        hardened = (
            "context.access_mode" in content
            and "context.allowed_roles" in content
            and (
                "frappe.PermissionError" in content
                or item.get("mode") == "authenticated"
            )
        )

        matrix.append({
            "route": "/" + route,
            "title": item.get("title"),
            "mode": item.get("mode"),
            "allowed_roles": item.get("allowed_roles"),
            "py_exists": py_path.exists(),
            "html_exists": html_path.exists(),
            "hardened": hardened,
        })

    return {
        "ok": True,
        "phase": "27J",
        "generated_at": str(now_datetime()),
        "matrix": matrix,
        "hardened_count": len([m for m in matrix if m.get("hardened")]),
        "total_count": len(matrix),
        "failed": [m for m in matrix if not m.get("hardened")],
        "routes": {
            "admin_control": "/signature-admin-control",
            "setup_wizard": "/signature-setup-wizard",
            "operations_center": "/signature-operations-center",
            "admin_audit": "/signature-admin-audit",
            "notifications_center": "/signature-notifications-center",
            "delegation_center": "/signature-delegation-center",
            "signature_inbox": "/signature-inbox",
        },
        "ready": all(m.get("hardened") for m in matrix),
    }


@frappe.whitelist()
def phase27j_export_access_matrix_snapshot_json():
    _phase27j_require_admin()

    data = phase27j_access_matrix_data()
    sha = _phase27j_sha256(data)
    content = _phase27j_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27j-page-access-hardening-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27J",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "hardened_count": data.get("hardened_count"),
        "total_count": data.get("total_count"),
        "ready": data.get("ready"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27j_page_access_hardening_health():
    _phase27j_require_admin()

    apply_result = phase27j_apply_page_access_hardening()
    data = phase27j_access_matrix_data()
    export = phase27j_export_access_matrix_snapshot_json()

    return {
        "ok": True,
        "phase": "27J",
        "apply_result": apply_result,
        "data": data,
        "export": export,
        "ready": bool(data.get("ready")),
    }


# Phase 27K: API Access Hardening.
import json as _phase27k_json
import hashlib as _phase27k_hashlib


def _phase27k_json_dumps(data):
    return _phase27k_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27k_sha256(data):
    if not isinstance(data, str):
        data = _phase27k_json_dumps(data)
    return _phase27k_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27k_admin_roles():
    return {
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }


def _phase27k_auditor_roles():
    return {
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
        "Internal Signature Auditor",
    }


def _phase27k_is_authenticated():
    return bool(getattr(frappe.session, "user", None) and frappe.session.user != "Guest")


def _phase27k_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection(_phase27k_admin_roles()))


def _phase27k_is_auditor():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])

    return bool(roles.intersection(_phase27k_auditor_roles()))


def _phase27k_require(mode):
    if mode == "public":
        return

    if mode == "authenticated":
        if not _phase27k_is_authenticated():
            frappe.throw("Authentication required.", frappe.PermissionError)
        return

    if mode == "auditor":
        if not _phase27k_is_auditor():
            frappe.throw("Only Signature Administrators or Auditors can access this API.", frappe.PermissionError)
        return

    if mode == "admin":
        if not _phase27k_is_admin():
            frappe.throw("Only Signature Administrators can access this API.", frappe.PermissionError)
        return

    frappe.throw(f"Unknown API access mode: {mode}", frappe.PermissionError)


def _phase27k_api_matrix():
    admin = [
        "admin_upsert_external_signature_system",
        "phase26j_retry_external_callback",
        "phase26j_generate_missing_certificate",
        "phase26h_create_gateway_demo_request",

        "phase27a_update_doctype_control",
        "phase27a_apply_doctype_control",
        "phase27a_apply_all_doctype_controls",
        "phase27a_refresh_control_center",

        "phase27b_admin_register_employee_signature",
        "phase27b_apply_employee_control_permissions",
        "phase27b_seed_employee_controls_from_employees",
        "phase27b_restrict_employee_signature_profile_permissions",

        "phase27c_apply_doctype_control_client_scripts",

        "phase27d_run_setup_step",
        "phase27d_run_full_setup_wizard",
        "phase27d_fix1_cleanup_signing_references",

        "phase27e_generate_missing_certificates",
        "phase27e_retry_external_callbacks",

        "phase27g_close_completed_signature_todos",

        "phase27h_run_notifications_now",
        "phase27h_export_notifications_snapshot_json",

        "phase27i_create_delegation_rule",
        "phase27i_reassign_signature_request",
        "phase27i_apply_active_delegations",

        "phase27j_apply_page_access_hardening",
        "phase27j_page_access_hardening_health",

        "phase27k_apply_api_access_hardening",
    ]

    auditor = [
        "phase26j_external_gateway_summary",
        "phase26j_external_gateway_requests",
        "phase26j_external_gateway_request_detail",
        "phase26j_verify_gateway_certificate",
        "phase26j_export_external_console_snapshot_json",
        "phase26j_external_console_health",

        "phase26o_production_readiness_report",

        "phase27e_operations_summary",
        "phase27e_pending_requests",
        "phase27e_recent_requests",
        "phase27e_certificate_overview",
        "phase27e_external_gateway_overview",
        "phase27e_operations_data",
        "phase27e_export_operations_snapshot_json",
        "phase27e_operations_center_health",

        "phase27f_admin_audit_logs",
        "phase27f_verify_admin_audit_hash_chain",
        "phase27f_export_admin_audit_snapshot_json",
        "phase27f_admin_audit_health",

        "phase27h_notifications_center_data",

        "phase27i_delegation_center_data",
        "phase27i_export_delegation_snapshot_json",
        "phase27i_delegation_center_health",

        "phase27j_access_matrix_data",
        "phase27j_export_access_matrix_snapshot_json",

        "phase27k_api_security_matrix_data",
        "phase27k_export_api_security_snapshot_json",
        "phase27k_api_access_hardening_health",
    ]

    authenticated = [
        "phase27g_signature_inbox_data",
        "phase27g_signature_badge_count",
        "phase27g_sync_signature_todos",
        "phase27g_export_signature_inbox_snapshot_json",
    ]

    public_intentional = [
        "external_signature_gateway_create_request",
        "external_signature_gateway_status",
        "verify_internal_signature_certificate",
        "phase26a_get_csrf_token",
    ]

    rows = []

    for fn in admin:
        rows.append({
            "function": fn,
            "mode": "admin",
            "allowed_roles": sorted(_phase27k_admin_roles()),
            "public_intentional": False,
        })

    for fn in auditor:
        rows.append({
            "function": fn,
            "mode": "auditor",
            "allowed_roles": sorted(_phase27k_auditor_roles()),
            "public_intentional": False,
        })

    for fn in authenticated:
        rows.append({
            "function": fn,
            "mode": "authenticated",
            "allowed_roles": ["All authenticated users"],
            "public_intentional": False,
        })

    for fn in public_intentional:
        rows.append({
            "function": fn,
            "mode": "public",
            "allowed_roles": ["Public / Guest where designed"],
            "public_intentional": True,
        })

    return rows


def _phase27k_wrap_api_function(function_name, mode):
    original_name = f"_phase27k_original_{function_name}"

    if globals().get(original_name):
        return {
            "function": function_name,
            "mode": mode,
            "exists": callable(globals().get(function_name)),
            "wrapped": True,
            "action": "already_wrapped",
        }

    original = globals().get(function_name)

    if not callable(original):
        return {
            "function": function_name,
            "mode": mode,
            "exists": False,
            "wrapped": False,
            "action": "missing",
        }

    globals()[original_name] = original

    def wrapper(*args, **kwargs):
        _phase27k_require(mode)
        return original(*args, **kwargs)

    wrapper.__name__ = function_name
    wrapper.__doc__ = getattr(original, "__doc__", None)

    globals()[function_name] = frappe.whitelist()(wrapper)

    return {
        "function": function_name,
        "mode": mode,
        "exists": True,
        "wrapped": True,
        "action": "wrapped",
    }


def _phase27k_auto_apply_api_wrappers():
    results = []

    for item in _phase27k_api_matrix():
        mode = item.get("mode")
        fn = item.get("function")

        if mode == "public":
            results.append({
                "function": fn,
                "mode": mode,
                "exists": callable(globals().get(fn)),
                "wrapped": False,
                "action": "public_intentional_not_wrapped",
            })
            continue

        results.append(_phase27k_wrap_api_function(fn, mode))

    return results


@frappe.whitelist()
def phase27k_apply_api_access_hardening():
    _phase27k_require("admin")

    results = _phase27k_auto_apply_api_wrappers()

    failed = [
        r for r in results
        if r.get("exists") and r.get("mode") != "public" and not r.get("wrapped")
    ]

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            phase27f_write_admin_audit(
                action="access.apply_api_access_hardening",
                category="Access Control",
                payload={"matrix": _phase27k_api_matrix()},
                result={"results": results},
                success=len(failed) == 0,
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27K",
        "results": results,
        "failed": failed,
        "ready": len(failed) == 0,
    }


@frappe.whitelist()
def phase27k_api_security_matrix_data():
    _phase27k_require("auditor")

    rows = []

    for item in _phase27k_api_matrix():
        fn = item.get("function")
        mode = item.get("mode")
        original_name = f"_phase27k_original_{fn}"

        exists = callable(globals().get(fn))
        wrapped = bool(globals().get(original_name))

        if mode == "public":
            hardened = True
        elif exists:
            hardened = wrapped
        else:
            hardened = True

        rows.append({
            "function": fn,
            "mode": mode,
            "allowed_roles": item.get("allowed_roles"),
            "public_intentional": item.get("public_intentional"),
            "exists": exists,
            "wrapped": wrapped,
            "hardened": hardened,
        })

    data = {
        "ok": True,
        "phase": "27K",
        "generated_at": str(now_datetime()),
        "matrix": rows,
        "existing_count": len([r for r in rows if r.get("exists")]),
        "wrapped_count": len([r for r in rows if r.get("wrapped")]),
        "public_intentional_count": len([r for r in rows if r.get("public_intentional")]),
        "hardened_count": len([r for r in rows if r.get("hardened")]),
        "total_count": len(rows),
        "failed": [r for r in rows if not r.get("hardened")],
        "routes": {
            "api_security_matrix": "/signature-api-security-matrix",
            "access_matrix": "/signature-access-matrix",
            "admin_control": "/signature-admin-control",
            "operations_center": "/signature-operations-center",
            "admin_audit": "/signature-admin-audit",
            "signature_inbox": "/signature-inbox",
        },
        "ready": all(r.get("hardened") for r in rows),
    }

    return data


@frappe.whitelist()
def phase27k_export_api_security_snapshot_json():
    _phase27k_require("auditor")

    data = phase27k_api_security_matrix_data()
    sha = _phase27k_sha256(data)
    content = _phase27k_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27k-api-access-hardening-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    return {
        "ok": True,
        "phase": "27K",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "existing_count": data.get("existing_count"),
        "wrapped_count": data.get("wrapped_count"),
        "public_intentional_count": data.get("public_intentional_count"),
        "hardened_count": data.get("hardened_count"),
        "total_count": data.get("total_count"),
        "ready": data.get("ready"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27k_api_access_hardening_health():
    _phase27k_require("admin")

    apply_result = phase27k_apply_api_access_hardening()
    data = phase27k_api_security_matrix_data()
    export = phase27k_export_api_security_snapshot_json()

    return {
        "ok": True,
        "phase": "27K",
        "apply_result": apply_result,
        "data": data,
        "export": export,
        "ready": bool(data.get("ready")),
    }


# Apply wrappers during module import so direct API calls remain protected after restart.
try:
    _phase27k_auto_apply_api_wrappers()
except Exception:
    pass


# Phase 27L: Final System Integrity Center.
import json as _phase27l_json
import hashlib as _phase27l_hashlib


def _phase27l_json_dumps(data):
    return _phase27l_json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _phase27l_sha256(data):
    if not isinstance(data, str):
        data = _phase27l_json_dumps(data)
    return _phase27l_hashlib.sha256(data.encode("utf-8")).hexdigest()


def _phase27l_admin_roles():
    return {
        "System Manager",
        "Internal Signature Administrator",
        "Internal Signature Manager",
    }


def _phase27l_is_admin():
    if frappe.session.user == "Administrator":
        return True

    roles = set(frappe.get_roles() or [])
    return bool(roles.intersection(_phase27l_admin_roles()))


def _phase27l_require_admin():
    if not _phase27l_is_admin():
        frappe.throw("Only Signature Administrators can access Final System Integrity Center.", frappe.PermissionError)


def _phase27l_safe_execute(function_name, kwargs=None):
    kwargs = kwargs or {}

    fn = globals().get(function_name)

    if not callable(fn):
        return {
            "ok": False,
            "available": False,
            "function": function_name,
            "error": "Function not available.",
        }

    try:
        result = fn(**kwargs)
        return {
            "ok": True,
            "available": True,
            "function": function_name,
            "result": result,
        }

    except Exception as exc:
        return {
            "ok": False,
            "available": True,
            "function": function_name,
            "error": str(exc),
        }


def _phase27l_db_counts():
    out = {}

    doctypes = [
        "Signature System Settings",
        "Signature DocType Control",
        "Signature Employee Control",
        "Employee Signature Profile",
        "Document Signature Request",
        "Internal Signature Certificate",
        "Internal Signature External System",
        "Internal Signature External Request",
        "Signature Admin Audit Log",
        "Signature Delegation Rule",
        "ToDo",
    ]

    for dt in doctypes:
        try:
            if not frappe.db.exists("DocType", dt):
                out[frappe.scrub(dt)] = {
                    "exists": False,
                    "count": 0,
                }
                continue

            issingle = int(frappe.db.get_value("DocType", dt, "issingle") or 0)

            if issingle:
                count = 1
            else:
                count = frappe.db.count(dt)

            out[frappe.scrub(dt)] = {
                "exists": True,
                "count": int(count or 0),
                "issingle": bool(issingle),
            }

        except Exception as exc:
            out[frappe.scrub(dt)] = {
                "exists": bool(frappe.db.exists("DocType", dt)),
                "count": 0,
                "error": str(exc),
            }

    return out


def _phase27l_request_status_counts():
    if not frappe.db.exists("DocType", "Document Signature Request"):
        return {}

    try:
        rows = frappe.db.sql(
            """
            SELECT status, COUNT(name) AS count_value
            FROM `tabDocument Signature Request`
            GROUP BY status
            ORDER BY COUNT(name) DESC
            """,
            as_dict=True,
        )

        return {
            r.get("status") or "Blank": int(r.get("count_value") or 0)
            for r in rows
        }
    except Exception:
        return {}


def _phase27l_certificate_status_counts():
    if not frappe.db.exists("DocType", "Internal Signature Certificate"):
        return {}

    try:
        rows = frappe.db.sql(
            """
            SELECT certificate_status, COUNT(name) AS count_value
            FROM `tabInternal Signature Certificate`
            GROUP BY certificate_status
            ORDER BY COUNT(name) DESC
            """,
            as_dict=True,
        )

        return {
            r.get("certificate_status") or "Blank": int(r.get("count_value") or 0)
            for r in rows
        }
    except Exception:
        return {}


def _phase27l_core_health_calls():
    calls = {
        "setup_wizard": _phase27l_safe_execute("phase27d_setup_wizard_data"),
        "operations": _phase27l_safe_execute("phase27e_operations_summary"),
        "audit_hash_chain": _phase27l_safe_execute("phase27f_verify_admin_audit_hash_chain"),
        "notifications": _phase27l_safe_execute("phase27h_notifications_center_data"),
        "delegation": _phase27l_safe_execute("phase27i_delegation_center_data"),
        "page_access": _phase27l_safe_execute("phase27j_access_matrix_data"),
        "api_security": _phase27l_safe_execute("phase27k_api_security_matrix_data"),
        "production_readiness": _phase27l_safe_execute("phase26o_production_readiness_report"),
        "external_gateway": _phase27l_safe_execute("phase26j_external_console_health"),
    }

    return calls


def _phase27l_extract_result(calls, key):
    item = calls.get(key) or {}
    return item.get("result") if item.get("ok") else {}


def _phase27l_evaluate_integrity(calls, db_counts):
    setup = _phase27l_extract_result(calls, "setup_wizard")
    audit = _phase27l_extract_result(calls, "audit_hash_chain")
    notifications = _phase27l_extract_result(calls, "notifications")
    delegation = _phase27l_extract_result(calls, "delegation")
    page_access = _phase27l_extract_result(calls, "page_access")
    api_security = _phase27l_extract_result(calls, "api_security")
    production = _phase27l_extract_result(calls, "production_readiness")
    external_gateway = _phase27l_extract_result(calls, "external_gateway")

    todo_counts = notifications.get("todo_counts") or {}
    request_counts = notifications.get("request_counts") or {}

    open_todos = int(todo_counts.get("open_signature_todos") or 0)
    pending_requests = int(request_counts.get("pending_requests") or 0)

    checks = [
        {
            "key": "setup_wizard_ready",
            "title": "Setup Wizard Ready",
            "ready": bool(setup.get("overall_ready") or setup.get("ready")),
            "details": {
                "ready_count": setup.get("ready_count"),
                "attention_count": setup.get("attention_count"),
            },
        },
        {
            "key": "audit_hash_chain_valid",
            "title": "Admin Audit Hash Chain Valid",
            "ready": bool(audit.get("valid")),
            "details": {
                "checked": audit.get("checked"),
                "issues_count": audit.get("issues_count"),
            },
        },
        {
            "key": "todo_pending_match",
            "title": "Open ToDos Match Pending Requests",
            "ready": open_todos == pending_requests,
            "details": {
                "open_signature_todos": open_todos,
                "pending_requests": pending_requests,
            },
        },
        {
            "key": "delegation_ready",
            "title": "Delegation Center Ready",
            "ready": bool(delegation.get("ready")),
            "details": {
                "rules_count": delegation.get("rules_count"),
                "active_rules_count": delegation.get("active_rules_count"),
                "pending_requests_count": delegation.get("pending_requests_count"),
            },
        },
        {
            "key": "page_access_ready",
            "title": "Page Access Hardened",
            "ready": bool(page_access.get("ready")),
            "details": {
                "hardened_count": page_access.get("hardened_count"),
                "total_count": page_access.get("total_count"),
                "failed": page_access.get("failed"),
            },
        },
        {
            "key": "api_security_ready",
            "title": "API Access Hardened",
            "ready": bool(api_security.get("ready")),
            "details": {
                "hardened_count": api_security.get("hardened_count"),
                "total_count": api_security.get("total_count"),
                "failed": api_security.get("failed"),
            },
        },
        {
            "key": "external_gateway_ready",
            "title": "External Gateway Ready",
            "ready": bool(external_gateway.get("ready") or external_gateway.get("ok")),
            "details": external_gateway,
        },
        {
            "key": "staging_ready",
            "title": "Staging Readiness",
            "ready": bool(production.get("staging_ready") or production.get("ready")),
            "details": {
                "staging_ready": production.get("staging_ready"),
                "production_ready": production.get("production_ready"),
                "blocker_count": production.get("blocker_count"),
                "warning_count": production.get("warning_count"),
                "warnings": production.get("warnings"),
            },
        },
    ]

    critical_ready = all(c.get("ready") for c in checks)

    warnings = []

    prod_result = production or {}
    for warning in prod_result.get("warnings") or []:
        warnings.append(warning)

    if not bool(prod_result.get("production_ready")):
        warnings.append("Production readiness is not fully green yet. This may be expected on staging because of developer_mode, email configuration, or pending signature requests.")

    request_status_counts = _phase27l_request_status_counts()
    certificate_status_counts = _phase27l_certificate_status_counts()

    return {
        "checks": checks,
        "ready_count": len([c for c in checks if c.get("ready")]),
        "total_count": len(checks),
        "failed": [c for c in checks if not c.get("ready")],
        "warnings": warnings,
        "request_status_counts": request_status_counts,
        "certificate_status_counts": certificate_status_counts,
        "overall_ready": critical_ready,
    }


@frappe.whitelist()
def phase27l_system_integrity_data():
    _phase27l_require_admin()

    db_counts = _phase27l_db_counts()
    calls = _phase27l_core_health_calls()
    evaluation = _phase27l_evaluate_integrity(calls, db_counts)

    data = {
        "ok": True,
        "phase": "27L",
        "generated_at": str(now_datetime()),
        "db_counts": db_counts,
        "health_calls": calls,
        "evaluation": evaluation,
        "routes": {
            "system_integrity_center": "/signature-system-integrity-center",
            "setup_wizard": "/signature-setup-wizard",
            "operations_center": "/signature-operations-center",
            "admin_audit": "/signature-admin-audit",
            "notifications_center": "/signature-notifications-center",
            "delegation_center": "/signature-delegation-center",
            "access_matrix": "/signature-access-matrix",
            "api_security_matrix": "/signature-api-security-matrix",
            "signature_inbox": "/signature-inbox",
            "production_readiness": "/signature-production-readiness",
        },
        "ready": bool(evaluation.get("overall_ready")),
    }

    return data


@frappe.whitelist()
def phase27l_export_system_integrity_snapshot_json():
    _phase27l_require_admin()

    data = phase27l_system_integrity_data()
    sha = _phase27l_sha256(data)
    content = _phase27l_json_dumps(data).encode("utf-8")

    from frappe.utils.file_manager import save_file

    file_doc = save_file(
        fname=f"phase27l-final-system-integrity-{sha[:18]}.json",
        content=content,
        dt=None,
        dn=None,
        is_private=1,
    )

    evaluation = data.get("evaluation") or {}

    return {
        "ok": True,
        "phase": "27L",
        "file_url": file_doc.file_url,
        "sha256": sha,
        "overall_ready": evaluation.get("overall_ready"),
        "ready_count": evaluation.get("ready_count"),
        "total_count": evaluation.get("total_count"),
        "failed": evaluation.get("failed"),
        "warnings": evaluation.get("warnings"),
        "routes": data.get("routes"),
    }


@frappe.whitelist()
def phase27l_final_integrity_health():
    _phase27l_require_admin()

    data = phase27l_system_integrity_data()
    export = phase27l_export_system_integrity_snapshot_json()

    try:
        if callable(globals().get("phase27f_write_admin_audit")):
            phase27f_write_admin_audit(
                action="integrity.final_system_integrity_health",
                category="System Integrity",
                payload={},
                result={
                    "overall_ready": data.get("ready"),
                    "evaluation": data.get("evaluation"),
                    "export": export,
                },
                success=bool(data.get("ready")),
                severity="Info" if data.get("ready") else "Warning",
            )
    except Exception:
        pass

    return {
        "ok": True,
        "phase": "27L",
        "data": data,
        "export": export,
        "ready": bool(data.get("ready")),
    }


# Forward admin_api functions
from surhan_signature.admin_api import (
    get_overview_data,
    get_system_users_and_employees,
    get_all_available_doctypes,
    get_doctype_controls_data,
    save_doctype_full_control,
    delete_doctype_control,
    auto_discover_all_doctypes,
    get_employee_signatures_data,
    get_employee_signature_details,
    save_employee_signature_and_permissions,
    create_or_update_delegation,
    get_operations_data,
    send_signature_reminder,
    reassign_signature_request,
    get_transaction_details,
    get_external_systems_data,
    upsert_external_system,
    delete_external_system,
    test_external_api_live,
    get_sdk_snippets,
    get_system_settings_data,
    save_system_settings,
    get_webhooks_data,
    retry_webhook_delivery,
    get_audit_trail_data,
    get_certificates_data,
    run_system_diagnostics,
    get_envelopes_data,
    void_envelope,
    get_delegations_data,
    save_delegation_rule,
    delete_delegation_rule,
    get_security_events_and_risks_data,
    get_global_doctype_matrix,
    toggle_doctype_control_quick,
)


