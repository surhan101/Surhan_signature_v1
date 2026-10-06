import base64
import html
import io
import json
import os
import zipfile
from typing import Optional

import frappe
from frappe.utils import get_url, now_datetime
from frappe.utils.file_manager import save_file
from frappe.utils.pdf import get_pdf

from surhan_signature.signing.crypto import sha256_hex
from surhan_signature.signing.security import safe_document_html


def _escape(value) -> str:
    return html.escape(str(value or ""))


def _file_bytes(file_url: Optional[str]) -> bytes:
    if not file_url:
        return b""

    if file_url.startswith("/private/files/"):
        filename = os.path.basename(file_url)
        path = frappe.get_site_path("private", "files", filename)
    elif file_url.startswith("/files/"):
        filename = os.path.basename(file_url)
        path = frappe.get_site_path("public", "files", filename)
    else:
        return b""

    if not os.path.exists(path):
        return b""

    with open(path, "rb") as f:
        return f.read()


def _file_sha256(file_url: Optional[str]) -> Optional[str]:
    raw = _file_bytes(file_url)
    if not raw:
        return None
    return sha256_hex(raw)


def _file_url_to_data_uri(file_url: Optional[str]) -> str:
    raw = _file_bytes(file_url)
    if not raw:
        return ""

    filename = os.path.basename(file_url or "")
    lower = filename.lower()

    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        mime = "image/jpeg"
    elif lower.endswith(".png"):
        mime = "image/png"
    else:
        mime = "application/octet-stream"

    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"


def _save_private_file(content: bytes, fname: str, env_name: str) -> tuple[str, str]:
    digest = sha256_hex(content)

    saved = save_file(
        fname=fname,
        content=content,
        dt="E-Sign Envelope",
        dn=env_name,
        folder=None,
        is_private=1,
    )

    return saved.file_url, digest


def _save_pdf(html_text: str, fname: str, env_name: str) -> tuple[str, str]:
    pdf_bytes = get_pdf(html_text)
    return _save_private_file(pdf_bytes, fname, env_name)


def _certificate_doc(envelope_name: str):
    cert_name = frappe.db.exists("E-Sign Certificate", {"envelope": envelope_name})
    if cert_name:
        return frappe.get_doc("E-Sign Certificate", cert_name)
    return None


def _signer_rows_html(env) -> str:
    rows = []

    for r in env.recipients:
        signature_visual = ""

        if r.signature_method == "Typed":
            signature_visual = f"<div class='typed-signature'>{_escape(r.signature_text)}</div>"
        elif r.signature_image:
            data_uri = _file_url_to_data_uri(r.signature_image)
            if data_uri:
                signature_visual = f"<img class='signature-img' src='{data_uri}' />"
            else:
                signature_visual = f"<span>{_escape(r.signature_image)}</span>"
        else:
            signature_visual = "<span>-</span>"

        rows.append(f"""
            <tr>
              <td>{_escape(r.signer_name)}</td>
              <td>{_escape(r.signer_email)}</td>
              <td>{_escape(r.role)}</td>
              <td>{_escape(r.status)}</td>
              <td>{_escape(r.signature_method)}</td>
              <td>{_escape(r.signed_at)}</td>
              <td>{signature_visual}</td>
            </tr>
        """)

    return "\n".join(rows)


def render_certificate_html(env, cert=None) -> str:
    cert = cert or _certificate_doc(env.name)
    certificate_no = cert.certificate_no if cert else env.certificate_no
    verification_url = (
        cert.verification_url
        if cert and cert.verification_url
        else f"{get_url()}/verify?certificate_no={certificate_no}"
    )

    final_hash_display = env.final_pdf_sha256 or "Recorded after final PDF generation. Verify online using the certificate page."

    return f"""
    <section class="certificate-page">
      <h1>Certificate of Completion</h1>
      <p class="muted">This certificate summarizes the electronic signing evidence recorded by Surhan Signature.</p>

      <div class="cert-grid">
        <div><b>Certificate No</b><span>{_escape(certificate_no)}</span></div>
        <div><b>Envelope</b><span>{_escape(env.name)}</span></div>
        <div><b>Document Title</b><span>{_escape(env.title)}</span></div>
        <div><b>Envelope Status</b><span>{_escape(env.status)}</span></div>
        <div><b>Completed On</b><span>{_escape(env.completed_on)}</span></div>
        <div><b>Signing Level</b><span>{_escape(env.signing_level)}</span></div>
        <div><b>Artifact Version</b><span>{_escape(getattr(env, "artifacts_version", 0))}</span></div>
      </div>

      <h2>Integrity Hashes</h2>
      <div class="hash-box"><b>Canonical SHA-256</b><code>{_escape(env.canonical_sha256)}</code></div>
      <div class="hash-box"><b>Final PDF SHA-256</b><code>{_escape(final_hash_display)}</code></div>
      <div class="hash-box"><b>Audit Root Hash</b><code>{_escape(env.audit_root_hash)}</code></div>

      <h2>Verification</h2>
      <p>Verification URL:</p>
      <code class="verify-url">{_escape(verification_url)}</code>

      <h2>Signer Evidence</h2>
      <table>
        <thead>
          <tr>
            <th>Signer</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Method</th>
            <th>Signed At</th>
            <th>Visual Signature</th>
          </tr>
        </thead>
        <tbody>{_signer_rows_html(env)}</tbody>
      </table>
    </section>
    """


def _base_pdf_style() -> str:
    return """
      <style>
        body { font-family: Arial, sans-serif; color: #111827; font-size: 12px; line-height: 1.6; }
        .page { padding: 24px; }
        .header { border-bottom: 2px solid #111827; padding-bottom: 12px; margin-bottom: 24px; }
        .header h1 { margin: 0; font-size: 22px; }
        .muted { color: #64748b; }
        .document-body { min-height: 420px; padding: 18px; border: 1px solid #e5e7eb; border-radius: 10px; }
        .signature-summary { margin-top: 28px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #d1d5db; padding: 8px; vertical-align: top; }
        th { background: #f3f4f6; font-weight: bold; }
        .signature-img { max-width: 160px; max-height: 70px; border: 1px solid #e5e7eb; padding: 4px; }
        .typed-signature { font-size: 18px; font-family: cursive; border-bottom: 1px solid #111827; display: inline-block; padding: 4px 18px; }
        .certificate-page { page-break-before: always; padding: 24px; }
        .cert-grid { display: table; width: 100%; border-collapse: collapse; margin: 16px 0; }
        .cert-grid div { display: table-row; }
        .cert-grid b, .cert-grid span { display: table-cell; border: 1px solid #d1d5db; padding: 8px; }
        .cert-grid b { background: #f3f4f6; width: 30%; }
        .hash-box { margin: 8px 0; padding: 10px; border: 1px solid #d1d5db; border-radius: 8px; }
        code { word-break: break-all; display: block; font-size: 10px; color: #334155; }
        .verify-url { font-size: 11px; padding: 8px; border: 1px solid #d1d5db; }
      </style>
    """


def render_signed_document_html(env) -> str:
    document_html = safe_document_html(env.document_html or "")
    cert = _certificate_doc(env.name)

    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      {_base_pdf_style()}
    </head>
    <body>
      <div class="page">
        <div class="header">
          <h1>{_escape(env.title)}</h1>
          <p class="muted">Final electronically signed document generated by Surhan Signature.</p>
          <p><b>Envelope:</b> {_escape(env.name)} | <b>Status:</b> {_escape(env.status)} | <b>Certificate:</b> {_escape(env.certificate_no)}</p>
        </div>

        <div class="document-body">{document_html}</div>

        <div class="signature-summary">
          <h2>Signature Summary</h2>
          <table>
            <thead>
              <tr>
                <th>Signer</th><th>Email</th><th>Role</th><th>Status</th><th>Method</th><th>Signed At</th><th>Visual Signature</th>
              </tr>
            </thead>
            <tbody>{_signer_rows_html(env)}</tbody>
          </table>
        </div>
      </div>

      {render_certificate_html(env, cert)}
    </body>
    </html>
    """


def render_certificate_pdf_html(env, cert) -> str:
    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      {_base_pdf_style()}
    </head>
    <body>
      {render_certificate_html(env, cert)}
    </body>
    </html>
    """


def _audit_logs_snapshot(envelope_name: str) -> list[dict]:
    return frappe.get_all(
        "E-Sign Audit Log",
        filters={"envelope": envelope_name},
        fields=[
            "name",
            "event_type",
            "actor_type",
            "actor_user",
            "actor_email",
            "timestamp_utc",
            "ip_address",
            "user_agent",
            "request_id",
            "details_json",
            "previous_hash",
            "current_hash",
            "creation",
            "modified",
        ],
        order_by="creation asc",
    )


def _manifest(env, cert) -> dict:
    recipients = []

    for r in env.recipients:
        signature_image_hash = _file_sha256(r.signature_image) if r.signature_image else None
        recipients.append({
            "row": r.name,
            "signer_name": r.signer_name,
            "signer_email": r.signer_email,
            "role": r.role,
            "status": r.status,
            "signature_method": r.signature_method,
            "signed_at": str(r.signed_at) if r.signed_at else None,
            "signature_image": r.signature_image,
            "signature_image_sha256": signature_image_hash,
        })

    return {
        "generated_at": str(now_datetime()),
        "system": "Surhan Signature",
        "envelope": env.name,
        "title": env.title,
        "status": env.status,
        "certificate_no": cert.certificate_no if cert else env.certificate_no,
        "artifact_version": int(getattr(env, "artifacts_version", 0) or 0),
        "canonical_sha256": env.canonical_sha256,
        "final_signed_pdf": env.final_signed_pdf,
        "final_pdf_sha256": env.final_pdf_sha256,
        "certificate_pdf": cert.certificate_pdf if cert else None,
        "certificate_pdf_sha256": getattr(cert, "certificate_pdf_sha256", None) if cert else None,
        "audit_root_hash": env.audit_root_hash,
        "verification_url": cert.verification_url if cert else None,
        "recipients": recipients,
    }


def generate_evidence_package(envelope_name: str) -> dict:
    env = frappe.get_doc("E-Sign Envelope", envelope_name)
    cert = _certificate_doc(env.name)

    if not cert:
        frappe.throw("Certificate not found.")

    manifest = _manifest(env, cert)
    audit_logs = _audit_logs_snapshot(env.name)

    mem = io.BytesIO()

    with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, default=str))
        z.writestr("audit_log.json", json.dumps(audit_logs, ensure_ascii=False, indent=2, default=str))
        z.writestr("document.html", env.document_html or "")

        if env.final_signed_pdf:
            raw = _file_bytes(env.final_signed_pdf)
            if raw:
                z.writestr(os.path.basename(env.final_signed_pdf), raw)

        if cert.certificate_pdf:
            raw = _file_bytes(cert.certificate_pdf)
            if raw:
                z.writestr(os.path.basename(cert.certificate_pdf), raw)

        for r in env.recipients:
            if r.signature_image:
                raw = _file_bytes(r.signature_image)
                if raw:
                    z.writestr(f"signatures/{os.path.basename(r.signature_image)}", raw)

    zip_bytes = mem.getvalue()
    package_url, package_hash = _save_private_file(
        zip_bytes,
        f"{env.name}-{cert.certificate_no}-evidence-package-v{int(getattr(env, 'artifacts_version', 0) or 0)}.zip",
        env.name,
    )

    env.evidence_package = package_url
    env.evidence_package_sha256 = package_hash
    env.save(ignore_permissions=True)

    cert.evidence_package = package_url
    cert.evidence_package_sha256 = package_hash
    cert.save(ignore_permissions=True)

    return {
        "evidence_package": package_url,
        "evidence_package_sha256": package_hash,
    }


def _existing_artifact_result(env, cert) -> dict:
    package = {}

    if not getattr(env, "evidence_package", None) or not getattr(cert, "evidence_package", None):
        package = generate_evidence_package(env.name)

    return {
        "ok": True,
        "already_finalized": True,
        "envelope": env.name,
        "certificate_no": cert.certificate_no,
        "artifact_version": int(getattr(env, "artifacts_version", 0) or 0),
        "final_signed_pdf": env.final_signed_pdf,
        "final_pdf_sha256": env.final_pdf_sha256,
        "certificate_pdf": cert.certificate_pdf,
        "certificate_pdf_sha256": getattr(cert, "certificate_pdf_sha256", None),
        "evidence_package": getattr(env, "evidence_package", None) or package.get("evidence_package"),
        "evidence_package_sha256": getattr(env, "evidence_package_sha256", None) or package.get("evidence_package_sha256"),
    }


def finalize_envelope_artifacts(envelope_name: str, force: bool = False) -> dict:
    env = frappe.get_doc("E-Sign Envelope", envelope_name)

    if env.status != "Signed":
        frappe.throw("Final artifacts can only be generated for Signed envelopes.")

    cert = _certificate_doc(env.name)
    if not cert:
        frappe.throw("Certificate not found for signed envelope.")

    already_has_core = bool(env.final_signed_pdf and cert.certificate_pdf)

    if already_has_core and not force:
        return _existing_artifact_result(env, cert)

    current_version = int(getattr(env, "artifacts_version", 0) or getattr(cert, "artifact_version", 0) or 0)
    next_version = current_version + 1

    env.artifacts_version = next_version
    env.artifacts_locked = 0
    env.save(ignore_permissions=True)
    env.reload()

    signed_html = render_signed_document_html(env)
    final_pdf_url, final_pdf_hash = _save_pdf(
        signed_html,
        f"{env.name}-final-signed-v{next_version}.pdf",
        env.name,
    )

    env.final_signed_pdf = final_pdf_url
    env.final_pdf_sha256 = final_pdf_hash
    env.artifacts_version = next_version
    env.artifacts_locked = 1
    env.save(ignore_permissions=True)

    env.reload()
    cert.reload()

    cert.artifact_version = next_version
    cert.final_hash = final_pdf_hash
    cert.original_hash = env.canonical_sha256
    cert.verification_url = f"{get_url()}/verify?certificate_no={cert.certificate_no}"
    cert.save(ignore_permissions=True)

    env.reload()
    cert.reload()

    certificate_html = render_certificate_pdf_html(env, cert)
    cert_pdf_url, cert_pdf_hash = _save_pdf(
        certificate_html,
        f"{cert.certificate_no}-certificate-v{next_version}.pdf",
        env.name,
    )

    cert.certificate_pdf = cert_pdf_url
    cert.certificate_pdf_sha256 = cert_pdf_hash
    cert.artifacts_locked = 1
    cert.save(ignore_permissions=True)

    env.reload()
    cert.reload()

    package = generate_evidence_package(env.name)

    return {
        "ok": True,
        "already_finalized": False,
        "envelope": env.name,
        "certificate_no": cert.certificate_no,
        "artifact_version": next_version,
        "final_signed_pdf": final_pdf_url,
        "final_pdf_sha256": final_pdf_hash,
        "certificate_pdf": cert_pdf_url,
        "certificate_pdf_sha256": cert_pdf_hash,
        "evidence_package": package.get("evidence_package"),
        "evidence_package_sha256": package.get("evidence_package_sha256"),
    }


def verify_artifact_files(envelope_name: str, update_status: bool = True) -> dict:
    env = frappe.get_doc("E-Sign Envelope", envelope_name)
    cert = _certificate_doc(env.name)

    result = {
        "envelope": env.name,
        "certificate_no": cert.certificate_no if cert else env.certificate_no,
        "final_signed_pdf": env.final_signed_pdf,
        "final_pdf_sha256_recorded": env.final_pdf_sha256,
        "final_pdf_sha256_actual": _file_sha256(env.final_signed_pdf),
        "certificate_pdf": cert.certificate_pdf if cert else None,
        "certificate_pdf_sha256_recorded": getattr(cert, "certificate_pdf_sha256", None) if cert else None,
        "certificate_pdf_sha256_actual": _file_sha256(cert.certificate_pdf) if cert else None,
        "evidence_package": getattr(env, "evidence_package", None),
        "evidence_package_sha256_recorded": getattr(env, "evidence_package_sha256", None),
        "evidence_package_sha256_actual": _file_sha256(getattr(env, "evidence_package", None)),
    }

    result["final_pdf_ok"] = (
        bool(result["final_pdf_sha256_recorded"])
        and result["final_pdf_sha256_recorded"] == result["final_pdf_sha256_actual"]
    )

    result["certificate_pdf_ok"] = (
        bool(result["certificate_pdf_sha256_recorded"])
        and result["certificate_pdf_sha256_recorded"] == result["certificate_pdf_sha256_actual"]
    )

    result["evidence_package_ok"] = (
        bool(result["evidence_package_sha256_recorded"])
        and result["evidence_package_sha256_recorded"] == result["evidence_package_sha256_actual"]
    )

    result["all_files_ok"] = result["final_pdf_ok"] and result["certificate_pdf_ok"] and result["evidence_package_ok"]

    if cert and update_status:
        frappe.flags.in_signature_system_update = True
        try:
            cert.last_file_integrity_status = "OK" if result["all_files_ok"] else "FAILED"
            cert.last_verified_at = now_datetime()
            cert.save(ignore_permissions=True)
        finally:
            frappe.flags.in_signature_system_update = False

    return result
