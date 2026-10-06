"""Private artifact invariants and public-response leak protection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


PRIVATE_FILE_PREFIX = "/private/files/"
SENSITIVE_DOCTYPES = (
    "E-Sign Certificate",
    "E-Sign Envelope",
    "E-Sign Settings",
    "E-Sign Test Run",
    "Employee Signature Profile",
    "Employee Signature Profile Version",
    "Internal Signature Certificate",
    "Internal Signature External Request",
)

ARTIFACT_FIELDS = {
    "E-Sign Envelope": (
        "original_file",
        "final_signed_pdf",
        "evidence_package",
    ),
    "E-Sign Certificate": (
        "certificate_pdf",
        "evidence_package",
        "verification_qr_pdf",
    ),
}


class PrivateArtifactExposure(RuntimeError):
    """Raised when a public response contains a private file URL."""


def private_urls_in_payload(value, path: str = "$") -> list[dict[str, str]]:
    """Return locations of private URLs without logging their full values."""
    found: list[dict[str, str]] = []

    if isinstance(value, str):
        if PRIVATE_FILE_PREFIX in value:
            found.append({"path": path, "prefix": PRIVATE_FILE_PREFIX})
        return found

    if isinstance(value, Mapping):
        for key, item in value.items():
            found.extend(private_urls_in_payload(item, f"{path}.{key}"))
        return found

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for index, item in enumerate(value):
            found.extend(private_urls_in_payload(item, f"{path}[{index}]"))

    return found


def assert_public_payload_safe(payload):
    """Fail closed if a guest/public payload contains private artifact URLs."""
    leaks = private_urls_in_payload(payload)
    if leaks:
        locations = ", ".join(item["path"] for item in leaks[:10])
        raise PrivateArtifactExposure(
            f"Public response blocked because it contains private artifact data at: {locations}"
        )
    return payload


def _table_exists(doctype: str) -> bool:
    import frappe

    return bool(frappe.db.exists("DocType", doctype))


def _artifact_references() -> list[dict]:
    import frappe

    rows: list[dict] = []
    for doctype, fields in ARTIFACT_FIELDS.items():
        if not _table_exists(doctype):
            continue
        meta = frappe.get_meta(doctype)
        available = [field for field in fields if meta.has_field(field)]
        if not available:
            continue
        for doc in frappe.get_all(doctype, fields=["name", *available], limit_page_length=0):
            for field in available:
                file_url = doc.get(field)
                if file_url:
                    rows.append(
                        {
                            "doctype": doctype,
                            "name": doc.name,
                            "field": field,
                            "file_url": file_url,
                        }
                    )
    return rows


def audit_private_artifacts() -> dict:
    """Audit database metadata only; never mutates or deletes files."""
    import frappe

    public_sensitive = frappe.db.count(
        "File",
        filters={"attached_to_doctype": ["in", SENSITIVE_DOCTYPES], "is_private": 0},
    )

    mismatched_private_urls = frappe.db.sql(
        """
        SELECT COUNT(*)
          FROM `tabFile`
         WHERE (file_url LIKE '/private/files/%' AND COALESCE(is_private, 0) <> 1)
            OR (file_url LIKE '/files/%' AND COALESCE(is_private, 0) = 1)
        """
    )[0][0]

    missing_records = []
    non_private_references = []
    for ref in _artifact_references():
        if not str(ref["file_url"]).startswith(PRIVATE_FILE_PREFIX):
            non_private_references.append(
                {key: ref[key] for key in ("doctype", "name", "field")}
            )
            continue
        file_row = frappe.db.get_value(
            "File", {"file_url": ref["file_url"]}, ["name", "is_private"], as_dict=True
        )
        if not file_row:
            missing_records.append(
                {key: ref[key] for key in ("doctype", "name", "field")}
            )
        elif not int(file_row.is_private or 0):
            non_private_references.append(
                {key: ref[key] for key in ("doctype", "name", "field")}
            )

    unattached_private = frappe.db.sql(
        """
        SELECT COUNT(*)
          FROM `tabFile`
         WHERE is_private = 1
           AND COALESCE(attached_to_doctype, '') = ''
           AND COALESCE(attached_to_name, '') = ''
        """
    )[0][0]

    duplicate_unattached = frappe.db.sql(
        """
        SELECT COUNT(*)
          FROM (
                SELECT file_name
                  FROM `tabFile`
                 WHERE is_private = 1
                   AND COALESCE(attached_to_doctype, '') = ''
                   AND COALESCE(attached_to_name, '') = ''
                 GROUP BY file_name, content_hash
                HAVING COUNT(*) > 1
               ) duplicates
        """
    )[0][0]

    blockers = {
        "public_sensitive_files": int(public_sensitive or 0),
        "private_url_flag_mismatches": int(mismatched_private_urls or 0),
        "artifact_references_without_file_record": len(missing_records),
        "non_private_artifact_references": len(non_private_references),
    }

    return {
        "ok": not any(blockers.values()),
        **blockers,
        "missing_record_details": missing_records[:50],
        "non_private_reference_details": non_private_references[:50],
        "unattached_private_files": int(unattached_private or 0),
        "duplicate_unattached_file_groups": int(duplicate_unattached or 0),
        "orphan_policy": "report_only_no_automatic_deletion",
        "public_payload_fail_closed": True,
    }


def health() -> dict:
    return audit_private_artifacts()
