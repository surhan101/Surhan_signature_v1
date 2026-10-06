import frappe


def execute():
    if frappe.db.exists("DocType", "E-Sign Settings"):
        expiry = int(frappe.db.get_single_value("E-Sign Settings", "otp_expiry_minutes") or 5)
        attempts = int(frappe.db.get_single_value("E-Sign Settings", "max_otp_attempts") or 5)
        frappe.db.set_single_value("E-Sign Settings", "otp_expiry_minutes", max(1, min(expiry, 15)))
        frappe.db.set_single_value("E-Sign Settings", "max_otp_attempts", max(1, min(attempts, 10)))

    if not frappe.db.table_exists("E-Sign Recipient"):
        return

    frappe.db.sql(
        """
        UPDATE `tabE-Sign Recipient`
        SET
            otp_salt = NULL,
            otp_hash = NULL,
            otp_expires_at = NULL,
            otp_attempts = 0,
            otp_verified = 0,
            otp_verified_at = NULL,
            status = CASE
                WHEN status IN ('OTP Requested', 'OTP Verified') THEN 'Viewed'
                ELSE status
            END
        WHERE
            otp_hash IS NOT NULL
            OR otp_salt IS NOT NULL
            OR COALESCE(otp_verified, 0) = 1
        """
    )
