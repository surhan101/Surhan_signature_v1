import unittest
from types import SimpleNamespace

from surhan_signature.signing.otp import (
    OTP_LENGTH,
    generate_numeric_otp,
    hash_otp,
    reset_otp_state_on_row,
)


class OTPPrimitiveTests(unittest.TestCase):
    def test_generated_otp_is_six_numeric_digits(self):
        for _ in range(100):
            otp = generate_numeric_otp()
            self.assertEqual(len(otp), OTP_LENGTH)
            self.assertTrue(otp.isdigit())

    def test_hash_is_bound_to_current_token(self):
        common = {"otp": "123456", "salt": "salt", "pepper": "site-secret"}
        first = hash_otp(token_digest="token-a", **common)
        second = hash_otp(token_digest="token-b", **common)
        self.assertNotEqual(first, second)

    def test_hash_is_bound_to_site_secret(self):
        common = {"otp": "123456", "salt": "salt", "token_digest": "token"}
        first = hash_otp(pepper="site-a", **common)
        second = hash_otp(pepper="site-b", **common)
        self.assertNotEqual(first, second)

    def test_reset_clears_previous_verification(self):
        row = SimpleNamespace(
            otp_token_hash="token-digest",
            otp_salt="salt",
            otp_hash="digest",
            otp_expires_at="future",
            otp_attempts=2,
            otp_verified=1,
            otp_verified_at="now",
        )
        reset_otp_state_on_row(row)
        self.assertIsNone(row.otp_token_hash)
        self.assertIsNone(row.otp_salt)
        self.assertIsNone(row.otp_hash)
        self.assertIsNone(row.otp_expires_at)
        self.assertEqual(row.otp_attempts, 0)
        self.assertEqual(row.otp_verified, 0)
        self.assertIsNone(row.otp_verified_at)


if __name__ == "__main__":
    unittest.main()
