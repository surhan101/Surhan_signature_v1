import unittest

from surhan_signature.signing.transaction import assert_signable_state


class SigningTransactionTests(unittest.TestCase):
    def setUp(self):
        self.recipient = {
            "name": "REC-1",
            "status": "OTP Verified",
            "signed_at": None,
            "token_hash": "token-digest",
            "otp_verified": 1,
        }
        self.envelope = {"name": "ENV-1", "status": "Sent", "locked": 0}

    def test_valid_state_is_accepted(self):
        self.assertIsNone(assert_signable_state(self.recipient, self.envelope))

    def test_duplicate_signature_is_rejected(self):
        self.recipient["status"] = "Signed"
        with self.assertRaisesRegex(ValueError, "already signed"):
            assert_signable_state(self.recipient, self.envelope)

    def test_revoked_token_is_rejected(self):
        self.recipient["token_hash"] = ""
        with self.assertRaisesRegex(ValueError, "no longer active"):
            assert_signable_state(self.recipient, self.envelope)

    def test_missing_otp_is_rejected(self):
        self.recipient["otp_verified"] = 0
        with self.assertRaisesRegex(ValueError, "verified OTP"):
            assert_signable_state(self.recipient, self.envelope)

    def test_locked_envelope_is_rejected(self):
        self.envelope["locked"] = 1
        with self.assertRaisesRegex(ValueError, "completed and locked"):
            assert_signable_state(self.recipient, self.envelope)
