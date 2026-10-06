import unittest

from surhan_signature.security.policy import classify


class AccessPolicyTests(unittest.TestCase):
    def test_unrelated_apps_are_ignored(self):
        self.assertEqual(classify("frappe.client.get"), "unrelated")

    def test_public_signing_flow_is_explicit(self):
        self.assertEqual(classify("surhan_signature.api.request_otp"), "public")
        self.assertEqual(classify("surhan_signature.api.sign_typed"), "public")

    def test_self_service_requires_login(self):
        self.assertEqual(classify("surhan_signature.api.get_my_signature_profile"), "self")

    def test_business_method_has_signature_user_policy(self):
        self.assertEqual(classify("surhan_signature.api.create_envelope"), "signature_user")

    def test_unknown_method_fails_closed(self):
        self.assertEqual(classify("surhan_signature.api.future_dangerous_method"), "admin")


if __name__ == "__main__":
    unittest.main()
