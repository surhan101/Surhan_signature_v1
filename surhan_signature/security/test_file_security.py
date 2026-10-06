import unittest

from surhan_signature.security.file_security import (
    PrivateArtifactExposure,
    assert_public_payload_safe,
    private_urls_in_payload,
)


class FileSecurityTests(unittest.TestCase):
    def test_nested_private_url_is_detected(self):
        leaks = private_urls_in_payload(
            {"certificate": {"files": ["/private/files/certificate.pdf"]}}
        )
        self.assertEqual(leaks[0]["path"], "$.certificate.files[0]")

    def test_private_url_embedded_in_text_is_detected(self):
        leaks = private_urls_in_payload({"message": "download /private/files/a.zip"})
        self.assertEqual(len(leaks), 1)

    def test_public_payload_is_accepted(self):
        payload = {"valid": True, "verification_url": "/verify?id=ABC"}
        self.assertIs(assert_public_payload_safe(payload), payload)

    def test_private_payload_fails_closed(self):
        with self.assertRaises(PrivateArtifactExposure):
            assert_public_payload_safe({"signed_pdf": "/private/files/signed.pdf"})
