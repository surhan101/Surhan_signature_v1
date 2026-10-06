import base64
import io
import unittest
from unittest.mock import patch

from PIL import Image

from surhan_signature.security.content import decode_signature_image, sanitize_document_html
from surhan_signature.security.outbound import UnsafeOutboundURL, validate_outbound_url


class Phase3SecurityTests(unittest.TestCase):
    def test_private_and_metadata_hosts_are_rejected(self):
        for value in ("http://127.0.0.1/x", "http://169.254.169.254/latest", "http://[::1]/"):
            with self.assertRaises(UnsafeOutboundURL):
                validate_outbound_url(value)

    @patch("surhan_signature.security.outbound.socket.getaddrinfo")
    def test_public_https_is_accepted(self, lookup):
        lookup.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        self.assertEqual(validate_outbound_url("https://example.com/hook"), "https://example.com/hook")

    def test_html_active_content_is_removed(self):
        cleaned = sanitize_document_html('<p onclick="x()">ok</p><script>alert(1)</script><img src=x>')
        self.assertNotIn("onclick", cleaned)
        self.assertNotIn("<script", cleaned)
        self.assertNotIn("<img", cleaned)

    def test_extension_spoofing_is_rejected(self):
        with self.assertRaises(ValueError):
            decode_signature_image("fake.png", base64.b64encode(b"not an image").decode())

    def test_real_png_is_accepted(self):
        output = io.BytesIO()
        Image.new("RGB", (2, 2), "white").save(output, format="PNG")
        ext, raw = decode_signature_image("signature.png", base64.b64encode(output.getvalue()).decode())
        self.assertEqual(ext, "png")
        self.assertTrue(raw.startswith(b"\x89PNG"))


if __name__ == "__main__":
    unittest.main()
