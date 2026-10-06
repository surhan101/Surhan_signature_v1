import unittest

from surhan_signature.signing.decline import (
    MAX_DECLINE_REASON_LENGTH,
    normalize_decline_reason,
)


class DeclineValidationTests(unittest.TestCase):
    def test_empty_reason_uses_safe_default(self):
        self.assertEqual(normalize_decline_reason("   "), "No reason provided.")

    def test_control_characters_are_removed(self):
        self.assertEqual(normalize_decline_reason("Not\x00 approved"), "Not approved")

    def test_reason_length_is_bounded(self):
        with self.assertRaises(ValueError):
            normalize_decline_reason("x" * (MAX_DECLINE_REASON_LENGTH + 1))


if __name__ == "__main__":
    unittest.main()
