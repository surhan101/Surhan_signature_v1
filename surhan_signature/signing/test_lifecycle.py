from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from surhan_signature.signing.lifecycle import (
    MAX_LIFECYCLE_REASON_LENGTH,
    envelope_is_expired,
    normalize_lifecycle_reason,
)


class LifecyclePolicyTests(unittest.TestCase):
    def test_control_characters_are_removed(self):
        self.assertEqual(normalize_lifecycle_reason("  safe\x00 reason  ", "default"), "safe reason")

    def test_reason_length_is_bounded(self):
        with self.assertRaises(ValueError):
            normalize_lifecycle_reason("x" * (MAX_LIFECYCLE_REASON_LENGTH + 1), "default")

    def test_expiry_boundary_is_terminal(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        self.assertTrue(envelope_is_expired(now, current_time=now))
        self.assertTrue(envelope_is_expired(now - timedelta(seconds=1), current_time=now))
        self.assertFalse(envelope_is_expired(now + timedelta(seconds=1), current_time=now))
