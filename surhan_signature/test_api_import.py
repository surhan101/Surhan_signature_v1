import importlib
import unittest


class LegacyAPIImportTests(unittest.TestCase):
    def test_api_imports_and_critical_entry_points_are_callable(self):
        api = importlib.import_module("surhan_signature.api")

        critical = (
            "request_otp",
            "verify_otp",
            "phase27e_operations_data",
            "phase27g_signature_inbox_data",
        )

        for name in critical:
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(api, name, None)))


if __name__ == "__main__":
    unittest.main()
