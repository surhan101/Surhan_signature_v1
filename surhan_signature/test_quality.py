import unittest

from surhan_signature.quality import api_metrics


class QualityTelemetryTests(unittest.TestCase):
    def test_metrics_parse_the_real_api(self):
        metrics = api_metrics()
        self.assertGreater(metrics["lines"], 1000)
        self.assertGreater(metrics["top_level_functions"], 100)

    def test_known_cmd_callers_are_compatible(self):
        metrics = api_metrics()
        self.assertTrue(metrics["cmd_compatibility_ok"], metrics["cmd_compatibility_missing"])

    def test_only_required_version_chains_remain(self):
        metrics = api_metrics()
        self.assertEqual(metrics["duplicate_function_names"], 7)


if __name__ == "__main__":
    unittest.main()
