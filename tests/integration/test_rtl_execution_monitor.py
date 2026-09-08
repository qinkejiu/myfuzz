import unittest

from myfuzz.integration.rtl_execution_monitor import validate_execution


class RtlExecutionMonitorTests(unittest.TestCase):
    def test_accepts_complete_cpu_and_peripheral_progress(self):
        metrics = {
            "cycles": 80,
            "requests": 11,
            "successful_reads": 10,
            "progress_events": 10,
            "completions": 11,
            "pass_completions": 1,
            "errors": 0,
            "first_fetch_matched": 1,
        }
        self.assertEqual(metrics, validate_execution(metrics))

    def test_rejects_each_incomplete_execution_fact(self):
        valid = {
            "cycles": 80,
            "requests": 11,
            "successful_reads": 10,
            "progress_events": 2,
            "completions": 11,
            "pass_completions": 1,
            "errors": 0,
            "first_fetch_matched": 1,
        }
        invalid = {
            "first_fetch_matched": 0,
            "progress_events": 1,
            "completions": 0,
            "pass_completions": 0,
            "errors": 1,
        }
        for key, value in invalid.items():
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "execution acceptance failed"
            ):
                validate_execution({**valid, key: value})


if __name__ == "__main__":
    unittest.main()
