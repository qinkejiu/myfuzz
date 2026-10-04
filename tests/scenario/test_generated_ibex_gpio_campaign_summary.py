"""Static accounting checks for the timed generated Ibex GPIO campaign."""

from __future__ import annotations

import unittest

from scripts.runs.run_generated_ibex_two_gpio_10min import (
    _case_counts, _mark_replay_error)


class GeneratedIbexGpioCampaignSummaryTests(unittest.TestCase):
    def test_scheduler_and_chain_completion_and_replay_counts_are_distinct(self):
        cases = [
            {"status": "complete", "coverage": {"chain_complete": True},
             "replay_attempted": True, "replay_skipped": False,
             "replay_matches": True, "replay_error": None},
            {"status": "complete", "coverage": {"chain_complete": False},
             "replay_attempted": False, "replay_skipped": True,
             "replay_matches": None, "replay_error": None},
            {"status": "complete", "coverage": {"chain_complete": True},
             "replay_attempted": True, "replay_skipped": False,
             "replay_matches": None, "replay_error": {"type": "RuntimeError"}},
        ]
        counts = _case_counts(cases)
        self.assertEqual(3, counts["complete"])
        self.assertEqual(3, counts["scheduler_complete"])
        self.assertEqual(2, counts["chain_complete"])
        self.assertEqual(2, counts["replay_attempted"])
        self.assertEqual(1, counts["replay_skipped"])
        self.assertEqual(1, counts["replay_matches"])
        self.assertEqual(1, counts["replay_errors"])

    def test_replay_exception_keeps_record_status_and_reports_error(self):
        report = {"status": "complete", "failure_class": None,
                  "replay_attempted": True, "replay_matches": None,
                  "replay_error": None}
        _mark_replay_error(report, RuntimeError("lost reply"))
        self.assertEqual("complete", report["status"])
        self.assertEqual("replay_error", report["failure_class"])
        self.assertEqual({"type": "RuntimeError", "message": "lost reply"},
                         report["replay_error"])


if __name__ == "__main__":
    unittest.main()
