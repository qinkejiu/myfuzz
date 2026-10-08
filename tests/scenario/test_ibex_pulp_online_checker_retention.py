"""The online checker must not retain every case's event suffix."""

import unittest

from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
from myfuzz.scenario.session_runtime import OnlineCaseReceipt


def receipt(case_id, events):
    return OnlineCaseReceipt(case_id, 0, len(events), tuple(events),
                             {"cpu": 0}, {"cpu": len(events)}, "running")


class IbexPulpOnlineCheckerRetentionTest(unittest.TestCase):
    def test_retry_accepts_same_events_without_retaining_suffix(self):
        checker = IbexPulpOnlineChecker()
        events = ({"event_id": 1, "kind": "noop", "payload": {"bytes": [1, 2, 3]}},)
        self.assertEqual(checker(receipt("case-1", events)), ())
        self.assertEqual(checker(receipt("case-1", events)), ())
        count, digest, result = checker._case_results["case-1"]
        self.assertEqual(count, 1)
        self.assertEqual(len(digest), 64)
        self.assertEqual(result, ())
        self.assertFalse(any(isinstance(item, dict) for item in
                             checker._case_results["case-1"]))

    def test_retry_rejects_tampered_nested_event_and_count(self):
        checker = IbexPulpOnlineChecker()
        events = ({"event_id": 1, "kind": "noop", "payload": {"bytes": [1, 2, 3]}},)
        checker(receipt("case-1", events))
        with self.assertRaisesRegex(ValueError, "identity reused"):
            checker(receipt("case-1", ({"event_id": 1, "kind": "noop",
                                        "payload": {"bytes": [1, 2, 4]}},)))
        with self.assertRaisesRegex(ValueError, "identity reused"):
            checker(receipt("case-1", events +
                            ({"event_id": 2, "kind": "noop"},)))
        self.assertEqual(checker(receipt("case-2", ({"event_id": 2,
                                                     "kind": "noop"},))), ())


if __name__ == "__main__":
    unittest.main()
