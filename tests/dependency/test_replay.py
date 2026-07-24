from __future__ import annotations

import unittest

from myfuzz.dependency.replay import ReplayObservation, ReplayQueue


class ReplayObservationTest(unittest.TestCase):
    def test_observation_is_conclusive_only_when_all_runtime_guards_hold(self) -> None:
        observation = ReplayObservation("cov", frozenset({"progress"}))
        self.assertTrue(observation.conclusive)

        for field in ("reset_stable", "timed_out", "crashed", "reproducible"):
            values = {"reset_stable": True, "timed_out": False, "crashed": False, "reproducible": True}
            values[field] = not values[field]
            current = ReplayObservation("cov", frozenset({"progress"}), **values)
            self.assertFalse(current.conclusive, field)

    def test_queue_retains_newest_records_with_deterministic_capacity(self) -> None:
        queue = ReplayQueue(2)
        queue.append(ReplayObservation("a"))
        queue.append(ReplayObservation("b"))
        queue.append(ReplayObservation("c"))
        self.assertEqual(("b", "c"), tuple(item.coverage_signature for item in queue.items))
        self.assertEqual(2, queue.capacity)

    def test_queue_rejects_non_positive_capacity(self) -> None:
        with self.assertRaises(ValueError):
            ReplayQueue(0)


if __name__ == "__main__":
    unittest.main()
