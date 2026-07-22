from __future__ import annotations

import unittest

from myfuzz.dependency.dynamic import ShrinkBudget, shrink_groups
from myfuzz.dependency.graph import DependencyGraph, field_group_node
from myfuzz.dependency.replay import ReplayObservation


def graph(*names: str) -> DependencyGraph:
    groups = tuple(field_group_node("binding", name) for name in names)
    return DependencyGraph(groups, groups, (), ())


class DynamicShrinkTest(unittest.TestCase):
    def test_replays_use_identical_seed_and_remove_one_group_at_a_time(self) -> None:
        calls: list[tuple[int, tuple[object, ...], int]] = []

        def replay(seed: int, enabled_groups: tuple[object, ...], cycles: int) -> ReplayObservation:
            calls.append((seed, enabled_groups, cycles))
            return ReplayObservation("coverage", frozenset({"progress"}))

        result = shrink_groups(graph("a", "b"), replay, ShrinkBudget(seed=19, cycles=7, repeat_count=2))

        self.assertEqual((), result.enabled_groups)
        self.assertEqual((field_group_node("binding", "a"), field_group_node("binding", "b")), result.removed_groups)
        self.assertTrue(calls)
        self.assertTrue(all(seed == 19 and cycles == 7 for seed, _, cycles in calls))
        baseline = tuple(field_group_node("binding", name) for name in ("a", "b"))
        self.assertEqual(baseline, calls[0][1])
        self.assertEqual((field_group_node("binding", "b"),), calls[2][1])
        self.assertEqual((), calls[4][1])
        self.assertEqual(len(calls[0][1]) - 1, len(calls[2][1]))
        self.assertEqual(len(calls[2][1]) - 1, len(calls[4][1]))

    def test_coverage_loss_vetoes_candidate(self) -> None:
        target = field_group_node("binding", "b")

        def replay(_seed: int, enabled: tuple[object, ...], _cycles: int) -> ReplayObservation:
            return ReplayObservation("lost" if target not in enabled else "coverage", frozenset({"progress"}))

        result = shrink_groups(graph("a", "b"), replay, ShrinkBudget(repeat_count=2))

        self.assertEqual((field_group_node("binding", "b"),), result.enabled_groups)
        self.assertEqual((field_group_node("binding", "a"),), result.removed_groups)
        self.assertIn("coverage loss", " ".join(result.diagnostics))

    def test_reset_timeout_and_crash_are_inconclusive_and_retain_group(self) -> None:
        group_b = field_group_node("binding", "b")

        def replay(_seed: int, enabled: tuple[object, ...], _cycles: int) -> ReplayObservation:
            if group_b not in enabled:
                return ReplayObservation("coverage", frozenset({"progress"}), timed_out=True)
            return ReplayObservation("coverage", frozenset({"progress"}))

        result = shrink_groups(graph("a", "b"), replay, ShrinkBudget(repeat_count=2))

        self.assertEqual((group_b,), result.enabled_groups)
        self.assertTrue(any("inconclusive" in diagnostic for diagnostic in result.diagnostics))

    def test_baseline_inconclusive_falls_back_to_static_groups(self) -> None:
        calls = 0

        def replay(_seed: int, _enabled: tuple[object, ...], _cycles: int) -> ReplayObservation:
            nonlocal calls
            calls += 1
            return ReplayObservation("coverage", frozenset(), crashed=True)

        result = shrink_groups(graph("a", "b"), replay, ShrinkBudget(repeat_count=2))

        self.assertEqual(result.static_groups, result.enabled_groups)
        self.assertTrue(result.used_static_fallback)
        self.assertEqual(2, calls)

    def test_group_cap_is_64_and_deterministic(self) -> None:
        static = graph(*(f"field-{index:02d}" for index in range(65)))
        seen: list[tuple[object, ...]] = []

        def replay(_seed: int, enabled: tuple[object, ...], _cycles: int) -> ReplayObservation:
            seen.append(enabled)
            return ReplayObservation("coverage", frozenset())

        result = shrink_groups(static, replay, ShrinkBudget(repeat_count=1))

        self.assertEqual(65, len(result.enabled_groups))
        self.assertEqual([], seen)
        self.assertTrue(result.used_static_fallback)
        self.assertIn("64", " ".join(result.diagnostics))


if __name__ == "__main__":
    unittest.main()
