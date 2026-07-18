import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.adaptive_mutation_v4 import (  # noqa: E402
    AdaptiveMutationController, MutationCandidate, MutationConfig, MutationLevel,
    ProtocolLaneScheduler, protocol_campaign_policy,
)
from myfuzz.builder.rawbits_v4 import RawBitsV4Lane  # noqa: E402


def candidate(index: int, level=MutationLevel.L0):
    return MutationCandidate("parent", "flip", index, f"payload-{index}", level, 1)


class AdaptiveMutationTest(unittest.TestCase):
    def test_protocol_scheduler_keeps_frozen_mix_and_b_is_raw(self):
        scheduler = ProtocolLaneScheduler(protocol_campaign_policy("C"))
        lanes = [scheduler.choose() for _ in range(10)]
        self.assertEqual(lanes.count(RawBitsV4Lane.PROTOCOL_WAVEFORM), 8)
        self.assertEqual(lanes.count(RawBitsV4Lane.ADVERSARIAL_MUTATION), 2)
        b_scheduler = ProtocolLaneScheduler(protocol_campaign_policy("B"))
        self.assertEqual([b_scheduler.choose() for _ in range(2)], [RawBitsV4Lane.RAW_ESCAPE] * 2)

    def test_stall_upgrade_and_branch_downgrade_cooldown(self):
        controller = AdaptiveMutationController(7)
        for _ in range(32):
            controller.observe_result(0)
        self.assertEqual(controller.level, MutationLevel.L1)
        controller.observe_result(1)
        self.assertEqual(controller.level, MutationLevel.L0)
        self.assertEqual(controller.state.cooldown, 8)
        for _ in range(8):
            controller.observe_result(0)
        self.assertEqual(controller.level, MutationLevel.L0)

    def test_deterministic_acceptance_and_bounded_pool(self):
        config = MutationConfig(exploration_capacity=3, acceptance_numerators=(32, 32, 32))
        first = AdaptiveMutationController(11, config)
        second = AdaptiveMutationController(11, config)
        results1 = [first.record(candidate(i), new_branch=False) for i in range(8)]
        results2 = [second.record(candidate(i), new_branch=False) for i in range(8)]
        self.assertEqual(results1, results2)
        self.assertEqual(len(first.exploration), 3)

    def test_primary_corpus_is_permanent_and_site_bound_is_enforced(self):
        controller = AdaptiveMutationController(1)
        root = candidate(0)
        self.assertTrue(controller.record(root, new_branch=True))
        self.assertEqual(len(controller.primary), 1)
        with self.assertRaisesRegex(Exception, "site bound"):
            controller.record(MutationCandidate("p", "x", 1, "d", MutationLevel.L0, 2), new_branch=False)

    def test_diagnostics_account_for_levels_transitions_and_checkpoint_resume(self):
        config = MutationConfig(
            stall_threshold=2, cooldown_tests=1,
            exploration_capacity=2, acceptance_numerators=(32, 32, 32),
        )
        controller = AdaptiveMutationController(19, config)
        for new_count in (0, 0, 0, 0, 1, 0, 0):
            controller.observe_result(new_count)
        controller.record(candidate(1), new_branch=True)
        controller.record(candidate(2), new_branch=False)
        controller.choose_exploration()

        diagnostics = controller.diagnostics()
        self.assertEqual(diagnostics["observed_results"], 7)
        self.assertEqual(diagnostics["new_branch_results"], 1)
        self.assertEqual(diagnostics["no_new_branch_results"], 6)
        self.assertEqual(diagnostics["cooldown_results"], 1)
        self.assertEqual(diagnostics["level_before_counts"], {
            "L0": 2, "L1": 4, "L2": 1,
        })
        self.assertEqual(diagnostics["transition_counts"], {
            "L0_TO_L1": 1, "L1_TO_L2": 2,
            "L2_TO_L1": 1, "L1_TO_L0": 0,
        })
        self.assertEqual(diagnostics["primary_insertions"], 1)
        self.assertEqual(diagnostics["exploration_insertions"], 1)
        self.assertEqual(diagnostics["exploration_selections"], 1)
        self.assertEqual(diagnostics["final_state"]["level"], "L2")

        restored = AdaptiveMutationController.from_checkpoint(controller.checkpoint())
        self.assertEqual(restored.diagnostics(), diagnostics)
        controller.observe_result(0)
        restored.observe_result(0)
        self.assertEqual(restored.diagnostics(), controller.diagnostics())

    def test_transition_history_is_bounded_but_total_counts_are_exact(self):
        controller = AdaptiveMutationController(
            23, MutationConfig(stall_threshold=1, cooldown_tests=0),
        )
        for _ in range(40):
            controller.observe_result(0)
            controller.observe_result(0)
            controller.observe_result(1)
            controller.observe_result(1)
        diagnostics = controller.diagnostics()
        self.assertGreater(diagnostics["transition_event_count"], 64)
        self.assertEqual(len(diagnostics["recent_transition_events"]), 64)
        self.assertTrue(diagnostics["transition_events_truncated"])
        self.assertEqual(
            sum(diagnostics["transition_counts"].values()),
            diagnostics["transition_event_count"],
        )

    def test_new_branch_promotes_exploration_ancestor_chain(self):
        controller = AdaptiveMutationController(
            29, MutationConfig(acceptance_numerators=(32, 32, 32)),
        )
        parent = MutationCandidate(
            "", "seed", 0, "parent", MutationLevel.L0, 0,
        )
        child = MutationCandidate(
            "parent", "bit_flip", 3, "child", MutationLevel.L0, 1,
            generation=1,
        )
        self.assertTrue(controller.record(parent, new_branch=False))
        self.assertTrue(controller.record(child, new_branch=True))
        self.assertEqual(len(controller.primary), 2)
        self.assertEqual(len(controller.exploration), 0)
        self.assertEqual(controller.diagnostics()["promoted_ancestors"], 1)


if __name__ == "__main__":
    unittest.main()
