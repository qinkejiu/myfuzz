from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from myfuzz.experiments import (
    CONSERVATIVE_PROFILE,
    ResourceProfileError,
    apply_resource_profile,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "experiments" / "rvx.json"
MIB = 1024 * 1024


def load_config() -> dict[str, object]:
    document = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


class ResourcePolicyTests(unittest.TestCase):
    def test_conservative_profile_is_deterministic_and_does_not_mutate_input(self) -> None:
        original = load_config()
        before = deepcopy(original)

        constrained = apply_resource_profile(original)

        self.assertEqual(before, original)
        self.assertEqual(1, constrained["candidate_selection"]["k"])
        self.assertEqual([1], constrained["candidate_pair"]["seeds"])
        self.assertEqual(
            [{"name": "smoke", "kind": "cycles", "value": 1000}],
            constrained["budgets"],
        )
        self.assertEqual(1, constrained["build_concurrency"])
        self.assertFalse(constrained["waveforms"])
        self.assertEqual(32, constrained["replay_queue_capacity"])
        self.assertEqual(512, constrained["event_ring_capacity"])
        self.assertEqual(16, constrained["field_groups_per_batch"])
        self.assertEqual(512 * MIB, constrained["soft_memory_bytes"])
        self.assertEqual(768 * MIB, constrained["hard_memory_bytes"])
        self.assertEqual(64_000_000, constrained["token_bytes"])

    def test_token_bytes_above_profile_ceiling_is_reduced(self) -> None:
        config = load_config()
        config["token_bytes"] = 128 * MIB

        constrained = apply_resource_profile(config)

        self.assertEqual(64 * MIB, constrained["token_bytes"])

    def test_profile_preserves_stricter_input_limits(self) -> None:
        config = load_config()
        config["candidate_selection"]["k"] = 1
        config["candidate_pair"]["seeds"] = [19]
        config["budgets"] = [{"name": "smoke", "kind": "cycles", "value": 100}]
        config["replay_queue_capacity"] = 4
        config["event_ring_capacity"] = 8
        config["field_groups_per_batch"] = 2
        config["soft_memory_bytes"] = 128 * MIB
        config["hard_memory_bytes"] = 256 * MIB
        config["token_bytes"] = 16 * MIB

        constrained = apply_resource_profile(config)

        self.assertEqual(1, constrained["candidate_selection"]["k"])
        self.assertEqual([19], constrained["candidate_pair"]["seeds"])
        self.assertEqual(config["budgets"], constrained["budgets"])
        self.assertEqual(4, constrained["replay_queue_capacity"])
        self.assertEqual(8, constrained["event_ring_capacity"])
        self.assertEqual(2, constrained["field_groups_per_batch"])
        self.assertEqual(128 * MIB, constrained["soft_memory_bytes"])
        self.assertEqual(256 * MIB, constrained["hard_memory_bytes"])
        self.assertEqual(16 * MIB, constrained["token_bytes"])

    def test_missing_smoke_budget_fails_closed(self) -> None:
        config = load_config()
        config["budgets"] = [{"name": "short", "kind": "seconds", "value": 30}]

        with self.assertRaisesRegex(ResourceProfileError, "smoke"):
            apply_resource_profile(config)

    def test_malformed_non_smoke_budget_fails_closed(self) -> None:
        config = load_config()
        config["budgets"] = [
            {"name": "smoke", "kind": "cycles", "value": 1000},
            {"name": "short", "kind": "minutes", "value": 30},
        ]

        with self.assertRaisesRegex(ResourceProfileError, "budget kind"):
            apply_resource_profile(config)

    def test_invalid_input_memory_policy_fails_closed(self) -> None:
        config = load_config()
        config["soft_memory_bytes"] = 256 * MIB
        config["hard_memory_bytes"] = 128 * MIB

        with self.assertRaisesRegex(ResourceProfileError, "soft_memory_bytes"):
            apply_resource_profile(config)

    def test_profile_memory_override_must_remain_ordered(self) -> None:
        with self.assertRaises(ResourceProfileError):
            replace(
                CONSERVATIVE_PROFILE,
                soft_memory_bytes=768 * MIB,
                hard_memory_bytes=512 * MIB,
            )


if __name__ == "__main__":
    unittest.main()
