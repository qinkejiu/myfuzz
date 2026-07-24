from __future__ import annotations

import unittest

from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.projection import (
    ProjectionState,
    build_projection_plan,
    project_sample,
)


def raw_abi() -> RawBitAbi:
    destinations = (
        RawDestination(0, 100, 10, 1),
        RawDestination(1, 100, 11, 4),
    )
    uses = (
        RawBitUse(0, 0, 0, 0, "direct", "direct"),
        RawBitUse(1, 4, 1, 0, "direct", "direct"),
    )
    document = {
        "raw_width": 5,
        "destinations": [
            {
                "destination_id": item.destination_id,
                "component_id": item.component_id,
                "port_id": item.port_id,
                "width": item.width,
            }
            for item in destinations
        ],
        "uses": [
            {
                "raw_lo": item.raw_lo,
                "raw_hi": item.raw_hi,
                "destination_id": item.destination_id,
                "destination_lo": item.destination_lo,
                "action": item.action,
                "category": item.category,
            }
            for item in uses
        ],
    }
    return RawBitAbi(5, destinations, uses, content_hash(document))


class ProjectionTest(unittest.TestCase):
    def test_project_sample_reassembles_fragmented_destination_slices(self) -> None:
        fragmented = RawBitAbi(
            raw_width=4,
            destinations=(RawDestination(7, 100, 10, 4),),
            uses=(
                RawBitUse(0, 1, 7, 2, "direct", "direct"),
                RawBitUse(2, 3, 7, 0, "direct", "direct"),
            ),
            abi_hash=content_hash({"fixture": "fragmented-destination"}),
        )
        plan = build_projection_plan(fragmented, ())

        result = project_sample(plan, 0b1001, ProjectionState.initial(plan))

        self.assertEqual(((7, 0b0110),), result.driven_fields)

    def test_projection_is_deterministic_and_preserves_raw_geometry(self) -> None:
        direct = raw_abi()
        plan = build_projection_plan(
            direct,
            (
                {
                    "action_id": 10,
                    "destination_id": 0,
                    "kind": "gate",
                    "category": "protocol_legality",
                    "max_cycles": 2,
                },
                {
                    "action_id": 11,
                    "destination_id": 1,
                    "kind": "fold_xor",
                    "category": "dependency_consistency",
                },
            ),
        )
        initial = ProjectionState.initial(plan)

        first = project_sample(plan, raw_value=0b10111, state=initial)
        repeated = project_sample(plan, raw_value=0b10111, state=initial)

        self.assertEqual(first, repeated)
        self.assertEqual(1, first.cycles_consumed)
        self.assertTrue(first.sample_consumed)
        self.assertLessEqual(first.next_state.value.bit_length(), plan.max_state_bits)
        self.assertEqual(direct.raw_width, plan.raw_abi.raw_width)
        self.assertEqual(
            [(use.raw_lo, use.raw_hi, use.destination_id) for use in direct.uses],
            [(use.raw_lo, use.raw_hi, use.destination_id) for use in plan.raw_abi.uses],
        )
        self.assertNotEqual(dict(first.driven_fields)[1], 0b1011)

    def test_temporal_gate_holds_then_times_out_with_bounded_counters(self) -> None:
        plan = build_projection_plan(
            raw_abi(),
            (
                {
                    "action_id": 1,
                    "destination_id": 0,
                    "kind": "gate",
                    "category": "protocol_legality",
                    "max_cycles": 2,
                },
            ),
        )

        first = project_sample(plan, 0b00001, ProjectionState.initial(plan))
        held = project_sample(plan, 0b00000, first.next_state)
        timed_out = project_sample(plan, 0b00000, held.next_state)

        self.assertEqual(1, dict(first.driven_fields)[0])
        self.assertEqual(1, dict(held.driven_fields)[0])
        self.assertEqual(1, dict(held.correction_counts)["protocol_legality"])
        self.assertEqual(0, held.timeout_count)
        self.assertEqual(1, timed_out.timeout_count)
        self.assertEqual(1, timed_out.violation_count)
        self.assertEqual(1, timed_out.no_progress_count)
        self.assertTrue(any(event == "timeout" for _, event in timed_out.protocol_events))
        self.assertEqual(0, timed_out.next_state.value)

    def test_delay_select_suppresses_then_releases_without_timeout(self) -> None:
        plan = build_projection_plan(
            raw_abi(),
            (
                {
                    "action_id": 1,
                    "destination_id": 0,
                    "kind": "delay_select",
                    "category": "progress",
                    "max_cycles": 2,
                },
            ),
        )

        started = project_sample(plan, 0b00001, ProjectionState.initial(plan))
        delayed = project_sample(plan, 0, started.next_state)
        released = project_sample(plan, 0, delayed.next_state)

        self.assertEqual(0, dict(started.driven_fields)[0])
        self.assertEqual(0, dict(delayed.driven_fields)[0])
        self.assertEqual(1, dict(released.driven_fields)[0])
        self.assertEqual(0, released.timeout_count)
        self.assertEqual(0, released.violation_count)
        self.assertIn((0, "release"), released.protocol_events)
        self.assertEqual(0, released.next_state.value)

    def test_rejects_unbounded_rules_invalid_values_and_state_width(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite max_cycles"):
            build_projection_plan(
                raw_abi(),
                (
                    {
                        "action_id": 1,
                        "destination_id": 0,
                        "kind": "gate",
                        "category": "protocol_legality",
                    },
                ),
            )

        plan = build_projection_plan(raw_abi(), ())
        with self.assertRaisesRegex(ValueError, "raw_value"):
            project_sample(plan, 1 << plan.raw_abi.raw_width, ProjectionState.initial(plan))
        with self.assertRaisesRegex(ValueError, "state width"):
            project_sample(plan, 0, ProjectionState(0, plan.max_state_bits + 1))

    def test_rejects_state_and_group_caps(self) -> None:
        with self.assertRaisesRegex(ValueError, "4096"):
            build_projection_plan(raw_abi(), (), max_state_bits=4097)
        with self.assertRaisesRegex(ValueError, "64"):
            build_projection_plan(raw_abi(), (), field_order=tuple(range(65)))


if __name__ == "__main__":
    unittest.main()
