from __future__ import annotations

import copy
import unittest

from myfuzz.harness import HarnessArtifact, build_harness, coverage_universe, raw_width
from myfuzz.harness.abi import build_raw_abi
from myfuzz.harness.depaware import build_depaware
from myfuzz.harness.projection import build_projection_plan


def manifest() -> dict[str, object]:
    return {
        "schema_version": "candidate_manifest.v1",
        "combinational_design": False,
        "candidate_id": "candidate-7",
        "top": {"module": "generated_top", "content_hash": "top-hash"},
        "top_port_abi": [
            {"port_id": 3, "emitted_name": "clock_signal", "direction": "input", "width": 1, "semantic_role": "clock", "active_level": 1, "fuzzable": False},
            {"port_id": 4, "emitted_name": "reset_signal", "direction": "input", "width": 1, "semantic_role": "reset", "active_level": 0, "synchronous": False, "io_meta_reset": True, "fuzzable": False, "reset_value": 0},
            {"port_id": 10, "emitted_name": "data_a", "direction": "input", "width": 8, "semantic_role": "data", "fuzzable": True, "dependency_group": {"kind": "field_group", "components": ["binding", "a"]}},
            {"port_id": 20, "emitted_name": "data_b", "direction": "inout", "width": 4, "semantic_role": "data", "fuzzable": True, "dependency_group": {"kind": "field_group", "components": ["binding", "b"]}},
            {"port_id": 30, "emitted_name": "result", "direction": "output", "width": 16, "semantic_role": "response", "fuzzable": False},
        ],
        "coverage_universe": [{"point_id": 1, "source_id": "s1"}, {"point_id": 2, "source_id": "s2"}],
        "dependency_groups": [
            {"kind": "field_group", "components": ["binding", "a"]},
            {"kind": "field_group", "components": ["binding", "b"]},
        ],
        "retained_dependency_groups": [
            {"kind": "field_group", "components": ["binding", "a"]},
        ],
    }


class HarnessTest(unittest.TestCase):
    def test_all_modes_share_raw_width_and_candidate_identity(self) -> None:
        document = manifest()
        artifacts = {mode: build_harness(document, mode) for mode in ("flat_direct", "candidate_direct", "candidate_depaware")}

        self.assertEqual(12, raw_width(document))
        self.assertEqual({12}, {artifact.raw_width for artifact in artifacts.values()})
        self.assertEqual(artifacts["candidate_direct"].candidate_id, artifacts["candidate_depaware"].candidate_id)
        self.assertEqual(artifacts["candidate_direct"].coverage_universe_id, artifacts["candidate_depaware"].coverage_universe_id)
        self.assertEqual(coverage_universe(document), artifacts["flat_direct"].coverage_universe_id)

    def test_packing_is_stable_and_depaware_retains_abi_bits(self) -> None:
        document = manifest()
        direct = build_harness(document, "candidate_direct")
        depaware = build_harness(document, "candidate_depaware")

        self.assertEqual([(0, 7), (8, 11)], [(use.raw_lo, use.raw_hi) for use in direct.abi.uses])
        self.assertEqual([(0, 7), (8, 11)], [(use.raw_lo, use.raw_hi) for use in depaware.abi.uses])
        self.assertEqual(("direct", "gate"), tuple(use.action for use in depaware.abi.uses))
        self.assertIn("protocol_projection", depaware.source_text)
        self.assertIn("gate", depaware.source_text)
        self.assertNotIn("$random", depaware.source_text)

    def test_candidate_destination_ids_are_top_port_ids_while_flat_ids_are_dense(self) -> None:
        document = manifest()
        candidate_direct = build_harness(document, "candidate_direct")
        candidate_depaware = build_harness(document, "candidate_depaware")
        flat_direct = build_harness(document, "flat_direct")

        self.assertEqual(
            [(10, 10), (20, 20)],
            [
                (destination.destination_id, destination.port_id)
                for destination in candidate_direct.abi.destinations
            ],
        )
        self.assertEqual(
            candidate_direct.abi.destinations,
            candidate_depaware.abi.destinations,
        )
        self.assertEqual(
            [(0, 10), (1, 20)],
            [
                (destination.destination_id, destination.port_id)
                for destination in flat_direct.abi.destinations
            ],
        )
        self.assertIn("assign port_10 = rfuzz_input_bits[7:0];", candidate_direct.source_text)
        self.assertIn("assign port_20 = rfuzz_input_bits[11:8];", candidate_direct.source_text)

    def test_depaware_sv_preserves_same_destination_actions_and_delay_release(self) -> None:
        document = manifest()
        plan = build_projection_plan(
            build_raw_abi(document),
            (
                {
                    "action_id": 1,
                    "destination_id": 10,
                    "kind": "fold_xor",
                    "category": "dependency_consistency",
                },
                {
                    "action_id": 2,
                    "destination_id": 10,
                    "kind": "delay_select",
                    "category": "progress",
                    "max_cycles": 2,
                },
            ),
        )

        artifact = build_depaware(document, plan)

        self.assertEqual(
            ("fold_xor", "delay_select"),
            tuple(action.kind for action in plan.actions if action.destination_id == 10),
        )
        self.assertIn("// action 1 fold_xor", artifact.source_text)
        self.assertIn("// action 2 delay_select", artifact.source_text)
        self.assertIn(">> 4", artifact.source_text)
        self.assertIn("<= 1", artifact.source_text)
        self.assertNotIn("timeout_count <= timeout_count + 1'b1;", artifact.source_text)

    def test_rejects_unknown_mode_and_structural_manifest_errors(self) -> None:
        with self.assertRaises(ValueError):
            build_harness(manifest(), "candidate_random")

        cases = []
        unbound = manifest()
        unbound["fields"] = [{"field_id": 1, "port_id": 999, "width": 1}]
        cases.append(unbound)
        multiple = manifest()
        multiple["top_port_abi"][2]["driver_count"] = 2
        cases.append(multiple)
        mismatch = manifest()
        mismatch["external_ports"] = [{"port_id": 10, "direction": "input", "width": 7}]
        cases.append(mismatch)
        bad_reset = manifest()
        bad_reset["top_port_abi"][1]["reset_value"] = 2
        cases.append(bad_reset)
        bad_group = manifest()
        bad_group["top_port_abi"][2]["dependency_group"] = {"kind": "field_group", "components": ["missing", "group"]}
        cases.append(bad_group)

        for document in cases:
            with self.assertRaises(ValueError):
                build_harness(document, "candidate_direct")

    def test_requires_explicit_control_declarations(self) -> None:
        missing_role = manifest()
        missing_role["top_port_abi"][0].pop("semantic_role")
        with self.assertRaises(ValueError):
            build_harness(missing_role, "candidate_direct")

        missing_active_level = manifest()
        missing_active_level["top_port_abi"][1].pop("active_level")
        with self.assertRaises(ValueError):
            build_harness(missing_active_level, "candidate_direct")

        contradictory_reset = manifest()
        contradictory_reset["top_port_abi"][1]["active_level"] = 1
        with self.assertRaises(ValueError):
            build_harness(contradictory_reset, "candidate_direct")

        missing_mapping = manifest()
        missing_mapping["top_port_abi"][2].pop("emitted_name")
        with self.assertRaises(ValueError):
            build_harness(missing_mapping, "candidate_direct")

        duplicate_mapping = manifest()
        duplicate_mapping["top_port_abi"][2]["emitted_name"] = duplicate_mapping["top_port_abi"][3]["emitted_name"]
        with self.assertRaises(ValueError):
            build_harness(duplicate_mapping, "candidate_direct")

        combinational = manifest()
        combinational["combinational_design"] = True
        combinational["top_port_abi"] = [port for port in combinational["top_port_abi"] if port["port_id"] not in {3, 4}]
        artifact = build_harness(combinational, "candidate_direct")
        self.assertNotIn("input logic clock", artifact.source_text)
        self.assertNotIn("input logic reset", artifact.source_text)
        self.assertNotIn("io_meta_reset", artifact.source_text)

    def test_rejects_input_without_explicit_fuzz_disposition(self) -> None:
        missing_fuzz_disposition = manifest()
        missing_fuzz_disposition["top_port_abi"][2].pop("fuzzable")
        with self.assertRaisesRegex(ValueError, "fuzz disposition must be explicit"):
            build_harness(missing_fuzz_disposition, "candidate_direct")

    def test_reordering_manifest_records_does_not_change_abi(self) -> None:
        document = manifest()
        reordered = copy.deepcopy(document)
        reordered["top_port_abi"] = list(reversed(reordered["top_port_abi"]))
        reordered["dependency_groups"] = list(reversed(reordered["dependency_groups"]))
        reordered["coverage_universe"] = list(reversed(reordered["coverage_universe"]))

        self.assertEqual(build_harness(document, "candidate_direct").abi, build_harness(reordered, "candidate_direct").abi)
        self.assertEqual(coverage_universe(document), coverage_universe(reordered))


if __name__ == "__main__":
    unittest.main()
