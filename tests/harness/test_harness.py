from __future__ import annotations

import copy
import unittest

from myfuzz.harness import HarnessArtifact, build_harness, coverage_universe, raw_width


def manifest() -> dict[str, object]:
    return {
        "schema_version": "candidate_manifest.v1",
        "candidate_id": "candidate-7",
        "top": {"module": "generated_top", "content_hash": "top-hash"},
        "top_port_abi": [
            {"port_id": 3, "emitted_name": "clock_signal", "direction": "input", "width": 1, "semantic_role": "clock", "fuzzable": False},
            {"port_id": 4, "emitted_name": "reset_signal", "direction": "input", "width": 1, "semantic_role": "reset", "fuzzable": False, "reset_value": 0},
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
