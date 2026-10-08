"""CV32E40P declarations reuse the shared generated OBI runtime contract."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.interface_description import load_interface_description
from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_harness,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/cpus/cv32e40p/component_profile.json"
INTERFACE = ROOT / "configs/cpus/cv32e40p/official_core_interface_description.json"


class Cv32e40pObiProfileTests(unittest.TestCase):
    def test_official_manifest_include_roots_reach_generated_build(self) -> None:
        expected = ("rtl/include", "bhv", "bhv/include", "sva")
        request = load_local_harness_request({
            "schema_version": "local_harness.v1",
            "profile_path": "configs/cpus/cv32e40p/component_profile.json",
            "instance_id": "cv32e40p_test",
            "reset_assert_ticks": 8,
            "reset_release_ticks": 8,
            "max_wait_cycles": 16,
        })
        plan = plan_local_harness(request, base_dir=ROOT)
        self.assertEqual(expected, plan.facts.include_roots)
        self.assertIn("rtl/cv32e40p_core.sv", dict(plan.parameter_sources))
        rendered = render_local_harness(plan)
        self.assertEqual(
            [f"external_designs/cv32e40p/{root}" for root in expected],
            rendered.build_document["include_roots"],
        )

    def test_source_lock_parameters_match_profile_types_and_values(self) -> None:
        profile_doc = json.loads(PROFILE.read_text(encoding="utf-8"))
        lock_doc = json.loads((ROOT / "configs/soc/sources.lock.json").read_text(
            encoding="utf-8"))
        record = next(row for row in lock_doc["components"]
                      if row["id"] == "cv32e40p")
        profile_values = {row["name"]: row["value"]
                          for row in profile_doc["source"]["elaboration"]["parameters"]}
        locked_values = {row["name"]: row["value"]
                         for row in record["typed_parameters"]}
        self.assertEqual(profile_values, locked_values)
        self.assertTrue(all(type(value) is str for value in locked_values.values()))

    def test_profile_uses_the_registered_official_pin_and_shared_obi_roles(self) -> None:
        profile = load_component_profile(PROFILE)
        interface = load_interface_description(INTERFACE)
        interface_endpoints = {endpoint.endpoint_id: endpoint for endpoint in interface.endpoints}

        self.assertEqual("cv32e40p", profile.component_id)
        self.assertEqual("external_designs/cv32e40p", profile.source.source_root)
        self.assertEqual("git:6033d2b1be3295ec774d17ac4cf226faacfdeb08",
                         profile.source.revision)
        self.assertEqual(
            set(),
            {endpoint.function for endpoint in profile.endpoints
             if endpoint.function in {"clock", "reset"}},
            "clock and reset are represented by clocks/resets, not duplicate endpoints",
        )
        irq_actions = tuple(action for action in profile.port_actions
                            if action.port == "irq_i")
        self.assertEqual((tuple(range(0, 11)), tuple(range(12, 32))),
                         tuple(action.bits for action in irq_actions))
        self.assertEqual(("constant", "constant"),
                         tuple(action.action for action in irq_actions))
        self.assertEqual((0, 0), tuple(action.value for action in irq_actions))
        self.assertEqual(("obi", "1"), interface_endpoints["processor.instruction"].protocol)
        self.assertEqual(("obi", "1"), interface_endpoints["processor.data"].protocol)
        self.assertEqual(
            {"req", "gnt", "addr", "rvalid", "rdata"},
            {field.role for field in profile.endpoint("processor.instruction").fields},
        )
        self.assertEqual(
            {"req", "gnt", "addr", "we", "wdata", "be", "rvalid", "rdata"},
            {field.role for field in profile.endpoint("processor.data").fields},
        )
        self.assertFalse(profile.capabilities["error_response"])
        self.assertTrue(profile.capabilities["byte_enable"])


if __name__ == "__main__":
    unittest.main()
