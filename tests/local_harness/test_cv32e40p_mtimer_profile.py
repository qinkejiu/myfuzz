"""The CV32E40P machine-timer profile reuses the generated OBI runtime."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/cpus/cv32e40p_mtimer/component_profile.json"
MEI_PROFILE = ROOT / "configs/cpus/cv32e40p/component_profile.json"


class Cv32e40pMachineTimerProfileTests(unittest.TestCase):
    def test_machine_timer_profile_projects_only_irq7_on_the_generated_obi_runtime(self) -> None:
        self.assertTrue(PROFILE.is_file(), "MTI-only CV32E40P profile is missing")
        profile_document = json.loads(PROFILE.read_text(encoding="utf-8"))
        mei_document = json.loads(MEI_PROFILE.read_text(encoding="utf-8"))
        profile = load_component_profile(PROFILE)

        self.assertEqual("cv32e40p", profile.component_id)
        self.assertEqual(mei_document["source"], profile_document["source"])
        self.assertEqual("cv32e40p_core", profile.source.top_module)

        irq_endpoint = profile.endpoint("processor.interrupts")
        self.assertEqual(
            [("machine_timer", (7, 7), "input", 1)],
            [(field.role, field.bit_range, field.direction, field.width)
             for field in irq_endpoint.fields],
        )
        self.assertEqual("processor.interrupts", profile.cpu.irq_entry_endpoint)
        self.assertEqual("machine_timer", profile.cpu.irq_entry_role)
        self.assertEqual("machine_timer", profile.cpu.irq_semantics)

        constants = [action for action in profile.port_actions
                     if action.port == "irq_i" and action.action == "constant"]
        constant_bits = [bit for action in constants for bit in action.bits]
        expected_constant_bits = [bit for bit in range(32) if bit != 7]
        self.assertEqual(expected_constant_bits, sorted(constant_bits))
        self.assertEqual(31, len(set(constant_bits)))
        self.assertTrue(all(action.value == 0 for action in constants))
        self.assertNotIn(7, constant_bits)
        self.assertEqual(list(range(32)), sorted([*constant_bits, 7]))

        request = load_local_harness_request({
            "schema_version": "local_harness.v1",
            "profile_path": "configs/cpus/cv32e40p_mtimer/component_profile.json",
            "instance_id": "cv32e40p_mtimer_contract",
            "reset_assert_ticks": 8,
            "reset_release_ticks": 8,
            "max_wait_cycles": 16,
        })
        plan = plan_local_harness(request, base_dir=ROOT)
        runtime = render_local_runtime(
            plan,
            render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT),
            base_dir=ROOT,
        )
        self.assertEqual("obi_cpu", runtime.runtime_document["kind"])
        irq_exports = [row for row in runtime.runtime_document["physical_exports"]
                       if row.get("physical_port") == "irq_i"
                       and row.get("disposition") == "functional"]
        self.assertEqual(1, len(irq_exports))
        self.assertEqual(
            (7, 7, 1, "input"),
            (irq_exports[0]["bit_lo"], irq_exports[0]["bit_hi"],
             irq_exports[0]["width"], irq_exports[0]["direction"]),
        )
        self.assertEqual("machine_timer", irq_exports[0]["role"])


if __name__ == "__main__":
    unittest.main()
