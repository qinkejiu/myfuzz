import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    TemporalConstraintEvaluator, add_system_services_to_soc_ir, build_control_plane,
    builtin_cpu_execution_profile, plan_system_services, synthesize_temporal_constraints,
)
from myfuzz.builder.contracts import seal_contract  # noqa: E402
from test_builder_control_plane import soc_fixture  # noqa: E402


def _fixture():
    base = soc_fixture(); view = dict(base.address_views[0]); view["global_base"] = 0x20000000
    base = seal_contract(replace(base, address_views=(view,), digest=""))
    profile = builtin_cpu_execution_profile("picorv32")
    services = plan_system_services(base.address_views, profile)
    soc = add_system_services_to_soc_ir(base, services)
    return soc, build_control_plane(soc, cpu_profile_digest=services.profile_digest)


class ConstraintSynthesisTest(unittest.TestCase):
    def test_internal_soc_marks_protocol_safe_degenerate_and_keeps_raw_bypass(self):
        soc, control = _fixture()
        generated = synthesize_temporal_constraints(soc, control)
        self.assertTrue(generated.protocol_safe_degenerate)
        self.assertEqual(generated.mode_outputs["D_SCENARIO_CONSTRAINED"], "scenario_opcode")
        evaluator = TemporalConstraintEvaluator(generated.ir)
        bypass = evaluator.step({"raw_opcode": 13, "scenario_guidance_enable": 0}, record_valid=True)
        self.assertEqual(bypass.outputs["scenario_opcode"], 13)
        guided = evaluator.step({"raw_opcode": 13, "scenario_guidance_enable": 1}, record_valid=True)
        self.assertIn(guided.outputs["scenario_opcode"], range(16))
        sources = {item["constraint_id"] for item in generated.evidence}
        self.assertEqual({"scenario_opcode_weight", "scenario_opcode_raw_bypass",
                          "scenario_state_sequence", "scenario_sequence_select",
                          "scenario_wait_bound",
                          "scenario_timeout_bound",
                          "scenario_address_align",
                          "scenario_target_region",
                          "record_stability", "operation_timeout"}, sources)
        sequence = next(
            item for item in generated.ir.constraints if item["id"] == "scenario_state_sequence"
        )
        self.assertEqual(len(sequence["states"]), 8)
        stateful = evaluator.step({
            "scenario_sequence_enable": 1, "scenario_state_opcode": 8,
        })
        self.assertEqual(stateful.outputs["scenario_opcode"], 8)
        aligned = evaluator.step({"raw_address": 0x1234567b})
        self.assertEqual(aligned.outputs["scenario_aligned_address"], 0x12345678)
        target = evaluator.step({"raw_target_region": 1}, record_valid=True)
        self.assertEqual(target.outputs["scenario_target_region"], 0)

    def test_same_contracts_produce_same_constraint_digest(self):
        soc, control = _fixture()
        self.assertEqual(synthesize_temporal_constraints(soc, control).ir.digest,
                         synthesize_temporal_constraints(soc, control).ir.digest)

    def test_target_constraint_uses_external_input_structure_not_ip_names(self):
        soc, _control = _fixture()
        dependent_instance = "never_seen_completion_dependent_target"
        dependent_view = dict(soc.address_views[-1])
        dependent_view.update(instance_id=dependent_instance, global_base=0x30000000)
        dependent_boundary = {
            "boundary_id": f"{dependent_instance}.opaque_input",
            "instance_id": dependent_instance,
            "port": "opaque_input",
            "direction": "input",
            "width": 1,
            "action": "rfuzz_drive",
            "reason": "test-only external progress dependency",
            "provenance": {"source": "unit_test"},
        }
        modified = seal_contract(replace(
            soc,
            address_views=(*soc.address_views, dependent_view),
            external_boundaries=(*soc.external_boundaries, dependent_boundary),
            digest="",
        ))
        control = build_control_plane(
            modified,
            cpu_profile_digest="4" * 64,
        )

        generated = synthesize_temporal_constraints(modified, control)
        constraint = next(
            item for item in generated.ir.constraints
            if item["id"] == "scenario_target_region"
        )
        ordered = tuple(sorted(
            modified.address_views, key=lambda item: str(item["instance_id"])
        ))
        dependent_index = next(
            index for index, view in enumerate(ordered)
            if view["instance_id"] == dependent_instance
        )
        self.assertNotIn(dependent_index, constraint["choices"])
        self.assertEqual(
            set(constraint["choices"]), set(range(len(ordered))) - {dependent_index}
        )


if __name__ == "__main__":
    unittest.main()
