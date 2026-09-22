"""Sample projection at the runtime boundary; simulator execution is isolated."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from myfuzz.composition.input_constraints import compile_rules, compile_input_constraints, InputConstraintError
from myfuzz.composition.soc_runtime import ExternalEvent, RuntimeSample, run_sample_with_policy


def rule(primitive, parameters, **overrides):
    result = dict(rule_id="value:port", category="environment_hard", owner="environment",
                  primitive=primitive, phase="sample", fields=["port"], read_set=[],
                  write_set=["port"], raw_bits=[[2, 5]], parameters=list(parameters.items()))
    result.update(overrides)
    return result


class SampleProjectionTests(unittest.TestCase):
    def run_policy(self, document, raw=255):
        policy = compile_rules([document], drive_profile="cpu_execute",
                               layout_hash="layout", plan_hash="plan")
        with TemporaryDirectory() as directory:
            record = Path(directory) / "tb.sv"
            record.write_text("// plan: plan\n// raw-input layout: layout\n")
            build = SimpleNamespace(testbench_path=record, raw_width=8)
            sample = RuntimeSample(17, (raw,), (ExternalEvent("rx", 0, 1),))
            with patch("myfuzz.composition.soc_runtime.run_sample", side_effect=lambda b, s, **kw: s):
                result = run_sample_with_policy(build, sample, policy=policy)
            self.assertEqual(sample.request_id, result.request_id)
            self.assertEqual(sample.events, result.events)
            self.assertEqual(raw, sample.raw[0])
            self.assertEqual(raw & ~0x3c, result.raw[0] & ~0x3c)
            return result.raw[0]

    def test_range_projects_only_invalid_values(self):
        spec = rule("value_range", {"low": 4, "high": 7})
        self.assertIn((self.run_policy(spec) >> 2) & 15, range(4, 8))
        self.assertEqual(0xd7, self.run_policy(spec, 0xd7))

    def test_enum_intersects_range_and_alignment(self):
        spec = rule("value_enum", {"values": [2, 4, 6, 8], "low": 3,
                                   "high": 7, "alignment": 4})
        self.assertEqual(0xd3, self.run_policy(spec))
        self.assertEqual(self.run_policy(spec), self.run_policy(spec))

    def test_mask_and_alignment_both_apply(self):
        spec = rule("value_mask_align", {"mask": 7, "alignment": 4})
        self.assertEqual(0xd3, self.run_policy(spec))

    def test_empty_intersection_is_rejected_before_execution(self):
        with self.assertRaises(InputConstraintError):
            self.run_policy(rule("value_enum", {"values": [3, 5], "alignment": 4}))

    def test_unsupported_sample_hard_rule_is_not_silently_ignored(self):
        with self.assertRaises(InputConstraintError):
            self.run_policy(rule("drive_hold", {}))

    def test_non_environment_sample_rule_cannot_repair_cpu_state(self):
        with self.assertRaises(InputConstraintError):
            self.run_policy(rule("value_range", {"low": 1, "high": 2}, owner="cpu"))

    def test_unknown_parameters_and_inapplicable_mode_are_rejected(self):
        for spec in (rule("value_range", {"low": 1, "high": 2, "magic": 3}),
                     rule("value_range", {"low": 1, "high": 2}, applies_in_modes=["mmio_only"])):
            with self.subTest(spec=spec), self.assertRaises(InputConstraintError):
                self.run_policy(spec)

    def test_field_outside_raw_width_is_rejected(self):
        with self.assertRaises(InputConstraintError):
            self.run_policy(rule("value_range", {"low": 1, "high": 2}, raw_bits=[[4, 9]]))

    def test_compiled_layout_mask_is_enforced_at_runtime(self):
        plan = SimpleNamespace(raw_layout={"layout_hash": "layout", "fields": [
            {"field_id": "port", "width": 4, "raw_lo": 2, "raw_hi": 5,
             "constraint": {"mask": 7}}]}, instances=(), plan={}, plan_hash="plan")
        policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        from myfuzz.composition.input_constraints import project_sample_values
        self.assertEqual(0xdf, project_sample_values(policy, 255, raw_width=8))

    def test_sample_repair_and_single_runtime_driver_can_share_a_field(self):
        plan = SimpleNamespace(raw_layout={"layout_hash": "layout", "fields": [
            {"field_id": "cpu0::port", "owner": "cpu0::port", "width": 4,
             "raw_lo": 2, "raw_hi": 5, "binding": {"port": "cpu0__port"},
             "constraint": {"randomizable": True, "enum": [4]}}]},
             instances=(), plan={}, plan_hash="plan")
        try:
            policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        except InputConstraintError as error:
            self.fail(f"preprocessing plus one physical driver is not double driving: {error}")
        from myfuzz.composition.input_constraints import project_sample_values
        self.assertEqual(0xd3, project_sample_values(policy, 255, raw_width=8))

    def test_runtime_payload_and_trace_use_projected_raw(self):
        policy = compile_rules([rule("value_enum", {"values": [4]})],
                               drive_profile="cpu_execute", layout_hash="layout", plan_hash="plan")
        with TemporaryDirectory() as directory:
            record = Path(directory) / "tb.sv"
            record.write_text("// plan: plan\n// raw-input layout: layout\n")
            build = SimpleNamespace(testbench_path=record, raw_width=8, executable=Path("sim"),
                                    boot_image=None, output_dir=Path(directory),
                                    slots=({"name": "port", "width": 4, "raw_lo": 2},))
            sample = RuntimeSample(17, (255,), (ExternalEvent("rx", 0, 1),))
            process = SimpleNamespace(returncode=0, stdout="MYFUZZ_SOC_RUN status=OK cycles=1\n",
                                      stderr="")
            with patch("myfuzz.composition.soc_runtime.subprocess.run", return_value=process) as simulator:
                result = run_sample_with_policy(build, sample, policy=policy)
            self.assertEqual(RuntimeSample(17, (0xd3,), sample.events).payload(),
                             simulator.call_args.kwargs["input"])
            self.assertEqual(({"cycle": 0, "raw": 0xd3, "port": 4},), result.trace)


if __name__ == "__main__":
    unittest.main()
