import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    DiscoveredModule,
    DiscoveredPort,
    DiscoveryResult,
    PortDirection,
    emit_rfuzz_metadata,
    generate_rfuzz_testcase,
    plan_system,
    run_instrumentation,
)
from builder_fixtures import module_spec, rtl_module, system_spec


class BridgeTest(unittest.TestCase):
    def test_rfuzz_bridge_maps_only_explicit_rfuzz_inputs_and_generates_bytes(self):
        extra = (
            DiscoveredPort("fuzz_i", PortDirection.INPUT, 4, None),
            DiscoveredPort("external_i", PortDirection.INPUT, 1, None),
        )
        modules = [
            module_spec("cpu", "cpu", "initiator"),
            module_spec("unit", "peripheral", "target", unknown_ports={
                "fuzz_i": {
                    "action": "rfuzz_drive", "reason": "selected fuzz control",
                    "reset_behavior": "hold zero during reset",
                },
                "external_i": {"action": "external_input", "reason": "board pin"},
            }),
        ]
        spec = system_spec(modules)
        discovery = DiscoveryResult(("/cpu.sv", "/unit.sv"), (
            rtl_module("cpu", "initiator"), rtl_module("unit", "target", extra),
        ))
        plan = plan_system(spec, discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex((TypeError, ValueError), "format"):
                emit_rfuzz_metadata(plan, directory, format_version="v2")
            metadata = emit_rfuzz_metadata(plan, directory, format_version="legacy-v1")
            self.assertEqual(metadata["fuzz_input_count"], 1)
            actions = json.loads((Path(directory) / "action_definitions.json").read_text())
            self.assertEqual(actions["input_mappings"][0]["port"], "fuzz_i")
            testcase = generate_rfuzz_testcase(
                directory, Path(directory) / "cases", cycles=8, seed=3,
                format_version="legacy-v1",
            )
            self.assertEqual(Path(testcase["bin"]).stat().st_size, 8)

    def test_instrumentation_bridge_runs_existing_engine_and_records_observation(self):
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as output:
            root = Path(project)
            rtl = root / "observed.sv"
            rtl.write_text("""
                module observed(input logic a, output logic y);
                  always_comb begin
                    if (a) y = 1'b1; else y = 1'b0;
                  end
                endmodule
            """)
            modules = [{
                "name": "observed", "kind": "observation", "source_set": "rtl", "ports": {},
                "unknown_ports": {"a": {"action": "tieoff", "reason": "test", "value": 0}},
                "top_candidate": True,
            }]
            spec = system_spec(modules)
            discovery = DiscoveryResult((rtl.as_posix(),), (
                DiscoveredModule("observed", rtl.as_posix(), "rtl", {}, (
                    DiscoveredPort("a", PortDirection.INPUT, 1, None),
                    DiscoveredPort("y", PortDirection.OUTPUT, 1, None),
                ), (), True, "user declaration"),
            ))
            plan = plan_system(spec, discovery)
            instrumented = Path(output) / "instrumented"
            result = run_instrumentation(plan, discovery, root, instrumented)
            self.assertGreaterEqual(result["coverage_point_count"], 1)
            self.assertEqual(result["observed_outputs"][0]["port"], "y")
            self.assertTrue((instrumented / "instrumentation.json").is_file())


if __name__ == "__main__":
    unittest.main()
