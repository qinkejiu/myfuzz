import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    HarnessPort, InputValidationError, PortDirection, RawBitsTestcase,
    build_constraint_ir, build_rawbits_layout, build_verilator_target,
    emit_dual_mode_harness, minimize_rawbits_cycles, run_verilator_target,
    write_rawbits_testcase,
)
from myfuzz.builder.contracts import CoverageABI, build_elaboration_manifest  # noqa: E402
from myfuzz.builder.atomic_target import (  # noqa: E402
    FIXED_CYCLE_RUNNER_SCHEMA, LEGACY_RUNNER_SCHEMA,
)


SOC = """\
module simple_soc(
 input logic clk, input logic resetn, input logic [69:0] pin,
 output logic seen, output logic [64:0] __vi_coverage
);
 assign seen=|pin;
 assign __vi_coverage=pin[64:0];
endmodule
"""


def evidence(soc_path):
    return {
        "original_soc_rtl": soc_path,
        "rfuzz_config": {"format": "RawBits v2", "modes": ["raw", "constrained"]},
        "address_graph": {"windows": []},
        "connection_graph": {"edges": []},
        "port_bindings": {"pin": "direct_fuzz"},
        "instrumentation_manifest": {"required": ["simple_soc"], "skipped": []},
        "generation_report": {"status": "verified"},
    }


class AtomicTargetTest(unittest.TestCase):
    def _fixture(self, root):
        source_root = root / "instrumented"
        source_root.mkdir()
        soc = source_root / "simple_soc.sv"
        soc.write_text(SOC)
        manifest = build_elaboration_manifest(
            top_module="simple_soc", rtl_files=(soc,), allow_roots=(source_root,),
            tools={"verilator": subprocess.check_output(["verilator", "--version"], text=True).strip()},
        )
        layout = build_rawbits_layout((
            {"target": "pin", "width": 70, "purpose": "input", "provenance": "user"},
        ))
        constraint_ir = build_constraint_ir(layout, (
            {"target": "pin", "primitive": "DIRECT", "provenance": "user"},
        ))
        abi = CoverageABI("a" * 64, "__vi_coverage", 65, tuple(
            {"point_id": f"simple.pin.{offset}", "included": True, "offset": offset}
            for offset in range(65)
        ))
        ports = (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
            HarnessPort("pin", PortDirection.INPUT, 70),
            HarnessPort("seen", PortDirection.OUTPUT, 1),
        )
        harness = emit_dual_mode_harness(
            "simple_soc", layout, constraint_ir, ports, module_name="target_harness",
            reset_cycles=1, drain_cycles=1, coverage_abi=abi,
        )
        return source_root, soc, manifest, layout, constraint_ir, abi, harness

    def test_atomic_target_is_runnable_cached_and_has_reproducible_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root, soc, manifest, layout, constraints, abi, harness = self._fixture(root)
            kwargs = dict(
                manifest=manifest, source_root=source_root, harness=harness, layout=layout,
                constraint_ir=constraints, coverage_abi=abi, evidence=evidence(soc), jobs=1,
            )
            first = build_verilator_target(root / "targets", **kwargs)
            cached = build_verilator_target(root / "targets", **kwargs)
            fresh = build_verilator_target(root / "targets_fresh", **kwargs)
            self.assertFalse(first.cached)
            self.assertTrue(cached.cached)
            self.assertEqual(first.target_digest, fresh.target_digest)
            self.assertEqual(
                (Path(first.path) / "evidence/target_generation_report.json").read_bytes(),
                (Path(fresh.path) / "evidence/target_generation_report.json").read_bytes(),
            )
            self.assertEqual(
                (Path(first.path) / "bin/myfuzz_target").read_bytes(),
                (Path(fresh.path) / "bin/myfuzz_target").read_bytes(),
            )
            self.assertEqual(
                Path(first.completion_manifest).read_bytes(),
                Path(fresh.completion_manifest).read_bytes(),
            )
            completion = json.loads(Path(first.completion_manifest).read_text())
            self.assertEqual(completion["target_digest"], first.target_digest)
            self.assertTrue((Path(first.path) / "bin/myfuzz_target").is_file())
            self.assertTrue((Path(first.path) / "sources.f").is_file())
            self.assertEqual(len(completion["evidence_files"]), 12)

            testcase = write_rawbits_testcase(
                layout, (0, (1 << 65) - 1), root / "cases", name="seed",
            )
            raw = run_verilator_target(
                first.path, testcase["rawbits"], testcase["metadata"], root / "runs", mode="raw",
            )
            constrained = run_verilator_target(
                first.path, testcase["rawbits"], testcase["metadata"], root / "runs",
                mode="constrained",
            )
            expected_hits = [f"simple.pin.{offset}" for offset in range(65)]
            self.assertEqual(raw.report["coverage_hit_point_ids"], expected_hits)
            self.assertEqual(constrained.report["coverage_hit_point_ids"], expected_hits)
            self.assertEqual(len(raw.report["coverage_hit_count_by_cycle"]), 2)
            self.assertEqual(raw.report["coverage_hit_count_by_cycle"][-1], 65)
            self.assertEqual(
                raw.report["coverage_hit_count_by_cycle"],
                sorted(raw.report["coverage_hit_count_by_cycle"]),
            )
            self.assertEqual(len(raw.report["coverage_trace_sha256"]), 64)
            self.assertNotEqual(raw.report["run_digest"], constrained.report["run_digest"])

    def test_failed_build_is_cleaned_and_bad_testcase_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root, soc, manifest, layout, constraints, abi, harness = self._fixture(root)
            broken = type(harness)(harness.module_name, harness.rtl + "broken", harness.observed_ports,
                                   harness.layout_digest)
            target_parent = root / "targets"
            with self.assertRaisesRegex(InputValidationError, "Verilator target build failed"):
                build_verilator_target(
                    target_parent, manifest=manifest, source_root=source_root, harness=broken,
                    layout=layout, constraint_ir=constraints, coverage_abi=abi,
                    evidence=evidence(soc), jobs=1,
                )
            self.assertFalse(any(path.is_dir() for path in target_parent.iterdir()))

            built = build_verilator_target(
                target_parent, manifest=manifest, source_root=source_root, harness=harness,
                layout=layout, constraint_ir=constraints, coverage_abi=abi,
                evidence=evidence(soc), jobs=1,
            )
            testcase = write_rawbits_testcase(layout, (1,), root / "cases", name="seed")
            metadata = json.loads(Path(testcase["metadata"]).read_text())
            metadata["layout_digest"] = "0" * 64
            Path(testcase["metadata"]).write_text(json.dumps(metadata))
            with self.assertRaisesRegex(InputValidationError, "metadata mismatch"):
                run_verilator_target(
                    built.path, testcase["rawbits"], testcase["metadata"], root / "runs", mode="raw",
                )

    def test_fixed_cycle_runner_is_distinct_and_reports_measured_cycle_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root, soc, manifest, layout, constraints, abi, harness = self._fixture(root)
            kwargs = dict(
                manifest=manifest, source_root=source_root, harness=harness, layout=layout,
                constraint_ir=constraints, coverage_abi=abi, evidence=evidence(soc), jobs=1,
            )
            legacy = build_verilator_target(root / "targets", **kwargs)
            fixed = build_verilator_target(
                root / "targets", **kwargs, runner_schema=FIXED_CYCLE_RUNNER_SCHEMA,
            )
            self.assertNotEqual(legacy.target_digest, fixed.target_digest)
            self.assertEqual(
                json.loads(Path(legacy.completion_manifest).read_text())["runner_schema"],
                LEGACY_RUNNER_SCHEMA,
            )
            self.assertEqual(
                json.loads(Path(fixed.completion_manifest).read_text())["runner_schema"],
                FIXED_CYCLE_RUNNER_SCHEMA,
            )

            testcase = write_rawbits_testcase(layout, (0, 1, 3), root / "cases", name="fixed")
            coverage = root / "coverage.bin"
            trace = root / "trace.bin"
            metrics = root / "metrics.json"
            completed = subprocess.run(
                [
                    str(Path(fixed.path) / "bin/myfuzz_target"), testcase["rawbits"], "3", "0",
                    str(coverage), str(trace), str(metrics),
                ],
                cwd=fixed.path, capture_output=True, text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
            self.assertEqual(len(trace.read_bytes()), 3 * ((abi.width + 7) // 8))
            values = json.loads(metrics.read_text())
            self.assertEqual(values["dut_cycles"], 3)
            self.assertEqual(values["accepted_records"] + values["stall_cycles"], 3)
            self.assertEqual(values["unconsumed_records"], 3 - values["accepted_records"])

    def test_cycle_minimization_is_deterministic(self):
        layout = build_rawbits_layout((
            {"target": "pin", "width": 4, "purpose": "input", "provenance": "user"},
        ))
        original = RawBitsTestcase((1, 2, 7, 3, 4), {"cycles": 5})
        minimized = minimize_rawbits_cycles(
            layout, original, lambda testcase: 7 in testcase.cycles,
        )
        self.assertEqual(minimized.cycles, (7,))
        self.assertEqual(minimized.metadata["layout_digest"], layout.digest)


if __name__ == "__main__":
    unittest.main()
