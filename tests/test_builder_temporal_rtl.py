import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    TemporalConstraintEvaluator, build_temporal_constraint_ir_v2,
    emit_temporal_constraint_rtl,
)


def rule(identifier, primitive, priority, **values):
    return {"id": identifier, "primitive": primitive, "priority": priority,
            "domain": "global", **values}


def fixture():
    constraints = (
        rule("stable", "STABLE_UNTIL", 1, dst="stable_o", sample="sample", activate="stable_go", release="release", width=8, reset=0),
        rule("valid", "VALID_READY", 2, valid="valid_o", payload="payload_o", sample="sample", activate="valid_go", ready="ready", width=8, reset_payload=0),
        rule("pulse", "PULSE_WIDTH", 3, dst="pulse_o", start="pulse_go", cycles=3),
        rule("hold", "HOLD_WHEN", 4, dst="hold_o", sample="sample", hold="hold", width=8, reset=3),
        rule("update", "UPDATE_ON", 5, dst="update_o", sample="sample", event="event", width=8, reset=4),
        rule("dep", "DEPENDENCY", 6, dst="dep_o", predicate="hold_o", true_value="sample", false_value=2, width=8),
        rule("mask", "BIT_MASK", 12, dst="masked_o", sample="sample", mask=0xfc, width=8),
        rule("wait", "WAIT_UNTIL", 7, activate="wait_go", predicate="done", limit=3, success="success_o", expired="expired_o"),
        rule("timeout", "TIMEOUT", 8, active="timeout_active", clear="clear", limit=3, fired="fired_o"),
        rule("choice", "CHOICE_WEIGHT", 9, dst="choice_o", raw_slice="raw", slice_width=4, choices=(10, 20, 30), integer_weights=(1, 2, 5), width=8),
        rule("fault", "FAULT_INJECT", 10, dst="fault_o", enable="fault_enable", kind="stuck", value=1, cycles=2, width=1),
        rule("seq", "SEQUENCE", 11, state="seq_state", initial="S0", states=("S0", "S1"), terminal=("S1",), transitions=(
            {"from": "S0", "to": "S1", "guard": "seq_set", "priority": 1},
            {"from": "S1", "to": "S0", "guard": "seq_clear", "priority": 2},
        )),
    )
    return build_temporal_constraint_ir_v2(
        rawbits_layout_digest="1" * 64, soc_digest="2" * 64,
        constraints=constraints, fault_capable_sinks=("fault_o",),
    )


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "iverilog/vvp required")
class TemporalRTLDifferentialTest(unittest.TestCase):
    def test_all_primitives_compile_and_match_reference_trace(self):
        ir = fixture(); emitted = emit_temporal_constraint_rtl(ir)
        evaluator = TemporalConstraintEvaluator(ir); rng = random.Random(20260714)
        vectors = []
        for cycle in range(10_000):
            outputs = evaluator.outputs
            values = {
                name: rng.randrange(1 << (4 if name == "raw" else 8 if name == "sample" else 1))
                for name in emitted.input_ports
            }
            # Avoid deliberately invalid retriggers in this long equivalence trace.
            values["valid_go"] = int(not outputs["valid_o"] and rng.randrange(8) == 0)
            values["pulse_go"] = int(not outputs["pulse_o"] and rng.randrange(10) == 0)
            domain_reset = cycle != 0 and cycle % 137 == 0
            record_valid = bool(rng.randrange(3))
            expected = evaluator.step(values, record_valid=record_valid,
                                      domain_resets=("global",) if domain_reset else ())
            vectors.append((values, record_valid, domain_reset, expected.outputs,
                            expected.runtime_error))
        self._run_vectors(emitted, vectors)

    def test_reset_macro_matches_reference_including_feedback_timeout_edge(self):
        ir = build_temporal_constraint_ir_v2(
            rawbits_layout_digest="1" * 64, soc_digest="2" * 64,
            constraints=(rule(
                "reset", "RESET_SEQUENCE", 1, start="start", drain_limit=1,
                isolate_limit=2, assert_cycles=2, complete_limit=4,
                drained="drained", isolated="isolated", reset_done="reset_done",
                error="error", request="request_o", force_isolate="force_o",
                success="success_o", failed="failed_o",
            ),),
        )
        emitted = emit_temporal_constraint_rtl(ir); evaluator = TemporalConstraintEvaluator(ir)
        inputs = [
            {"start": 1}, {}, {}, {"isolated": 1}, {}, {"reset_done": 1}, {}, {},
            {"start": 1}, {"error": 1}, {},
        ]
        vectors = []
        for values in inputs:
            complete = {signal: int(values.get(signal, 0)) for signal in emitted.input_ports}
            expected = evaluator.step(complete)
            vectors.append((complete, False, False, expected.outputs, expected.runtime_error))
        self._run_vectors(emitted, vectors)

    def _run_vectors(self, emitted, vectors):

        ports = [".clk(clk)", ".rst_n(rst_n)", ".raw_bits_valid(raw_bits_valid)",
                 ".raw_bits_ready(raw_bits_ready)",
                 ".constraint_runtime_error(constraint_runtime_error)"]
        ports.extend(f".{port}({port})" for port in emitted.domain_reset_ports.values())
        ports.extend(f".{port}({port})" for port in emitted.input_ports.values())
        ports.extend(f".{port}({port})" for port in emitted.output_ports.values())
        declarations = ["logic clk = 0;", "logic rst_n = 0;", "logic raw_bits_valid = 0;",
                        "wire raw_bits_ready;", "wire constraint_runtime_error;"]
        declarations.extend(f"logic {port} = 0;" for port in emitted.domain_reset_ports.values())
        declarations.extend(f"logic [63:0] {port} = 0;" for port in emitted.input_ports.values())
        declarations.extend(f"wire [63:0] {port};" for port in emitted.output_ports.values())
        body = ["#1; clk = 1; #1; clk = 0; #1; rst_n = 1;"]
        for cycle, (values, record_valid, domain_reset, expected, runtime_error) in enumerate(vectors):
            body.append(f"raw_bits_valid = {int(record_valid)};")
            for domain, port in emitted.domain_reset_ports.items():
                body.append(f"{port} = {int(domain_reset and domain == 'global')};")
            for signal, port in emitted.input_ports.items(): body.append(f"{port} = {int(values[signal])};")
            body.append("#1; clk = 1; #1;")
            for signal, port in emitted.output_ports.items():
                value = expected[signal]
                if isinstance(value, str): value = emitted.state_encodings[signal][value]
                body.append(f"if ({port} !== {int(value)}) $fatal(1, \"cycle {cycle} {signal} expected {value} got %0d\", {port});")
            body.append(f"if (constraint_runtime_error !== {int(runtime_error)}) $fatal(1, \"cycle {cycle} runtime error mismatch\");")
            body.append("clk = 0; #1;")
        body.append('$display("TEMPORAL_RTL_PASS"); $finish;')
        tb = "\n".join([
            emitted.rtl, "module tb;", *("  " + line for line in declarations),
            f"  {emitted.module_name} dut (" + ", ".join(ports) + ");",
            "  initial begin", *("    " + line for line in body), "  end", "endmodule", "",
        ])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "tb.sv"; executable = root / "sim.out"
            source.write_text(tb)
            compile_run = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_run.returncode, 0, compile_run.stderr)
            run = subprocess.run(["vvp", str(executable)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("TEMPORAL_RTL_PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()
