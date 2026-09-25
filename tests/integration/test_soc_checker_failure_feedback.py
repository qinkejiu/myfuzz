"""Failure feedback survives the RFuzz FIFO exchange as replayable raw input."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from myfuzz.integration.rfuzz_live import CheckerFailureStore, _configuration
from myfuzz.integration.soc_builder import _testbench


def artifact():
    return SimpleNamespace(
        layout=SimpleNamespace(raw_width=8),
        transport=SimpleNamespace(byte_count=1),
        coverage_ports=(("__vi_coverage", 0), ("checker_eval_o", 0),
                        ("checker_fail_o", 0), ("checker_fail_o", 1)),
        build_document={"checker_feedback": {"properties": [
            {"bit": 0, "property_id": "OBI.INSTR.STALL_STABLE"},
            {"bit": 1, "property_id": "OBI.INSTR.NO_ORPHAN_RSP"},
        ]}},
    )


class CheckerFailureStoreTests(unittest.TestCase):
    def test_config_marks_only_failure_bus_as_failing(self):
        config = _configuration(artifact())
        self.assertEqual(2, config.count("fail = true"))
        self.assertEqual(2, config.count("fail = false"))

    def test_saves_exact_raw_records_and_property_ids_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckerFailureStore(Path(tmp), artifact(), max_cases=2,
                                        max_bytes=10)
            records = [b"\x12", b"\x34", b"\x56"]
            counters = bytes((1, 0, 1, 1))
            first = store.record(records, counters)
            second = store.record(records, counters)
            self.assertEqual(first, second)
            manifest = json.loads((Path(tmp) / "failures/manifest.json").read_text())
            self.assertEqual(1, manifest["entries"])
            entry = manifest["cases"][0]
            self.assertEqual(3, entry["cycles"])
            self.assertEqual(1, entry["record_width_bytes"])
            self.assertEqual("0x0000000000003", entry["failure_mask"])
            self.assertEqual(["OBI.INSTR.STALL_STABLE", "OBI.INSTR.NO_ORPHAN_RSP"],
                             entry["failure_ids"])
            self.assertEqual(b"\x12\x34\x56",
                             (Path(tmp) / "failures" / entry["raw_file"]).read_bytes())
            self.assertEqual(1, store.saved_cases)

    def test_nonfailure_is_not_saved_and_bounds_are_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckerFailureStore(Path(tmp), artifact(), max_cases=1,
                                        max_bytes=2)
            self.assertIsNone(store.record([b"\x00"], bytes((1, 1, 0, 0))))
            self.assertFalse((Path(tmp) / "failures").exists())
            self.assertIsNone(store.record([b"\x01", b"\x02", b"\x03"],
                                           bytes((0, 0, 1, 0))))
            self.assertEqual(1, store.dropped_cases)
            self.assertEqual(0, store.saved_cases)


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"),
                     "Icarus required")
class CheckerFailureHarnessTests(unittest.TestCase):
    def test_failure_stops_dut_cycles_but_consumes_remaining_input(self):
        ports = [
            {"name": "clk_i", "direction": "input", "width": 1},
            {"name": "rst_ni", "direction": "input", "width": 1},
            {"name": "executed_o", "direction": "output", "width": 1},
            {"name": "checker_eval_o", "direction": "output", "width": 50},
            {"name": "checker_fail_o", "direction": "output", "width": 50},
        ]
        bench = _testbench(SimpleNamespace(raw_width=1, fields=()),
                           {"unmapped": []}, ports, "myfuzz_soc_top",
                           (("executed_o", 0), ("checker_fail_o", 0)))
        dut = """module myfuzz_soc_top(input logic clk_i, rst_ni,
          output logic executed_o, output logic [49:0] checker_eval_o,
          output logic [49:0] checker_fail_o);
          logic [3:0] cycles;
          always @(posedge clk_i or negedge rst_ni)
            if (!rst_ni) cycles <= 0; else cycles <= cycles + 1;
          assign executed_o = cycles[0];
          assign checker_eval_o = 50'b1;
          assign checker_fail_o = cycles >= 1 ? 50'b1 : 50'b0;
        endmodule"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tb.sv").write_text(bench)
            (root / "dut.sv").write_text(dut)
            subprocess.run(["iverilog", "-g2012", "-s", "myfuzz_live_tb",
                            "-o", str(root / "sim"), str(root / "dut.sv"),
                            str(root / "tb.sv")], check=True, capture_output=True)
            result = subprocess.run(["vvp", str(root / "sim")],
                                    input="1 3\n0\n0\n0\n2 1\n0\n", text=True,
                                    capture_output=True, check=True)
            replies = [line for line in result.stdout.splitlines()
                       if line.startswith("RFUZZ_COUNTERS")]
            self.assertEqual(2, len(replies))
            self.assertTrue(replies[0].endswith("0101"), replies[0])
            self.assertTrue(replies[1].endswith("0101"), replies[1])


if __name__ == "__main__":
    unittest.main()
