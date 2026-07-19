import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import build_compose_v5_target_artifact  # noqa: E402
from myfuzz.builder.rawbits_v5 import build_rawbits_v5_layout, encode_rawbits_v5_records  # noqa: E402


TOY_RTL = r"""
module toy_cpu(
  input  logic clk,
  input  logic rst_n,
  input  logic ready_i,
  output logic valid_o,
  output logic [7:0] data_o,
  output logic [3:0] state_o
);
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_o <= 4'h0;
      data_o <= 8'h1;
    end else if (ready_i) begin
      if (state_o[0]) data_o <= data_o + 8'h3;
      else data_o <= data_o ^ 8'ha5;
      state_o <= state_o + 4'h1;
    end else begin
      if (data_o[0]) data_o <= data_o + 8'h1;
      else data_o <= data_o;
    end
  end
  assign valid_o = state_o[0] | data_o[0];
endmodule

module toy_ip(
  input  logic valid_i,
  input  logic [7:0] data_i,
  input  logic ext_i,
  output logic ready_o,
  output logic [7:0] observe_o
);
  always_comb begin
    if (valid_i && ext_i) observe_o = data_i;
    else if (valid_i) observe_o = ~data_i;
    else observe_o = 8'h00;
  end
  assign ready_o = ext_i | data_i[0];
endmodule
"""


TOY_HARNESS = r"""
module toy_compose_harness(
  input  logic [2:0] rawbits_i,
  output logic [21:0] observe_o
);
  logic clk;
  logic rst_n;
  logic ext_i;
  logic ready;
  logic valid;
  logic [7:0] data;
  logic [3:0] state;
  logic [7:0] ip_observe;

  assign ext_i = rawbits_i[0];
  assign clk = rawbits_i[1];
  assign rst_n = rawbits_i[2];

  toy_cpu u_cpu(
    .clk(clk),
    .rst_n(rst_n),
    .ready_i(ready),
    .valid_o(valid),
    .data_o(data),
    .state_o(state)
  );
  toy_ip u_ip(
    .valid_i(valid),
    .data_i(data),
    .ext_i(ext_i),
    .ready_o(ready),
    .observe_o(ip_observe)
  );
  assign observe_o = {state, data, ip_observe, ready, valid};
endmodule
"""


def _layout():
    return build_rawbits_v5_layout((
        {"name": "ext_i", "component": "ip0", "owner": "ip0.ext_i",
         "kind": "external_input", "width": 1},
        {"name": "clk", "component": "soc", "owner": "soc.clk", "kind": "clock",
         "width": 1},
        {"name": "rst_n", "component": "soc", "owner": "soc.rst_n", "kind": "reset",
         "width": 1},
    ))


def _record(layout, *, ext, clk, rst_n):
    values = {"ip0.ext_i": ext, "soc.clk": clk, "soc.rst_n": rst_n}
    result = 0
    for field in layout.fields:
        result |= int(values[field.owner]) << field.offset
    return result


def _bit_count_hex(value: str) -> int:
    return sum(byte.bit_count() for byte in bytes.fromhex(value))


@unittest.skipUnless(shutil.which("verilator"), "Verilator is required for compose-v5 target build")
class ComposeV5TargetBuildTest(unittest.TestCase):
    def test_builds_target_runs_json_contract_and_campaign_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rtl = root / "toy.sv"
            rtl.write_text(TOY_RTL, encoding="utf-8")
            layout = _layout()
            artifact = root / "artifact"
            built = build_compose_v5_target_artifact(
                rtl_files=(rtl,),
                allow_roots=(root,),
                harness_rtl=TOY_HARNESS,
                harness_module_name="toy_compose_harness",
                layout=layout,
                output_dir=artifact,
                topology="toy_direct_target",
                jobs=1,
            )

            self.assertEqual(built.layout_digest, layout.digest)
            self.assertTrue((artifact / "bin" / "myfuzz_target").is_file())
            self.assertGreater(built.coverage_width, 0)
            records = (
                _record(layout, ext=0, clk=0, rst_n=0),
                _record(layout, ext=1, clk=1, rst_n=0),
                _record(layout, ext=1, clk=0, rst_n=1),
                _record(layout, ext=1, clk=1, rst_n=1),
                _record(layout, ext=0, clk=0, rst_n=1),
                _record(layout, ext=0, clk=1, rst_n=1),
            )
            payload = root / "case.rawbits"
            payload.write_bytes(encode_rawbits_v5_records(layout, records))
            result_path = root / "result.json"
            completed = subprocess.run(
                [
                    artifact / "bin" / "myfuzz_target",
                    payload,
                    layout.digest,
                    result_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(result_path.read_text())
            self.assertEqual(result["schema"], "myfuzz.compose-v5-target-execution/v1")
            self.assertTrue(result["settled"])
            self.assertEqual(result["steps"], len(records))
            self.assertEqual(result["rising_edges"], {"soc.clk": 3})
            self.assertEqual(result["falling_edges"], {"soc.clk": 2})
            self.assertGreater(_bit_count_hex(result["coverage_hex"]), 0)

            campaign_out = root / "campaign_c"
            command = [
                sys.executable,
                str(ROOT / "src/myfuzz/scripts/compose_v5_campaign.py"),
                "--artifact",
                str(artifact),
                "--scheme",
                "C",
                "--seconds",
                "10",
                "--output-dir",
                str(campaign_out),
                "--seed",
                "11",
                "--max-testcases",
                "2",
                "--testcase-bytes",
                "4",
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((campaign_out / "campaign_report.json").read_text())
            self.assertEqual(report["scheme"], "C")
            self.assertEqual(report["completed_count"], 2)
            self.assertGreater(report["coverage_hits"], 0)


if __name__ == "__main__":
    unittest.main()
