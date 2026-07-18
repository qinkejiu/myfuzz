import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import InputValidationError, emit_flat_shell
from myfuzz.builder.contracts import SystemIR


class FlatShellTest(unittest.TestCase):
    def test_every_child_port_is_qualified_exposed_and_unconnected(self):
        ir = SystemIR("flat", (
            {"name": "cpu", "module_type": "cpu_mod", "instance": "u_cpu", "ports": (
                {"name": "clk", "direction": "input", "width": 1},
                {"name": "req", "direction": "output", "width": 8},)},
            {"name": "ip", "module_type": "ip_mod", "instance": "u_ip", "ports": (
                {"name": "clk", "direction": "input", "width": 1},
                {"name": "req", "direction": "input", "width": 8},
                {"name": "seen", "direction": "output", "width": 1},)},
        ), ({"source": "cpu.req", "target": "ip.req", "width": 8},), ())
        emitted = emit_flat_shell(ir)
        self.assertEqual({p["name"] for p in emitted.external_ports}, {
            "u_cpu__clk", "u_cpu__req", "u_ip__clk", "u_ip__req", "u_ip__seen"})
        self.assertNotIn("__edge_", emitted.rtl)
        self.assertIn(".req(u_cpu__req)", emitted.rtl)
        self.assertIn(".req(u_ip__req)", emitted.rtl)
        self.assertTrue(next(p for p in emitted.external_ports if p["name"] == "u_ip__req")["fuzz_control"])
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "flat.sv"
            source.write_text("module cpu_mod(input logic clk, output logic [7:0] req); assign req=8'h5a; endmodule\n"
                              "module ip_mod(input logic clk,input logic [7:0] req,output logic seen); assign seen=|req; endmodule\n" + emitted.rtl)
            result = subprocess.run(["iverilog", "-g2012", "-s", emitted.module_name,
                                     "-o", str(Path(directory) / "a.out"), str(source)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_inout_and_bad_module_fields_fail_closed(self):
        module = {"name": "ip", "module_type": "ip_mod", "instance": "u_ip", "ports": (
            {"name": "pad", "direction": "inout", "width": 1},)}
        with self.assertRaisesRegex(InputValidationError, "inout"):
            emit_flat_shell(SystemIR("flat", (module,), (), ()))
        with self.assertRaisesRegex(InputValidationError, "unknown field"):
            emit_flat_shell(SystemIR("flat", (dict(module, surprise=True),), (), ()))


if __name__ == "__main__": unittest.main()
