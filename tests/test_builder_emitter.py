import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import InputValidationError, emit_system
from myfuzz.builder import DiscoveryResult, plan_system
from builder_fixtures import module_spec, rtl_module, system_spec


class EmitterTest(unittest.TestCase):
    def test_emits_parseable_structured_artifacts_and_report_evidence(self):
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        spec = system_spec(modules)
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator"), rtl_module("ram", "target"),
        ))
        plan = plan_system(spec, discovery)
        with tempfile.TemporaryDirectory() as directory:
            report = emit_system(plan, spec, discovery, directory, generate_wrapper=True)
            for name in report["generated_files"]:
                self.assertTrue((Path(directory) / name).is_file(), name)
            for name in report["generated_files"]:
                if name.endswith(".json"):
                    json.loads((Path(directory) / name).read_text())
            address_map = json.loads((Path(directory) / "address_map.json").read_text())
            self.assertEqual(address_map["windows"][0]["source"], "system_auto")
            self.assertIn("reason", address_map["windows"][0])
            bindings = json.loads((Path(directory) / "port_bindings.json").read_text())
            self.assertTrue(all("confidence" in item for item in bindings["port_bindings"]))
            self.assertTrue(report["wrapper"]["generated"])

    def test_virtual_fabric_skips_optional_wrapper_with_reason(self):
        modules = [
            module_spec("cpu", "cpu", "initiator"), module_spec("dma", "dma", "initiator"),
            module_spec("ram", "ram", "target"),
        ]
        spec = system_spec(modules)
        discovery = DiscoveryResult(tuple(f"/{name}.sv" for name in ("cpu", "dma", "ram")), (
            rtl_module("cpu", "initiator"), rtl_module("dma", "initiator"), rtl_module("ram", "target"),
        ))
        with tempfile.TemporaryDirectory() as directory:
            report = emit_system(plan_system(spec, discovery), spec, discovery, directory, generate_wrapper=True)
            self.assertFalse(report["wrapper"]["generated"])
            self.assertIn("protocol backend", report["wrapper"]["reason"])

    def test_invalid_plan_cannot_be_emitted(self):
        from myfuzz.builder import DiscoveredPort, PortDirection
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("gpio", "peripheral", "target")]
        spec = system_spec(modules)
        discovery = DiscoveryResult(("/cpu.sv", "/gpio.sv"), (
            rtl_module("cpu", "initiator"),
            rtl_module("gpio", "target", (DiscoveredPort("pad", PortDirection.INOUT, 1, None),)),
        ))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(InputValidationError, "cannot emit invalid system plan"):
                emit_system(plan_system(spec, discovery), spec, discovery, directory)

    @unittest.skipUnless(shutil.which("iverilog"), "iverilog is not installed")
    def test_direct_wrapper_compiles(self):
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        spec = system_spec(modules)
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator"), rtl_module("ram", "target"),
        ))
        source = """
module cpu(output req_o, output we_o, output [31:0] addr_o, output [31:0] wdata_o,
           input [31:0] rdata_i, input gnt_i);
endmodule
module ram(input req_i, input we_i, input [31:0] addr_i, input [31:0] wdata_i,
           output [31:0] rdata_o, output gnt_o);
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            emit_system(plan_system(spec, discovery), spec, discovery, out, generate_wrapper=True)
            rtl = out / "modules.sv"
            rtl.write_text(source)
            result = subprocess.run(
                ["iverilog", "-g2012", "-s", "planned_wrapper", "-o", str(out / "wrapper.vvp"),
                 str(rtl), str(out / "planned_wrapper.sv")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
