import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from myfuzz.builder import (  # noqa: E402
    AxiLiteV4Capability, DiscoveryResult, DiscoveredModule, DiscoveredPort,
    PortDirection, SocExternalPort, axi_lite_v4_profile_registry,
    add_system_services_to_soc_ir, analyze_declared_components_v2,
    builtin_cpu_execution_profile,
    build_axi_lite_v4_layout, build_cpu_semantic_v4_layout, build_soc_ir_v2,
    emit_protocol_harness_v4, emit_soc_ir_v4, load_system_spec, plan_system,
    plan_system_services,
)
from builder_fixtures import system_spec  # noqa: E402
from myfuzz.builder.contracts import CoverageABIV2  # noqa: E402
from test_builder_generated_soc_v2 import AXI, _module  # noqa: E402


AXI_PROT = {
    **AXI,
    "awprot": ("s_axi_awprot", PortDirection.INPUT, 3),
    "arprot": ("s_axi_arprot", PortDirection.INPUT, 3),
}


def _prot_module(name, role, base=None):
    table = AXI_PROT
    def direction_for_role(direction):
        if role != "initiator":
            return direction
        return PortDirection.OUTPUT if direction == PortDirection.INPUT else PortDirection.INPUT
    ports = tuple(DiscoveredPort(physical, direction_for_role(direction), width, None)
                  for physical, direction, width in table.values())
    mapping = {semantic: physical for semantic, (physical, _direction, _width) in table.items()}
    return {
        "name": name, "kind": "cpu" if role == "initiator" else "peripheral", "source_set": "rtl",
        "ports": {}, "interfaces": [{"name": "bus", "protocol": "axi_lite", "role": role, "ports": mapping}],
        **({"address": {"mode": "fixed", "base": base, "size": 0x100, "alignment": 0x100}} if base is not None else {}),
    }, DiscoveredModule(name, f"/{name}.sv", "rtl", {}, ports, (), True, "fixture")


class GeneratedSocV4Test(unittest.TestCase):
    @staticmethod
    def _stubs():
        stubs = []
        for name, role, table in (("cpu_h", "initiator", AXI), ("ip_h", "target", AXI)):
            def direction(value):
                if role != "initiator": return value
                return PortDirection.OUTPUT if value == PortDirection.INPUT else PortDirection.INPUT
            declarations = ", ".join(
                f"{direction(item_direction).value} logic [{width-1}:0] {physical}" if width > 1 else f"{direction(item_direction).value} logic {physical}"
                for physical, item_direction, width in table.values()
            )
            stubs.append(f"module {name}({declarations}); endmodule")
        return "\n".join(stubs)

    @staticmethod
    def _harness_fixture(cpu_semantic=False):
        specs, facts = zip(_module("cpu_h", "initiator", "axi_lite"), _module("ip_h", "target", "axi_lite", 0x22000000))
        spec = system_spec(list(specs))
        discovery = DiscoveryResult(("/cpu_h.sv", "/ip_h.sv"), facts)
        plan = plan_system(spec, discovery)
        if not plan.valid:
            raise AssertionError(plan.validation_issues)
        ir = build_soc_ir_v2(spec, discovery, plan, source_digests={"cpu_h": "1" * 64, "ip_h": "2" * 64}, analysis_manifest_digest="3" * 64)
        soc = emit_soc_ir_v4(ir, module_name="harness_soc")
        layout = None
        if cpu_semantic:
            capability = soc.fabric_capability
            layout = build_cpu_semantic_v4_layout(build_axi_lite_v4_layout(
                AxiLiteV4Capability(
                    capability.address_width, capability.data_width,
                    capability.awprot_present, capability.arprot_present,
                    max_write_outstanding=capability.write_reorder_depth,
                    max_read_outstanding=capability.read_reorder_depth,
                )
            ))
        return emit_protocol_harness_v4(soc, layout=layout)

    def test_v4_soc_replaces_fabric_and_compiles_with_trace_boundary(self):
        specs, facts = zip(_module("cpu_v4", "initiator", "axi_lite"), _module("ip_v4", "target", "axi_lite", 0x20000000))
        spec = system_spec(list(specs))
        discovery = DiscoveryResult(("/cpu_v4.sv", "/ip_v4.sv"), facts)
        plan = plan_system(spec, discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        ir = build_soc_ir_v2(spec, discovery, plan, source_digests={"cpu_v4": "1" * 64, "ip_v4": "2" * 64}, analysis_manifest_digest="3" * 64)
        emitted = emit_soc_ir_v4(ir)
        self.assertEqual(emitted.schema, "myfuzz.generated-soc/v4")
        self.assertIn("infrastructure_reset", emitted.rtl)
        self.assertIn("trace_awvalid", emitted.rtl)
        self.assertIn("myfuzz_generated_soc_v4_fabric", emitted.rtl)
        stubs = []
        for name, role, table in (("cpu_v4", "initiator", AXI), ("ip_v4", "target", AXI)):
            def direction(value):
                from myfuzz.builder import PortDirection
                if role != "initiator": return value
                return PortDirection.OUTPUT if value == PortDirection.INPUT else PortDirection.INPUT
            declarations = ", ".join(
                f"{direction(item_direction).value} logic [{width-1}:0] {physical}" if width > 1 else f"{direction(item_direction).value} logic {physical}"
                for physical, item_direction, width in table.values()
            )
            stubs.append(f"module {name}({declarations}); endmodule")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "soc.sv"
            output = Path(directory) / "soc.out"
            source.write_text(emitted.rtl + "\n".join(stubs))
            result = subprocess.run(["iverilog", "-g2012", "-s", emitted.module_name, "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_ultra_loader_bindings_are_not_rewritten_as_cpu_master_signals(self):
        spec = load_system_spec(ROOT / "examples/protocol_system_v2/ultra_riscv_axi_ram.json")
        analyzed = analyze_declared_components_v2(spec, ROOT)
        plan = plan_system(spec, analyzed.discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        base = build_soc_ir_v2(
            spec,
            analyzed.discovery,
            plan,
            source_digests=analyzed.source_digests,
            analysis_manifest_digest=analyzed.analysis_manifest_digest,
        )
        profile = builtin_cpu_execution_profile("ultra_riscv")
        services = plan_system_services(base.address_views, profile)
        ir = add_system_services_to_soc_ir(base, services)
        emitted = emit_soc_ir_v4(
            ir,
            module_name="ultra_loader_soc_v4",
            rom_install_backend=dict(profile.rom_install_backend),
            boot_rom_words=16384,
            boot_rom_load_base=0,
        )
        self.assertIn(".loader_awaddr(rom_loader_awaddr)", emitted.rtl)
        self.assertIn(".loader_araddr(rom_loader_araddr)", emitted.rtl)
        self.assertIn(".m_awaddr(cpu_m_awaddr)", emitted.rtl)
        self.assertIn(".m_araddr(cpu_m_araddr)", emitted.rtl)
        self.assertIn(".cpu_reset(cpu_execution_reset)", emitted.rtl)

    def test_cpu_reset_gate_replaces_reset_domain_expression(self):
        spec = load_system_spec(ROOT / "examples/protocol_system_v2/picorv32_axi_ram.json")
        analyzed = analyze_declared_components_v2(spec, ROOT)
        plan = plan_system(spec, analyzed.discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        base = build_soc_ir_v2(
            spec,
            analyzed.discovery,
            plan,
            source_digests=analyzed.source_digests,
            analysis_manifest_digest=analyzed.analysis_manifest_digest,
        )
        profile = builtin_cpu_execution_profile("picorv32")
        services = plan_system_services(base.address_views, profile)
        ir = add_system_services_to_soc_ir(base, services)
        emitted = emit_soc_ir_v4(
            ir,
            module_name="picorv32_reset_domain_soc_v4",
            rom_install_backend=dict(profile.rom_install_backend),
            boot_rom_words=16384,
            boot_rom_load_base=0,
        )
        self.assertIn(".resetn(cpu_resetn)", emitted.rtl)
        self.assertNotIn(".resetn((resetn&&!domain_reset_active[0]))", emitted.rtl)

    def test_unseen_axi_lite_protection_signals_are_boundary_wired(self):
        specs, facts = zip(
            _prot_module("cpu_prot", "initiator"),
            _prot_module("ip_prot", "target", 0x21000000),
        )
        spec = system_spec(list(specs))
        discovery = DiscoveryResult(("/cpu_prot.sv", "/ip_prot.sv"), facts)
        plan = plan_system(spec, discovery, registry=axi_lite_v4_profile_registry())
        self.assertTrue(plan.valid, plan.validation_issues)
        ir = build_soc_ir_v2(
            spec, discovery, plan,
            source_digests={"cpu_prot": "1" * 64, "ip_prot": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )
        emitted = emit_soc_ir_v4(ir, module_name="prot_soc")
        self.assertTrue(emitted.fabric_capability.awprot_present)
        self.assertTrue(emitted.fabric_capability.arprot_present)
        self.assertIn("trace_awprot", emitted.rtl)
        self.assertIn(".s_axi_awprot(s_awprot[0])", emitted.rtl)
        self.assertIn("m_awaddr,m_awprot,m_wvalid", emitted.rtl)
        self.assertIn("m_araddr,m_arprot,m_rvalid", emitted.rtl)
        stubs = []
        for name, role in (("cpu_prot", "initiator"), ("ip_prot", "target")):
            def direction(value):
                if role != "initiator":
                    return value
                return PortDirection.OUTPUT if value == PortDirection.INPUT else PortDirection.INPUT
            declarations = ", ".join(
                f"{direction(item_direction).value} logic [{width-1}:0] {physical}" if width > 1 else f"{direction(item_direction).value} logic {physical}"
                for physical, item_direction, width in AXI_PROT.values()
            )
            stubs.append(f"module {name}({declarations}); endmodule")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "soc.sv"
            output = Path(directory) / "soc.out"
            source.write_text(emitted.rtl + "\n".join(stubs))
            result = subprocess.run(["iverilog", "-g2012", "-s", emitted.module_name, "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_protocol_harness_compiles_shared_raw_and_protocol_lanes(self):
        harness = self._harness_fixture()
        self.assertEqual({lane.lane for lane in harness.layout.lanes}, {"RAW_ESCAPE", "PROTOCOL_WAVEFORM", "ADVERSARIAL_MUTATION"})
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "harness.sv"
            output = Path(directory) / "harness.out"
            source.write_text(harness.rtl + self._stubs())
            result = subprocess.run(["iverilog", "-g2012", "-s", harness.module_name, "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_protocol_harness_executes_each_first_stage_lane(self):
        harness = self._harness_fixture()
        width = harness.layout.record_width_bytes * 8
        for lane, submode in ((1, 1), (2, 3), (3, 4)):
            tb = f"""
module tb;
  logic clk=0,resetn=0,start=0,finish=0,valid=0;
  logic ready,consumed,done,format_error,runtime_error; logic [2:0] latched;
  always #1 clk=~clk;
  {harness.module_name} dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.end_i(finish),
    .lane_i(3'd{lane}),.submode_i(8'd{submode}),.record_i({width}'d0),.record_valid_i(valid),
    .layout_digest_i(256'h{harness.layout.digest}),.soc_digest_i(256'h{harness.soc_digest}),
    .record_ready_o(ready),.record_consumed_o(consumed),.done_o(done),.format_error_o(format_error),
    .runtime_error_o(runtime_error),.lane_latched_o(latched));
  initial begin
    repeat(2) @(posedge clk); resetn=1; @(posedge clk); start=1; @(posedge clk); start=0;
    repeat(2) @(posedge clk); if(!ready) $fatal(1,"lane not ready"); valid=1; @(posedge clk); valid=0;
    finish=1; @(posedge clk); finish=0; @(posedge clk);
    if(!done||format_error||runtime_error||latched!=3'd{lane}) $fatal(1,"lane smoke failed");
    $finish;
  end
endmodule
"""
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "smoke.sv"
                output = Path(directory) / "smoke.out"
                source.write_text(harness.rtl + self._stubs() + tb)
                compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)], capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                executed = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
                self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)

    def test_cpu_semantic_layout_enables_lane_four_and_releases_cpu_master(self):
        harness = self._harness_fixture(cpu_semantic=True)
        width = harness.layout.record_width_bytes * 8
        self.assertIn("assign select_trace=(lane_latched!=3'd4)", harness.rtl)
        tb = f"""
module tb;
  logic clk=0,resetn=0,start=0,finish=0,valid=0;
  logic ready,consumed,done,format_error,runtime_error; logic [2:0] latched;
  always #1 clk=~clk;
  {harness.module_name} dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.end_i(finish),
    .lane_i(3'd4),.submode_i(8'd6),.record_i({width}'d65),.record_valid_i(valid),
    .cpu_execute_i(1'b0),.cpu_ready_o(),
    .layout_digest_i(256'h{harness.layout.digest}),.soc_digest_i(256'h{harness.soc_digest}),
    .record_ready_o(ready),.record_consumed_o(consumed),.done_o(done),.format_error_o(format_error),
    .runtime_error_o(runtime_error),.lane_latched_o(latched));
  initial begin
    repeat(2) @(posedge clk); resetn=1; @(posedge clk); start=1; @(posedge clk); start=0;
    repeat(2) @(posedge clk); if(!ready) $fatal(1,"CPU lane not ready");
    valid=1; @(posedge clk); if(!consumed) $fatal(1,"CPU byte not consumed"); valid=0;
    finish=1; @(posedge clk); finish=0; @(posedge clk);
    if(!done||format_error||runtime_error||latched!=3'd4) $fatal(1,"CPU lane smoke failed");
    $finish;
  end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "cpu_lane.sv"
            output = Path(directory) / "cpu_lane.out"
            source.write_text(harness.rtl + self._stubs() + tb)
            compiled = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)

    def test_cpu_semantic_execution_gate_holds_cpu_reset_until_release(self):
        harness = self._harness_fixture(cpu_semantic=True)
        width = harness.layout.record_width_bytes * 8
        tb = f"""
module tb;
  logic clk=0,resetn=0,start=0,finish=0,valid=0,execute=0;
  logic ready,consumed,done,format_error,runtime_error,cpu_ready; logic [2:0] latched;
  always #1 clk=~clk;
  {harness.module_name} dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.end_i(finish),
    .lane_i(3'd4),.submode_i(8'd6),.record_i({width}'d65),.record_valid_i(valid),
    .cpu_execute_i(execute),.cpu_ready_o(cpu_ready),
    .layout_digest_i(256'h{harness.layout.digest}),.soc_digest_i(256'h{harness.soc_digest}),
    .record_ready_o(ready),.record_consumed_o(consumed),.done_o(done),
    .format_error_o(format_error),.runtime_error_o(runtime_error),.lane_latched_o(latched));
  initial begin
    repeat(2) @(posedge clk); resetn=1; @(posedge clk); start=1; @(posedge clk); start=0;
    repeat(3) @(posedge clk); if(cpu_ready) $fatal(1,"CPU escaped execution gate");
    execute=1; repeat(2) @(posedge clk); if(!cpu_ready) $fatal(1,"CPU did not leave reset");
    finish=1; @(posedge clk); finish=0; @(posedge clk);
    if(!done||format_error||runtime_error) $fatal(1,"CPU gate smoke failed");
    $finish;
  end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "cpu_gate.sv"
            output = Path(directory) / "cpu_gate.out"
            source.write_text(harness.rtl + self._stubs() + tb)
            compiled = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)

    def test_literal_protocol_violation_is_reported_without_format_rejection(self):
        harness = self._harness_fixture()
        width = harness.layout.record_width_bytes * 8
        protocol = next(item for item in harness.layout.lanes if item.lane == "PROTOCOL_WAVEFORM")
        record = 0
        for field in protocol.fields:
            if field.name in {"literal_awvalid", "literal_dut_reset"}:
                record |= 1 << field.offset
        tb = f"""
module tb;
  logic clk=0,resetn=0,start=0,finish=0,valid=0;
  logic ready,consumed,done,format_error,runtime_error,observed_valid;
  logic [2:0] latched; logic [7:0] rule; logic [63:0] violation_cycle; logic [255:0] snapshot;
  always #1 clk=~clk;
  {harness.module_name} dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.end_i(finish),
    .lane_i(3'd2),.submode_i(8'd3),.record_i({width}'h{record:x}),.record_valid_i(valid),
    .layout_digest_i(256'h{harness.layout.digest}),.soc_digest_i(256'h{harness.soc_digest}),
    .record_ready_o(ready),.record_consumed_o(consumed),.done_o(done),.format_error_o(format_error),
    .runtime_error_o(runtime_error),.lane_latched_o(latched),.observed_protocol_valid_o(observed_valid),
    .violation_rule_o(rule),.violation_cycle_o(violation_cycle),.violation_snapshot_o(snapshot));
  initial begin
    repeat(2) @(posedge clk); resetn=1; @(posedge clk); start=1; @(posedge clk); start=0;
    repeat(2) @(posedge clk); valid=1; @(posedge clk); valid=0; repeat(2) @(posedge clk);
    if(format_error||runtime_error||observed_valid||rule==0) $fatal(1,"violation classification failed");
    finish=1; @(posedge clk); finish=0; @(posedge clk); if(!done) $fatal(1,"missing done");
    $finish;
  end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "violation.sv"
            output = Path(directory) / "violation.out"
            source.write_text(harness.rtl + self._stubs() + tb)
            compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)

    def test_v4_coverage_is_projected_and_frozen_with_64_bit_epoch(self):
        base = self._harness_fixture()
        # Rebuild the fixture SoC from the embedded RTL and add the instrumentation boundary.
        specs, facts = zip(_module("cpu_h", "initiator", "axi_lite"), _module("ip_h", "target", "axi_lite", 0x22000000))
        spec = system_spec(list(specs)); discovery = DiscoveryResult(("/cpu_h.sv", "/ip_h.sv"), facts)
        plan = plan_system(spec, discovery)
        ir = build_soc_ir_v2(spec, discovery, plan, source_digests={"cpu_h": "1" * 64, "ip_h": "2" * 64}, analysis_manifest_digest="3" * 64)
        soc = emit_soc_ir_v4(ir, module_name="coverage_soc")
        rtl = soc.rtl.replace(
            ");", ",\n  input logic [63:0] coverage_epoch_i,\n  output logic [2:0] __vi_coverage\n);", 1,
        ).replace("\nendmodule\n", "\n  assign __vi_coverage=coverage_epoch_i[2:0];\nendmodule\n", 1)
        soc = replace(soc, rtl=rtl, external_port_specs=soc.external_port_specs + (
            SocExternalPort("coverage_epoch_i", "input", 64, "coverage"),
            SocExternalPort("__vi_coverage", "output", 3, "coverage"),
        ))
        coverage = CoverageABIV2("b" * 64, "__vi_coverage", 2, 64, (
            {"included": True, "offset": 0, "source_offset": 0},
            {"included": True, "offset": 1, "source_offset": 2},
        ), transport_width=3)
        harness = emit_protocol_harness_v4(soc, coverage_abi=coverage)
        width = harness.layout.record_width_bytes * 8
        tb = f"""
module tb;
 logic clk=0,resetn=0,start=0,finish=0,valid=0;logic ready,consumed,done,fe,re,ov,cv;logic[2:0]lane;logic[1:0]cov;logic[7:0]rule;logic[63:0]vc;logic[255:0]vs;
 always #1 clk=~clk;
 {harness.module_name} dut(.clk_i(clk),.harness_resetn_i(resetn),.start_i(start),.end_i(finish),.lane_i(3'd1),.submode_i(8'd1),
 .record_i({width}'d0),.record_valid_i(valid),.layout_digest_i(256'h{harness.layout.digest}),.soc_digest_i(256'h{harness.soc_digest}),
 .record_ready_o(ready),.record_consumed_o(consumed),.done_o(done),.format_error_o(fe),.runtime_error_o(re),.lane_latched_o(lane),
 .observed_protocol_valid_o(ov),.violation_rule_o(rule),.violation_cycle_o(vc),.violation_snapshot_o(vs),
 .coverage_epoch_i(64'd5),.coverage_abi_digest_i(256'h{coverage.manifest_digest}),.coverage_o(cov),.coverage_live_o(),.coverage_valid_o(cv));
 initial begin repeat(2)@(posedge clk);resetn=1;@(posedge clk);start=1;@(posedge clk);start=0;repeat(2)@(posedge clk);finish=1;@(posedge clk);finish=0;@(posedge clk);
 if(!done||!cv||cov!=2'b11||fe||re)$fatal(1,"coverage freeze failed");$finish;end
endmodule
"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "coverage.sv"; output = Path(directory) / "coverage.out"
            source.write_text(harness.rtl + self._stubs() + tb)
            compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)


if __name__ == "__main__":
    unittest.main()
