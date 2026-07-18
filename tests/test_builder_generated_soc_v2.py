import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    DiscoveredModule, DiscoveredPort, DiscoveryResult, PortDirection,
    add_system_services_to_soc_ir, build_soc_ir_v2, builtin_cpu_execution_profile,
    build_control_plane, emit_generated_harness_v2, emit_soc_ir_v2, plan_system,
    plan_system_services, synthesize_temporal_constraints,
)
from builder_fixtures import system_spec  # noqa: E402
from myfuzz.builder.generated_soc_v2 import _service_instances  # noqa: E402


AXI = {
    "awvalid": ("s_axi_awvalid", PortDirection.INPUT, 1), "awready": ("s_axi_awready", PortDirection.OUTPUT, 1),
    "awaddr": ("s_axi_awaddr", PortDirection.INPUT, 32), "wvalid": ("s_axi_wvalid", PortDirection.INPUT, 1),
    "wready": ("s_axi_wready", PortDirection.OUTPUT, 1), "wdata": ("s_axi_wdata", PortDirection.INPUT, 32),
    "wstrb": ("s_axi_wstrb", PortDirection.INPUT, 4), "bvalid": ("s_axi_bvalid", PortDirection.OUTPUT, 1),
    "bready": ("s_axi_bready", PortDirection.INPUT, 1), "bresp": ("s_axi_bresp", PortDirection.OUTPUT, 2),
    "arvalid": ("s_axi_arvalid", PortDirection.INPUT, 1), "arready": ("s_axi_arready", PortDirection.OUTPUT, 1),
    "araddr": ("s_axi_araddr", PortDirection.INPUT, 32), "rvalid": ("s_axi_rvalid", PortDirection.OUTPUT, 1),
    "rready": ("s_axi_rready", PortDirection.INPUT, 1), "rdata": ("s_axi_rdata", PortDirection.OUTPUT, 32),
    "rresp": ("s_axi_rresp", PortDirection.OUTPUT, 2),
}
APB = {
    "paddr": ("paddr", PortDirection.INPUT, 32), "psel": ("psel", PortDirection.INPUT, 1),
    "penable": ("penable", PortDirection.INPUT, 1), "pwrite": ("pwrite", PortDirection.INPUT, 1),
    "pwdata": ("pwdata", PortDirection.INPUT, 32), "prdata": ("prdata", PortDirection.OUTPUT, 32),
    "pready": ("pready", PortDirection.OUTPUT, 1), "pslverr": ("pslverr", PortDirection.OUTPUT, 1),
}
APB4 = {**APB, "pstrb": ("pstrb", PortDirection.INPUT, 4)}


def _module(name, role, protocol, base=None):
    table = AXI if protocol == "axi_lite" else APB4 if protocol == "apb4" else APB
    def direction_for_role(direction):
        if role != "initiator":
            return direction
        return PortDirection.OUTPUT if direction == PortDirection.INPUT else PortDirection.INPUT

    ports = tuple(DiscoveredPort(physical, direction_for_role(direction), width, None)
                  for physical, direction, width in table.values())
    mapping = {semantic: physical for semantic, (physical, _direction, _width) in table.items()}
    return {
        "name": name, "kind": "cpu" if role == "initiator" else "peripheral", "source_set": "rtl",
        "ports": {}, "interfaces": [{"name": "bus", "protocol": protocol, "role": role, "ports": mapping}],
        **({"address": {"mode": "fixed", "base": base, "size": 0x100, "alignment": 0x100}} if base is not None else {}),
    }, DiscoveredModule(name, f"/{name}.sv", "rtl", {}, ports, (), True, "fixture")


class GeneratedSocV2Test(unittest.TestCase):
    def test_tcm_loader_delays_mailbox_acceptance_until_install_ready(self):
        ir = SimpleNamespace(
            service_nodes=({"node_id": "mailbox", "kind": "control_mailbox"},),
            reset_domains=(),
            logical_modules=(),
        )
        windows = (("mailbox", 0x10000000, 0x1000, "axi_lite"),)
        without_loader = "\n".join(_service_instances(ir, windows, object(), None))
        with_loader = "\n".join(_service_instances(ir, windows, object(), {"owner": "cpu"}))
        self.assertIn(".start_i(control_start)", without_loader)
        self.assertIn(".start_i((control_start&&rom_install_ready))", with_loader)

    def test_unseen_axi_and_two_apb_targets_compile_from_socir(self):
        specs, facts = zip(_module("cpu_unseen", "initiator", "axi_lite"),
                           _module("axi_weird", "target", "axi_lite", 0x20000000),
                           _module("apb_alpha", "target", "apb3", 0x20001000),
                           _module("apb_beta", "target", "apb4", 0x20002000))
        spec = system_spec(list(specs))
        discovery = DiscoveryResult(tuple(f"/{name}.sv" for name in ("cpu_unseen", "axi_weird", "apb_alpha", "apb_beta")), facts)
        plan = plan_system(spec, discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        ir = build_soc_ir_v2(spec, discovery, plan,
                             source_digests={name: f"{index + 1:064x}" for index, name in enumerate(("cpu_unseen", "axi_weird", "apb_alpha", "apb_beta"))},
                             analysis_manifest_digest="f" * 64)
        emitted = emit_soc_ir_v2(ir)
        self.assertEqual(emitted.fabric_slots, ("apb_alpha", "apb_beta", "axi_weird"))
        stubs = []
        for name, role, table in (("cpu_unseen", "initiator", AXI), ("axi_weird", "target", AXI),
                                  ("apb_alpha", "target", APB), ("apb_beta", "target", APB4)):
            def stub_direction(direction):
                if role != "initiator":
                    return direction
                return PortDirection.OUTPUT if direction == PortDirection.INPUT else PortDirection.INPUT

            declarations = ", ".join(
                f"{stub_direction(direction).value} logic [{width-1}:0] {physical}" if width > 1
                else f"{stub_direction(direction).value} logic {physical}"
                for physical, direction, width in table.values()
            )
            assignments = " assign pslverr=1'b0; assign pready=1'b1; assign prdata='0;" if table in (APB, APB4) else ""
            stubs.append(f"module {name}({declarations});{assignments} endmodule")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "soc.sv"; executable = root / "soc.out"
            source.write_text(emitted.rtl + "\n".join(stubs))
            result = subprocess.run(["iverilog", "-g2012", "-s", emitted.module_name, "-o", str(executable), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            services = plan_system_services(ir.address_views, builtin_cpu_execution_profile("picorv32"))
            complete_ir = add_system_services_to_soc_ir(ir, services)
            control = build_control_plane(complete_ir, cpu_profile_digest=services.profile_digest)
            complete = emit_soc_ir_v2(complete_ir, module_name="complete_unseen_soc", control_plane=control)
            self.assertIn("__myfuzz_boot_rom", complete.fabric_slots)
            self.assertIn("BOOT_ROM_HEX_FILE", complete.rtl)
            self.assertIn("control_raw_bits", complete.external_ports)
            source.write_text(complete.rtl + "\n".join(stubs))
            result = subprocess.run(["iverilog", "-g2012", "-s", complete.module_name,
                                     "-o", str(executable), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            constraints = synthesize_temporal_constraints(complete_ir, control)
            harness = emit_generated_harness_v2(
                complete, control, constraints, module_name="complete_unseen_harness",
            )
            source.write_text(harness.rtl + "\n".join(stubs))
            result = subprocess.run(["iverilog", "-g2012", "-s", harness.module_name,
                                     "-o", str(executable), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_authoritative_irq_ports_wire_through_generated_mapper(self):
        cpu_spec, cpu_fact = _module("cpu_irq", "initiator", "axi_lite")
        ip_spec, ip_fact = _module("ip_irq", "target", "axi_lite", 0x20000000)
        cpu_spec["ports"]["irq_i"] = {
            "direction": "input", "type": "interrupt_sink", "width": 32,
        }
        ip_spec["ports"]["irq_o"] = {
            "direction": "output", "type": "interrupt_source", "width": 2,
        }
        cpu_fact = replace(cpu_fact, ports=cpu_fact.ports + (
            DiscoveredPort("irq_i", PortDirection.INPUT, 32, None),
        ))
        ip_fact = replace(ip_fact, ports=ip_fact.ports + (
            DiscoveredPort("irq_o", PortDirection.OUTPUT, 2, None),
        ))
        spec = system_spec([cpu_spec, ip_spec])
        discovery = DiscoveryResult(("/cpu_irq.sv", "/ip_irq.sv"), (cpu_fact, ip_fact))
        plan = plan_system(spec, discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        ir = build_soc_ir_v2(
            spec, discovery, plan,
            source_digests={"cpu_irq": "1" * 64, "ip_irq": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )
        services = plan_system_services(ir.address_views, builtin_cpu_execution_profile("picorv32"))
        complete_ir = add_system_services_to_soc_ir(ir, services)
        emitted = emit_soc_ir_v2(complete_ir, module_name="irq_soc")
        self.assertIn(".irq_sources(external_irq_sources|internal_irq_sources)", emitted.rtl)
        self.assertIn(".cpu_irq(mapped_cpu_irq)", emitted.rtl)
        self.assertIn(".irq_i(mapped_cpu_irq)", emitted.rtl)
        self.assertIn(".irq_o(irq_source_0)", emitted.rtl)

        def declarations(role, table, extra):
            def direction(direction):
                if role != "initiator":
                    return direction
                return PortDirection.OUTPUT if direction == PortDirection.INPUT else PortDirection.INPUT
            base = [
                f"{direction(item_direction).value} logic [{width-1}:0] {physical}"
                if width > 1 else f"{direction(item_direction).value} logic {physical}"
                for physical, item_direction, width in table.values()
            ]
            return ", ".join(base + extra)

        stubs = (
            f"module cpu_irq({declarations('initiator', AXI, ['input logic [31:0] irq_i'])}); endmodule\n"
            f"module ip_irq({declarations('target', AXI, ['output logic [1:0] irq_o'])});"
            " assign irq_o=2'b01; endmodule\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "irq_soc.sv"
            executable = root / "irq_soc.out"
            source.write_text(emitted.rtl + stubs)
            result = subprocess.run(
                ["iverilog", "-g2012", "-s", emitted.module_name, "-o", str(executable), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
