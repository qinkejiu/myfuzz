import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    DiscoveredModule, DiscoveredPort, DiscoveryResult, InputValidationError, PortDirection,
    build_soc_ir_v2, plan_system,
)
from myfuzz.builder.input_model import (  # noqa: E402
    AddressAliasPolicy, AddressMode, AddressRequest, ClockDomain,
)
from builder_fixtures import module_spec, rtl_module, system_spec  # noqa: E402


class SoCIRV2PlannerTest(unittest.TestCase):
    def test_internal_dependency_modules_are_discovered_but_not_soc_components(self):
        spec, discovery, _ = self._fixture()
        dependency = DiscoveredModule(
            "internal_helper", "/internal_helper.sv", "rtl", {},
            (DiscoveredPort("opaque_i", PortDirection.INPUT, 1, None),), (), False,
            "instantiated by a declared wrapper",
        )
        expanded = replace(discovery, modules=discovery.modules + (dependency,))
        replanned = plan_system(spec, expanded)
        self.assertTrue(replanned.valid, replanned.validation_issues)
        self.assertFalse(any(item.module == "internal_helper" for item in replanned.unknown_ports))
        ir = build_soc_ir_v2(
            spec, expanded, replanned,
            source_digests={"cpu": "1" * 64, "ram": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )
        self.assertNotIn("internal_helper", {item["instance_id"] for item in ir.instances})

    def _fixture(self):
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        spec = system_spec(modules)
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (rtl_module("cpu", "initiator"), rtl_module("ram", "target")))
        return spec, discovery, plan_system(spec, discovery)

    def test_same_facts_emit_identical_content_addressed_soc(self):
        spec, discovery, plan = self._fixture()
        kwargs = {"source_digests": {"cpu": "1" * 64, "ram": "2" * 64}, "analysis_manifest_digest": "3" * 64}
        first = build_soc_ir_v2(spec, discovery, plan, **kwargs)
        second = build_soc_ir_v2(spec, discovery, plan, **kwargs)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.address_views[0]["transform"], "local = global - global_base")
        self.assertEqual(first.address_views[0]["alias_policy"], "reject")
        self.assertEqual(first.provenance["planner"], "myfuzz.protocol-driven/v2")

    def test_missing_source_digest_and_multiple_clocks_fail_closed(self):
        spec, discovery, plan = self._fixture()
        with self.assertRaisesRegex(InputValidationError, "missing proven source digest"):
            build_soc_ir_v2(spec, discovery, plan, source_digests={"cpu": "1" * 64}, analysis_manifest_digest="3" * 64)
        multi_clock = replace(spec, clock_domains=(ClockDomain("a", "clk"), ClockDomain("b", "clk")))
        with self.assertRaisesRegex(InputValidationError, "one clock domain"):
            build_soc_ir_v2(multi_clock, discovery, plan, source_digests={"cpu": "1" * 64, "ram": "2" * 64}, analysis_manifest_digest="3" * 64)

    def test_window_larger_than_local_address_space_rejects_alias(self):
        spec, discovery, plan = self._fixture()
        bindings = tuple(replace(item, width=4) if item.module == "ram" and item.semantic.endswith(".address") else item
                         for item in plan.port_bindings)
        aliased = replace(plan, port_bindings=bindings)
        with self.assertRaisesRegex(InputValidationError, "aliases.*local address space"):
            build_soc_ir_v2(spec, discovery, aliased, source_digests={"cpu": "1" * 64, "ram": "2" * 64}, analysis_manifest_digest="3" * 64)

    def test_explicit_mirror_policy_allows_narrow_local_address(self):
        spec, discovery, plan = self._fixture()
        window = plan.address_plan.windows[0]
        ram = replace(spec.modules[1], address=AddressRequest(
            AddressMode.FIXED, window.size, window.base, window.size,
            AddressAliasPolicy.ALLOW_MIRROR,
        ))
        mirrored_spec = replace(spec, modules=(spec.modules[0], ram))
        bindings = tuple(
            replace(item, width=4)
            if item.module == "ram" and item.semantic.endswith(".address") else item
            for item in plan.port_bindings
        )
        mirrored = replace(plan, port_bindings=bindings)

        ir = build_soc_ir_v2(
            mirrored_spec, discovery, mirrored,
            source_digests={"cpu": "1" * 64, "ram": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )

        self.assertEqual(ir.address_views[0]["alias_policy"], "allow_mirror")
        self.assertIn("mod 2^4", ir.address_views[0]["transform"])

    def test_authoritative_interrupt_ports_create_internal_and_external_edges(self):
        cpu = module_spec("cpu", "cpu", "initiator")
        ram = module_spec("ram", "ram", "target")
        cpu["ports"]["irq_i"] = {"direction": "input", "type": "interrupt_sink", "width": 32}
        ram["ports"]["irq_o"] = {"direction": "output", "type": "interrupt_source", "width": 2}
        spec = system_spec([cpu, ram])
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator", (DiscoveredPort("irq_i", PortDirection.INPUT, 32, None),)),
            rtl_module("ram", "target", (DiscoveredPort("irq_o", PortDirection.OUTPUT, 2, None),)),
        ))
        ir = build_soc_ir_v2(
            spec, discovery, plan_system(spec, discovery),
            source_digests={"cpu": "1" * 64, "ram": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )
        self.assertEqual(len(ir.interrupt_edges), 2)
        internal, external = ir.interrupt_edges
        self.assertEqual(internal["source"]["kind"], "internal")
        self.assertEqual(internal["source"]["instance_id"], "ram")
        self.assertEqual(internal["mapper_offset"], 0)
        self.assertEqual(internal["sink"]["port"], "irq_i")
        self.assertEqual(external["source"]["kind"], "external")
        self.assertEqual(internal["provenance"]["source"], "authoritative_port_annotation")

    def test_rfuzz_driven_unknown_input_is_an_external_boundary(self):
        cpu = module_spec("cpu", "cpu", "initiator")
        ram = module_spec("ram", "ram", "target", unknown_ports={
            "pins_i": {
                "action": "rfuzz_drive", "reason": "bit-level environment input",
                "reset_behavior": "zero",
            },
        })
        spec = system_spec([cpu, ram])
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator"),
            rtl_module("ram", "target", (
                DiscoveredPort("pins_i", PortDirection.INPUT, 8, None),
            )),
        ))

        ir = build_soc_ir_v2(
            spec, discovery, plan_system(spec, discovery),
            source_digests={"cpu": "1" * 64, "ram": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )

        boundary = next(item for item in ir.external_boundaries if item["port"] == "pins_i")
        self.assertEqual(boundary["action"], "rfuzz_drive")
        self.assertEqual(boundary["direction"], "input")

    def test_interrupt_source_without_sink_fails_closed(self):
        cpu = module_spec("cpu", "cpu", "initiator")
        ram = module_spec("ram", "ram", "target")
        ram["ports"]["irq_o"] = {"direction": "output", "type": "interrupt_source", "width": 1}
        spec = system_spec([cpu, ram])
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator"),
            rtl_module("ram", "target", (DiscoveredPort("irq_o", PortDirection.OUTPUT, 1, None),)),
        ))
        with self.assertRaisesRegex(InputValidationError, "require one interrupt_sink"):
            build_soc_ir_v2(
                spec, discovery, plan_system(spec, discovery),
                source_digests={"cpu": "1" * 64, "ram": "2" * 64},
                analysis_manifest_digest="3" * 64,
            )

    def test_non_32_bit_interrupt_sink_fails_closed(self):
        cpu = module_spec("cpu", "cpu", "initiator")
        ram = module_spec("ram", "ram", "target")
        cpu["ports"]["irq_i"] = {"direction": "input", "type": "interrupt_sink", "width": 1}
        spec = system_spec([cpu, ram])
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator", (DiscoveredPort("irq_i", PortDirection.INPUT, 1, None),)),
            rtl_module("ram", "target"),
        ))
        with self.assertRaisesRegex(InputValidationError, "interrupt_sink width must be 32"):
            build_soc_ir_v2(
                spec, discovery, plan_system(spec, discovery),
                source_digests={"cpu": "1" * 64, "ram": "2" * 64},
                analysis_manifest_digest="3" * 64,
            )


if __name__ == "__main__":
    unittest.main()
