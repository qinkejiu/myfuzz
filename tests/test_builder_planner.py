import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    DiscoveredModule,
    DiscoveredPort,
    DiscoveryResult,
    PortDirection,
    SystemSpec,
    plan_system,
)


SIGNALS = {
    "request": (1, "req"), "write_enable": (1, "we"), "address": (32, "addr"),
    "write_data": (32, "wdata"), "read_data": (32, "rdata"), "grant": (1, "gnt"),
}


def rtl_module(name, role, extra=(), address_width=32):
    directions = {
        "initiator": {"request": "output", "write_enable": "output", "address": "output", "write_data": "output", "read_data": "input", "grant": "input"},
        "target": {"request": "input", "write_enable": "input", "address": "input", "write_data": "input", "read_data": "output", "grant": "output"},
    }[role]
    ports = [
        DiscoveredPort(f"{prefix}_{'o' if directions[semantic] == 'output' else 'i'}", PortDirection(directions[semantic]),
                       address_width if semantic == "address" else width, None)
        for semantic, (width, prefix) in SIGNALS.items()
    ]
    ports.extend(extra)
    return DiscoveredModule(name, f"/{name}.sv", "rtl", {}, tuple(ports), (), True, "test")


def module_spec(name, kind, role, address=None, unknown_ports=None):
    directions = {
        "initiator": {"request": "output", "write_enable": "output", "address": "output", "write_data": "output", "read_data": "input", "grant": "input"},
        "target": {"request": "input", "write_enable": "input", "address": "input", "write_data": "input", "read_data": "output", "grant": "output"},
    }[role]
    ports = {
        semantic: f"{prefix}_{'o' if directions[semantic] == 'output' else 'i'}"
        for semantic, (_, prefix) in SIGNALS.items()
    }
    result = {
        "name": name, "kind": kind, "source_set": "rtl", "ports": {},
        "interfaces": [{"name": "bus", "protocol": "simple_bus", "role": role, "ports": ports}],
    }
    if address:
        result["address"] = address
    if unknown_ports:
        result["unknown_ports"] = unknown_ports
    return result


class PlannerTest(unittest.TestCase):
    def test_direct_protocol_connection_and_addresses(self):
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        spec = self._spec(modules)
        discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (
            rtl_module("cpu", "initiator"), rtl_module("ram", "target"),
        ))
        plan = plan_system(spec, discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        self.assertEqual(plan.address_plan.windows[0].size, 4096)
        self.assertEqual(len(plan.graph.connections), 6)
        self.assertFalse(plan.virtual_modules)

    def test_multi_master_multi_target_uses_virtual_fabric(self):
        modules = [
            module_spec("cpu", "cpu", "initiator"), module_spec("dma", "dma", "initiator"),
            module_spec("ram", "ram", "target", {"mode": "fixed", "base": 0, "size": 4096}),
            module_spec("uart", "peripheral", "target"),
        ]
        spec = self._spec(modules)
        discovery = DiscoveryResult(tuple(f"/{name}.sv" for name in ("cpu", "dma", "ram", "uart")), tuple(
            rtl_module(name, role) for name, role in (
                ("cpu", "initiator"), ("dma", "initiator"), ("ram", "target"), ("uart", "target")
            )
        ))
        plan = plan_system(spec, discovery)
        self.assertTrue(plan.valid, plan.validation_issues)
        self.assertIn("__fabric_simple_bus", plan.virtual_modules)
        self.assertEqual(len(plan.address_plan.windows), 2)
        self.assertEqual(len(plan.graph.connections), 24)
        self.assertTrue(any(item.kind.value == "handshake" for item in plan.graph.constraints))

    def test_narrow_target_address_uses_virtual_fabric_projection(self):
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        plan = plan_system(
            self._spec(modules),
            DiscoveryResult(("/cpu.sv", "/ram.sv"), (
                rtl_module("cpu", "initiator"),
                rtl_module("ram", "target", address_width=16),
            )),
        )
        self.assertTrue(plan.valid, plan.validation_issues)
        self.assertIn("__fabric_simple_bus", plan.virtual_modules)
        self.assertTrue(any(
            item.target.module == "ram" and item.target.port == "addr_i"
            and "low 16 of 32 address bits" in item.expression
            for item in plan.graph.constraints
        ))

    def test_unknown_input_policy_and_output_observation_are_integrated(self):
        extra = (
            DiscoveredPort("rx_i", PortDirection.INPUT, 1, None),
            DiscoveredPort("tx_o", PortDirection.OUTPUT, 1, None),
        )
        modules = [
            module_spec("cpu", "cpu", "initiator"),
            module_spec("uart", "peripheral", "target", unknown_ports={
                "rx_i": {"action": "external_input", "reason": "UART pin"}
            }),
        ]
        plan = plan_system(
            self._spec(modules),
            DiscoveryResult(("/cpu.sv", "/uart.sv"), (
                rtl_module("cpu", "initiator"), rtl_module("uart", "target", extra),
            )),
        )
        self.assertTrue(plan.valid, plan.validation_issues)
        actions = {item.port: item.action.value for item in plan.unknown_ports}
        self.assertEqual(actions, {"rx_i": "external_input", "tx_o": "observe"})

    def test_dangerous_inout_invalidates_plan(self):
        extra = (DiscoveredPort("pad", PortDirection.INOUT, 1, None),)
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("gpio", "peripheral", "target")]
        plan = plan_system(
            self._spec(modules),
            DiscoveryResult(("/cpu.sv", "/gpio.sv"), (
                rtl_module("cpu", "initiator"), rtl_module("gpio", "target", extra),
            )),
        )
        self.assertFalse(plan.valid)
        self.assertIn("unknown inout", plan.validation_issues[0])

    @staticmethod
    def _spec(modules):
        return SystemSpec.from_dict({
            "schema_version": 1, "name": "planned",
            "sources": [{"name": "rtl", "rtl_files": [f"{module['name']}.sv" for module in modules]}],
            "modules": modules,
        })


if __name__ == "__main__":
    unittest.main()
