import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    CapabilityMismatch, InterfaceRole, builtin_backend_registry, builtin_profile_registry,
)


class BuiltinProfileTest(unittest.TestCase):
    def test_axi_lite_and_apb_profiles_are_protocol_based(self):
        registry = builtin_profile_registry()
        self.assertEqual(len(registry.query("axi_lite", InterfaceRole.INITIATOR)), 1)
        self.assertEqual(len(registry.query("axi_lite", InterfaceRole.TARGET)), 1)
        self.assertEqual(len(registry.query("apb3", InterfaceRole.TARGET)), 1)
        self.assertEqual(len(registry.query("apb4", InterfaceRole.TARGET)), 1)
        result = registry.resolve_port(
            protocol="axi_lite", interface_role="target", port_name="alien_awvalid", direction="input",
        )
        self.assertIsNone(result.annotation)
        generic = registry.resolve_port(
            protocol="axi_lite", interface_role="target", port_name="s_axi_awvalid", direction="input",
        )
        self.assertEqual(generic.annotation.port_type, "axi_lite.awvalid")

    def test_apb4_profile_carries_semantics_and_capabilities(self):
        profile = builtin_profile_registry().query("apb4", "target")[0]
        self.assertIn("setup_access_phases", profile.capabilities)
        self.assertIn("data_width == 32", profile.width_rules)
        self.assertTrue(any(rule.semantic == "apb4.pstrb" and rule.required for rule in profile.ports))


class BackendRegistryTest(unittest.TestCase):
    def test_selection_depends_on_protocol_graph_and_capability(self):
        registry = builtin_backend_registry()
        self.assertEqual(
            registry.select(protocols=("axi_lite",), required_capabilities=("decode",)).backend_id,
            "axi_lite_fabric",
        )
        self.assertEqual(
            registry.select(protocols=("apb4", "axi_lite"), required_capabilities=("write_strobes",)).backend_id,
            "axi_lite_to_apb4",
        )

    def test_unsupported_width_master_count_and_clock_fail_structurally(self):
        registry = builtin_backend_registry()
        cases = (
            {"protocols": ("axi_lite",), "data_width": 64},
            {"protocols": ("axi_lite",), "initiator_count": 2},
            {"protocols": ("axi_lite",), "clock_domain_count": 2},
            {"protocols": ("wishbone",)},
        )
        for request in cases:
            with self.subTest(request=request), self.assertRaises(CapabilityMismatch) as caught:
                registry.select(**request)
            self.assertTrue(caught.exception.reasons)

    def test_module_and_instance_names_are_not_registry_inputs(self):
        registry = builtin_backend_registry()
        first = registry.select(protocols=("apb3", "axi_lite"), required_capabilities=("bridge",))
        second = registry.select(protocols=("axi_lite", "apb3"), required_capabilities=("bridge",))
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
