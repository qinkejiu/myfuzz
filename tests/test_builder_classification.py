import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    DiscoveredInstance,
    DiscoveredModule,
    DiscoveredPort,
    DiscoveryResult,
    ModuleKind,
    PortDirection,
    SystemSpec,
    builtin_profile_registry,
    classify_modules,
)


def module(name, ports=(), instances=()):
    return DiscoveredModule(name, f"/{name}.sv", "rtl", {}, tuple(ports), tuple(instances), True, "test")


def port(name, direction):
    return DiscoveredPort(name, PortDirection(direction), 1, None)


class ClassificationTest(unittest.TestCase):
    def test_builtin_profile_has_channels_address_and_constraints(self):
        profiles = builtin_profile_registry().query("simple_bus", "target")
        self.assertEqual(len(profiles), 1)
        self.assertEqual([channel.name for channel in profiles[0].channels], ["request", "response"])
        self.assertTrue(profiles[0].address_rule.requires_window)
        self.assertEqual(profiles[0].address_rule.default_size, 4096)
        self.assertTrue(profiles[0].constraints)

    def test_user_kind_is_authoritative(self):
        spec = self._spec([{"name": "odd", "kind": "debug", "source_set": "rtl", "ports": {}}])
        discovery = DiscoveryResult(("/odd.sv",), (module("odd", [port("req_o", "output")]),))
        result = classify_modules(spec, discovery)[0]
        self.assertEqual(result.kind, ModuleKind.DEBUG)
        self.assertEqual(result.source, "user")

    def test_undeclared_modules_are_inferred_structurally(self):
        spec = self._spec([{"name": "declared", "kind": "cpu", "source_set": "rtl", "ports": {}}])
        discovery = DiscoveryResult(("/all.sv",), (
            module("master", [port("req_o", "output")]),
            module("target", [port("req_i", "input")]),
            module("bridge", [port("req_o", "output"), port("req_i", "input")]),
            module("container", instances=[DiscoveredInstance("u", "target")]),
            module("mystery", [port("feature", "input")]),
        ))
        kinds = {item.module: item.kind for item in classify_modules(spec, discovery)}
        self.assertEqual(kinds["master"], ModuleKind.BUS_MASTER)
        self.assertEqual(kinds["target"], ModuleKind.BUS_SLAVE)
        self.assertEqual(kinds["bridge"], ModuleKind.BRIDGE)
        self.assertEqual(kinds["container"], ModuleKind.INTERCONNECT)
        self.assertEqual(kinds["mystery"], ModuleKind.UNKNOWN)

    @staticmethod
    def _spec(modules):
        return SystemSpec.from_dict({
            "schema_version": 1, "name": "classify",
            "sources": [{"name": "rtl", "rtl_files": ["all.sv"]}],
            "modules": modules,
        })


if __name__ == "__main__":
    unittest.main()
