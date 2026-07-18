import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import AddressMode, InputValidationError, SystemSpec, load_system_spec
from myfuzz.builder.input_model import AddressAliasPolicy


class InputModelTest(unittest.TestCase):
    def test_minimal_example_has_fixed_and_auto_addresses(self):
        spec = load_system_spec(ROOT / "examples" / "minimal_system.json")

        self.assertEqual(spec.schema_version, 1)
        self.assertEqual(spec.modules[1].address.mode, AddressMode.FIXED)
        self.assertEqual(spec.modules[1].address.base, 0)
        self.assertEqual(spec.modules[2].address.mode, AddressMode.AUTO)
        self.assertIsNone(spec.modules[2].address.base)
        self.assertEqual(spec.modules[0].ports["clk_i"].port_type, "clock")
        self.assertEqual(spec.modules[0].ports["clk_i"].width, 1)
        self.assertEqual(spec.modules[0].interfaces[0].protocol, "simple_bus")
        self.assertEqual(spec.modules[1].parameters["ADDR_WIDTH"], 12)
        self.assertEqual(spec.clock_domains[0].frequency_hz, 50_000_000)

    def test_auto_address_rejects_base(self):
        data = self._valid_dict()
        data["modules"][0]["address"] = {"mode": "auto", "base": 4096, "size": 256}

        with self.assertRaisesRegex(InputValidationError, r"modules\[0\]\.address\.base.*only valid"):
            SystemSpec.from_dict(data)

    def test_fixed_address_requires_base(self):
        data = self._valid_dict()
        data["modules"][0]["address"] = {"mode": "fixed", "size": 256}

        with self.assertRaisesRegex(InputValidationError, r"modules\[0\]\.address\.base.*required"):
            SystemSpec.from_dict(data)

    def test_rejects_zero_address_size(self):
        data = self._valid_dict()
        data["modules"][0]["address"] = {"mode": "auto", "size": 0}

        with self.assertRaisesRegex(InputValidationError, r"address\.size.*greater than zero"):
            SystemSpec.from_dict(data)

    def test_parses_explicit_address_mirror_policy(self):
        data = self._valid_dict()
        data["modules"][0]["address"] = {
            "mode": "fixed", "base": 0x1000, "size": 0x1000,
            "alias_policy": "allow_mirror",
        }

        address = SystemSpec.from_dict(data).modules[0].address

        self.assertEqual(address.alias_policy, AddressAliasPolicy.ALLOW_MIRROR)

    def test_rejects_misaligned_fixed_base(self):
        data = self._valid_dict()
        data["modules"][0]["address"] = {
            "mode": "fixed", "base": 0x1800, "size": 256, "alignment": 4096
        }

        with self.assertRaisesRegex(InputValidationError, r"address\.base.*aligned to 0x1000"):
            SystemSpec.from_dict(data)

    def test_rejects_duplicate_module_names(self):
        data = self._valid_dict()
        data["modules"].append(dict(data["modules"][0]))

        with self.assertRaisesRegex(InputValidationError, "duplicate module name 'unit'"):
            SystemSpec.from_dict(data)

    def test_rejects_unsupported_schema_version(self):
        data = self._valid_dict()
        data["schema_version"] = 2

        with self.assertRaisesRegex(InputValidationError, r"schema_version.*unsupported schema version 2"):
            SystemSpec.from_dict(data)

    def test_rejects_malformed_port_annotation(self):
        data = self._valid_dict()
        data["modules"][0]["ports"]["clk"] = {"direction": "sideways", "type": "clock"}

        with self.assertRaisesRegex(InputValidationError, r"ports\.clk\.direction.*input.*output.*inout"):
            SystemSpec.from_dict(data)

    def test_rejects_unknown_clock_domain(self):
        data = self._valid_dict()
        data["modules"][0]["clock_domain"] = "missing"

        with self.assertRaisesRegex(InputValidationError, "unknown clock domain 'missing'"):
            SystemSpec.from_dict(data)

    def test_rejects_duplicate_physical_interface_binding(self):
        data = self._valid_dict()
        data["modules"][0]["interfaces"] = [{
            "name": "bus", "protocol": "simple_bus", "role": "target",
            "ports": {"request": "req_i", "write_enable": "req_i"},
        }]

        with self.assertRaisesRegex(InputValidationError, "physical port.*multiple"):
            SystemSpec.from_dict(data)

    def test_parses_explicit_unknown_port_policy(self):
        data = self._valid_dict()
        data["modules"][0]["unknown_ports"] = {
            "feature_i": {"action": "tieoff", "reason": "unused mode", "value": 0}
        }
        spec = SystemSpec.from_dict(data)
        self.assertEqual(spec.modules[0].unknown_ports["feature_i"].action, "tieoff")

    def test_parses_distinct_logical_instance_rtl_module_and_component_id(self):
        data = self._valid_dict()
        data["modules"][0].update({
            "name": "ram1", "rtl_module": "shared_ram", "component_id": "ip.ram1",
        })

        module = SystemSpec.from_dict(data).modules[0]

        self.assertEqual(module.name, "ram1")
        self.assertEqual(module.rtl_module, "shared_ram")
        self.assertEqual(module.component_id, "ip.ram1")

    def test_rejects_unknown_source_ownership(self):
        data = self._valid_dict()
        data["modules"][0]["source_set"] = "missing"

        with self.assertRaisesRegex(InputValidationError, "unknown source set 'missing'"):
            SystemSpec.from_dict(data)

    def test_rejects_unknown_fields_with_location(self):
        data = self._valid_dict()
        data["modules"][0]["adress"] = {}

        with self.assertRaisesRegex(InputValidationError, r"\$\.modules\[0\].*unknown field.*adress"):
            SystemSpec.from_dict(data)

    def test_invalid_json_reports_file_location(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('{"schema_version":', encoding="utf-8")

            with self.assertRaisesRegex(InputValidationError, r"invalid\.json:1:19: invalid JSON"):
                load_system_spec(path)

    @staticmethod
    def _valid_dict():
        return json.loads(
            """{
              "schema_version": 1,
              "name": "test",
              "sources": [{"name": "rtl", "rtl_files": ["unit.sv"]}],
              "modules": [{
                "name": "unit",
                "kind": "generic",
                "source_set": "rtl",
                "ports": {"clk": {"direction": "input", "type": "clock"}}
              }]
            }"""
        )


if __name__ == "__main__":
    unittest.main()
