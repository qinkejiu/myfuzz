from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.components import ComponentDefinitionError, load_builtin_component_catalog, load_component_catalog
from myfuzz.composition import load_interface_description
from myfuzz.composition.source_crawler import annotate_interfaces, source_tree_hash
from myfuzz.isa import CpuDefinitionError, load_builtin_cpu_catalog, load_cpu_catalog


ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE_DIR = ROOT / "src" / "myfuzz" / "isa" / "profiles"
CPU_INTERFACE_FILES = {
    "cva6.rv64imafdc": ROOT / "configs" / "cpus" / "cva6" / "interface_description.json",
    "boom.rv64imafdc": ROOT / "configs" / "cpus" / "boom" / "interface_description.json",
}
REUSABLE_COMPONENTS = ("clint", "plic", "pwm", "i2c", "dma")


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object: {path}")
    return value


def _legacy_component_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "component_type": "legacy_fixture",
        "module_name": "legacy_fixture",
        "protocols": [["apb", "4"]],
        "address_alignment": 4,
        "default_size": 4096,
        "irq_capable": False,
        "requires": [],
        "source_status": "reference",
        "source_paths": ["rtl/legacy_fixture.sv"],
        "implemented": False,
        "parameter_limits": {"WIDTH": [1, 32]},
    }
    document.update(overrides)
    return document


def _synthetic_interface(root_name: str, module_name: str, source_hash: str) -> dict[str, object]:
    return {
        "schema_version": "interface_description.v1",
        "source": {
            "root": root_name,
            "revision": source_hash,
            "top_module": module_name,
            "files": ["rtl/core.sv"],
        },
        "endpoints": [
            {
                "endpoint_id": "cpu.memory_master",
                "function": "memory_master",
                "fields": [
                    {"role": "address", "aliases": ["opaque_address"]},
                    {"role": "valid", "aliases": ["opaque_valid"]},
                    {"role": "ready", "aliases": ["opaque_ready"]},
                    {"role": "write_data", "aliases": ["opaque_write_data"]},
                    {"role": "read_data", "aliases": ["opaque_read_data"]},
                ],
            }
        ],
    }


class CpuProfileInterfaceTests(unittest.TestCase):
    def test_cva6_and_boom_profiles_expose_rv64_interfaces_as_reference_only(self) -> None:
        catalog = load_builtin_cpu_catalog(root=ROOT)

        for cpu_id, interface_path in CPU_INTERFACE_FILES.items():
            with self.subTest(cpu_id=cpu_id):
                profile = catalog.require(cpu_id)
                self.assertEqual((64,), profile.xlen)
                self.assertTrue({"I", "M", "A", "F", "D", "C"} <= set(profile.extensions))
                self.assertEqual(interface_path.relative_to(ROOT).as_posix(), profile.interface_description)
                self.assertIsNotNone(profile.source_locator)
                assert profile.source_locator is not None
                self.assertFalse(profile.source_locator["available"])
                self.assertEqual("reference", profile.source_status)
                self.assertFalse(profile.implemented)

                document = _load_json(interface_path)
                semantic_description = load_interface_description(interface_path)
                self.assertEqual(6, len(semantic_description.endpoints))
                source = document["source"]
                self.assertIsInstance(source, dict)
                assert isinstance(source, dict)
                self.assertEqual(profile.source_locator["root"], source["root"])
                self.assertEqual(profile.source_locator["revision"], source["revision"])
                self.assertEqual(profile.source_locator["top_module"], source["top_module"])

    def test_cpu_interface_documents_contain_semantics_not_physical_hdl_facts(self) -> None:
        expected_functions = {
            "instruction_memory_master",
            "data_memory_master",
            "interrupt_sink",
            "debug_transport",
            "clock",
            "reset",
        }

        def walk(value: object) -> list[str]:
            keys: list[str] = []
            if isinstance(value, dict):
                for key, child in value.items():
                    keys.append(str(key))
                    keys.extend(walk(child))
            elif isinstance(value, list):
                for child in value:
                    keys.extend(walk(child))
            return keys

        for path in CPU_INTERFACE_FILES.values():
            with self.subTest(path=path):
                document = _load_json(path)
                self.assertEqual("interface_description.v1", document["schema_version"])
                endpoints = document["endpoints"]
                self.assertIsInstance(endpoints, list)
                assert isinstance(endpoints, list)
                self.assertTrue(expected_functions <= {item["function"] for item in endpoints})
                self.assertNotIn("direction", walk(document))
                self.assertNotIn("width", walk(document))
                self.assertNotIn("signed", walk(document))
                self.assertNotIn("timing", walk(document))

    def test_same_generic_crawler_path_handles_different_cpu_names(self) -> None:
        source_template = """\
module {module_name}(
  input logic clk_x,
  input logic rst_x,
  output logic [63:0] opaque_address,
  output logic opaque_valid,
  input logic opaque_ready,
  output logic [63:0] opaque_write_data,
  input logic [63:0] opaque_read_data
);
  always_ff @(posedge clk_x) begin
    if (opaque_valid && !opaque_ready) opaque_write_data <= opaque_write_data;
  end
endmodule
"""

        annotations: dict[str, dict[str, object]] = {}
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            for cpu_name in ("cva6", "boom"):
                source_root = base / cpu_name
                source = source_root / "rtl" / "core.sv"
                source.parent.mkdir(parents=True)
                module_name = f"opaque_{cpu_name}"
                source.write_text(source_template.format(module_name=module_name), encoding="utf-8")
                source_hash = source_tree_hash(source_root, (source,))
                description = load_interface_description(
                    _synthetic_interface(cpu_name, module_name, source_hash)
                )
                annotations[cpu_name] = annotate_interfaces(description, base_dir=base)

        self.assertEqual(
            [field["role"] for field in annotations["cva6"]["endpoints"][0]["fields"]],
            [field["role"] for field in annotations["boom"]["endpoints"][0]["fields"]],
        )
        self.assertEqual(
            [field["width"] for field in annotations["cva6"]["endpoints"][0]["fields"]],
            [field["width"] for field in annotations["boom"]["endpoints"][0]["fields"]],
        )
        self.assertNotEqual(
            annotations["cva6"]["endpoints"][0]["module"],
            annotations["boom"]["endpoints"][0]["module"],
        )

    def test_reusable_profiles_have_generic_capabilities_and_are_not_implemented(self) -> None:
        catalog = load_builtin_component_catalog()
        for component_type in REUSABLE_COMPONENTS:
            with self.subTest(component_type=component_type):
                profile = catalog.require(component_type)
                self.assertTrue(profile.endpoints)
                self.assertTrue(profile.protocol_features)
                self.assertTrue(profile.external_pins)
                self.assertTrue(profile.dependencies)
                self.assertTrue(profile.parameters)
                self.assertEqual("reference", profile.source_status)
                self.assertFalse(profile.implemented)
                self.assertTrue(all(endpoint.role for endpoint in profile.endpoints))
                self.assertTrue(all(features for features in profile.protocol_features.values()))
                self.assertTrue(
                    all(protocol in profile.protocols for protocol in profile.protocol_features)
                )
                self.assertTrue(all(dependency.required for dependency in profile.dependencies))
                self.assertTrue(all(parameter.default is not None for parameter in profile.parameters.values()))

                raw = json.dumps(_load_json(ROOT / "src" / "myfuzz" / "components" / "profiles" / f"{component_type}.json")).lower()
                self.assertNotIn("renderer", raw)
                for cpu_name in ("ibex", "cva6", "boom"):
                    self.assertNotIn(cpu_name, raw)

    def test_legacy_component_profiles_without_optional_metadata_remain_loadable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            (directory / "legacy.json").write_text(
                json.dumps(_legacy_component_document()), encoding="utf-8"
            )

            profile = load_component_catalog(directory).require("legacy_fixture")

        self.assertEqual((), profile.endpoints)
        self.assertEqual({}, dict(profile.protocol_features))
        self.assertEqual((), profile.external_pins)
        self.assertEqual((), profile.dependencies)
        self.assertEqual((1, 32), profile.parameters["WIDTH"].limits)

    def test_cpu_source_locator_metadata_is_strict_and_status_bound(self) -> None:
        base_document = {
            "cpu_id": "fixture.rv64i",
            "vendor": "fixture",
            "xlen": [64],
            "extensions": ["I"],
            "core_native_protocols": [],
            "integration_protocols": [],
            "source_status": "reference",
            "source_paths": ["third_party/fixture"],
            "implemented": False,
            "interface_description": "configs/fixture/interface_description.json",
            "source_locator": {
                "root": "third_party/fixture",
                "revision": "sha256:" + "0" * 64,
                "top_module": "fixture_top",
                "available": False,
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            invalid_status = dict(base_document)
            invalid_status["source_locator"] = dict(base_document["source_locator"], available=True)  # type: ignore[arg-type]
            (directory / "invalid_status.json").write_text(
                json.dumps(invalid_status), encoding="utf-8"
            )
            with self.assertRaises(CpuDefinitionError):
                load_cpu_catalog(directory)

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            invalid_paths = dict(base_document)
            invalid_paths["source_locator"] = dict(
                base_document["source_locator"], files=[{"not": "a path"}]  # type: ignore[arg-type]
            )
            (directory / "invalid_paths.json").write_text(
                json.dumps(invalid_paths), encoding="utf-8"
            )
            with self.assertRaises(CpuDefinitionError):
                load_cpu_catalog(directory)

    def test_optional_component_metadata_is_strictly_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            document = _legacy_component_document(
                endpoints=[{"endpoint_id": "registers", "role": "register_target"}],
            )
            (directory / "invalid.json").write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)


if __name__ == "__main__":
    unittest.main()
