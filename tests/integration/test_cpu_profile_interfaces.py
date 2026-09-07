from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.components import ComponentDefinitionError, load_builtin_component_catalog, load_component_catalog
from myfuzz.composition import load_interface_description
from myfuzz.composition.source_crawler import annotate_interfaces, source_tree_hash
from myfuzz.isa import CpuDefinitionError, load_builtin_cpu_catalog, load_cpu_catalog
from myfuzz.protocols import load_protocol_catalog
from myfuzz.composition.source_crawler import SourceCrawlError


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
    def test_source_backed_availability_requires_verified_matching_annotation(self) -> None:
        for failure in (None, "empty-interface", "missing-root", "zero-pin", "locator-mismatch", "missing-field"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                tree = base / "rtl"
                (tree / "rtl").mkdir(parents=True)
                source = tree / "rtl/core.sv"
                source.write_text("module core(output [63:0] opaque_address, output opaque_valid, input opaque_ready, output [63:0] opaque_write_data, input [63:0] opaque_read_data); endmodule")
                description = _synthetic_interface("rtl", "core", source_tree_hash(tree, (source,)))
                locator = dict(description["source"], available=True)
                if failure == "missing-root":
                    locator["root"] = description["source"]["root"] = "absent"
                elif failure == "zero-pin":
                    locator["revision"] = description["source"]["revision"] = "sha256:" + "0" * 64
                elif failure == "locator-mismatch":
                    locator["top_module"] = "other"
                elif failure == "missing-field":
                    description["endpoints"][0]["fields"][0]["aliases"] = ["absent"]
                (base / "interface.json").write_text(json.dumps({} if failure == "empty-interface" else description))
                profiles = base / "profiles"
                profiles.mkdir()
                document = dict(cpu_id="fixture", vendor="fixture", xlen=[64], extensions=["I"], core_native_protocols=[], integration_protocols=[["apb", "4"]], source_status="implemented", source_paths=["rtl"], implemented=True, interface_description="interface.json", source_locator=locator)
                (profiles / "fixture.json").write_text(json.dumps(document))
                catalog = load_cpu_catalog(profiles, root=base)
                self.assertEqual(failure is None, catalog.require("fixture").implemented)
                if failure:
                    self.assertEqual((), catalog.compatible_protocols("fixture"))
                # Metadata-free legacy availability remains file based.
                del document["interface_description"], document["source_locator"]
                (profiles / "fixture.json").write_text(json.dumps(document))
                self.assertTrue(load_cpu_catalog(profiles, root=base).require("fixture").implemented)

    def test_templates_have_materialization_entry_and_consumed_endpoint_keys(self) -> None:
        for path in CPU_INTERFACE_FILES.values():
            document = _load_json(path)
            self.assertEqual("sources.f", document["source"].get("filelist"))
            for endpoint in document["endpoints"]:
                self.assertNotIn("source_anchor", endpoint)

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
                self.assertEqual(5 if cpu_id.startswith("cva6") else 6, len(semantic_description.endpoints))
                source = document["source"]
                self.assertIsInstance(source, dict)
                assert isinstance(source, dict)
                self.assertEqual(profile.source_locator["root"], source["root"])
                self.assertEqual(profile.source_locator["revision"], source["revision"])
                self.assertEqual(profile.source_locator["top_module"], source["top_module"])

    def test_cpu_interface_documents_contain_semantics_not_physical_hdl_facts(self) -> None:
        expected_functions = {
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
                self.assertTrue(any("memory_master" in item["function"] for item in endpoints))
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
                prefix = "alpha_" if cpu_name == "cva6" else "beta_"
                source.write_text(source_template.format(module_name=module_name).replace("opaque_", prefix), encoding="utf-8")
                module_name = module_name.replace("opaque_", prefix)
                source_hash = source_tree_hash(source_root, (source,))
                document = _synthetic_interface(cpu_name, module_name, source_hash)
                for field in document["endpoints"][0]["fields"]:
                    field["aliases"] = [name.replace("opaque_", prefix) for name in field["aliases"]]
                description = load_interface_description(document)
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

    def test_cva6_export_template_validates_complete_axi4_with_renamed_ports(self) -> None:
        # Independent physical fixture: test every role, direction and channel width.
        widths = {"awid": 4, "arid": 4, "bid": 4, "rid": 4,
                  "awaddr": 64, "araddr": 64, "awlen": 8, "arlen": 8,
                  "awsize": 3, "arsize": 3, "awburst": 2, "arburst": 2,
                  "wdata": 64, "rdata": 64, "wstrb": 8, "bresp": 2, "rresp": 2}
        inputs = {"awready", "wready", "bid", "bresp", "bvalid", "arready", "rid", "rdata", "rresp", "rlast", "rvalid"}
        catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
        for prefix in ("export_", "renamed_"):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                tree = base / "source"
                tree.mkdir()
                document = _load_json(CPU_INTERFACE_FILES["cva6.rv64imafdc"])
                ports = []
                memory = document["endpoints"][0]
                self.assertEqual({f.field_id for f in catalog.require("axi4", "1").fields}, {f["role"] for f in memory["fields"]})
                for endpoint in document["endpoints"]:
                    for field in endpoint["fields"]:
                        role = field["role"]
                        name = prefix + role
                        field["aliases"] = [name]
                        width = widths.get(role, 1)
                        direction = "input" if endpoint is not memory or role in inputs else "output"
                        ports.append(f"{direction} logic [{width - 1}:0] {name}")
                hdl = tree / "boundary.sv"
                hdl.write_text("module cva6_axi_boundary(" + ",".join(ports) + "); endmodule")
                filelist = tree / "sources.f"
                filelist.write_text("boundary.sv\n")
                document["source"].update(root="source", revision=source_tree_hash(tree, (hdl, filelist)))
                annotations = annotate_interfaces(load_interface_description(document), base_dir=base, protocol_catalog=catalog)
                annotated = next(e for e in annotations["endpoints"] if e["endpoint_id"] == "cpu.memory")
                self.assertEqual("consistent", annotated["protocol_candidates"][0]["status"])
                (base / "interface.json").write_text(json.dumps(document))
                profiles = base / "profiles"
                profiles.mkdir()
                profile = _load_json(CPU_PROFILE_DIR / "cva6.json")
                profile.update(source_paths=["source"], interface_description="interface.json",
                               source_status="implemented", implemented=True,
                               source_locator=dict(document["source"], available=True))
                (profiles / "cpu.json").write_text(json.dumps(profile))
                self.assertTrue(load_cpu_catalog(profiles, root=base).require(profile["cpu_id"]).implemented)
                # Protocol mismatches must also fail through catalog availability.
                memory["fields"][0]["role"] = "not_an_axi_field"
                (base / "interface.json").write_text(json.dumps(document))
                self.assertFalse(load_cpu_catalog(profiles, root=base).require(profile["cpu_id"]).implemented)

    def test_boom_materialized_template_still_requires_tilelink_dependency(self) -> None:
        catalog = load_builtin_cpu_catalog(root=ROOT)
        self.assertEqual((), catalog.compatible_protocols("boom.rv64imafdc"))
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            tree = base / "source"
            tree.mkdir()
            document = _load_json(CPU_INTERFACE_FILES["boom.rv64imafdc"])
            ports = {alias for endpoint in document["endpoints"] for field in endpoint["fields"] for alias in field["aliases"]}
            hdl = tree / "tile.sv"
            hdl.write_text("module boom_tile(" + ",".join("input " + p for p in sorted(ports)) + "); endmodule")
            filelist = tree / "sources.f"
            filelist.write_text("tile.sv\n")
            document["source"].update(root="source", revision=source_tree_hash(tree, (hdl, filelist)))
            with self.assertRaisesRegex(SourceCrawlError, "protocol-unsupported:.*tilelink@1"):
                annotate_interfaces(load_interface_description(document), base_dir=base, protocol_catalog=load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins"))
            (base / "interface.json").write_text(json.dumps(document))
            profiles = base / "profiles"
            profiles.mkdir()
            profile = _load_json(CPU_PROFILE_DIR / "boom.json")
            profile.update(source_paths=["source"], interface_description="interface.json",
                           source_status="implemented", implemented=True,
                           source_locator=dict(document["source"], available=True))
            (profiles / "cpu.json").write_text(json.dumps(profile))
            self.assertFalse(load_cpu_catalog(profiles, root=base).require(profile["cpu_id"]).implemented)

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
