from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.isa import CpuDefinitionError, load_builtin_cpu_catalog, load_cpu_catalog


ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "src" / "myfuzz" / "isa" / "profiles"


def _profile_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "cpu_id": "test.rv32i",
        "vendor": "test-vendor",
        "xlen": [32],
        "extensions": ["I"],
        "core_native_protocols": [["ready-valid-mmio", "1"]],
        "integration_protocols": [["apb", "4"]],
        "source_status": "reference",
        "source_paths": ["third_party/test-cpu"],
        "implemented": False,
    }
    document.update(overrides)
    return document


class CpuCatalogTest(unittest.TestCase):
    def test_builtin_catalog_loads_all_six_profiles_with_unique_ids(self) -> None:
        catalog = load_builtin_cpu_catalog()

        self.assertEqual(
            {
                "ibex.rv32imc",
                "cva6.rv64imafdc",
                "boom.rv64imafdc",
                "rocket.rv64imafdc",
                "picorv32.rv32i",
                "cv32e40p.rv32imc",
            },
            {profile.cpu_id for profile in catalog.profiles},
        )
        self.assertEqual(len(catalog.profiles), len({profile.cpu_id for profile in catalog.profiles}))

    def test_builtin_profiles_have_exact_metadata_and_statuses(self) -> None:
        expected = {
            "ibex.rv32imc": {
                "vendor": "lowRISC",
                "xlen": (32,),
                "extensions": ("I", "M", "C"),
                "core_native_protocols": (("ready-valid-mmio", "1"),),
                "integration_protocols": (("tl-ul", "1"), ("apb", "4"), ("axi4-lite", "1")),
                "source_status": "implemented",
                "source_paths": (
                    "third_party/rfuzz/upstream/ibex/sources.f",
                    "configs/designs/ibex_multicomponent_ip/rtl/local_sources.f",
                    "configs/designs/ibex_multicomponent_ip/rtl/ibex_multicomponent_ip_top.sv",
                ),
                "implemented": False,
            },
            "cva6.rv64imafdc": {
                "vendor": "OpenHW Group",
                "xlen": (64,),
                "extensions": ("I", "M", "A", "F", "D", "C"),
                "core_native_protocols": (("axi4", "1"),),
                "integration_protocols": (("axi4", "1"),),
                "source_status": "reference",
                "source_paths": ("third_party/cva6",),
                "implemented": False,
            },
            "boom.rv64imafdc": {
                "vendor": "Berkeley Architecture Research",
                "xlen": (64,),
                "extensions": ("I", "M", "A", "F", "D", "C"),
                "core_native_protocols": (("boom-tile", "1"),),
                "integration_protocols": (("tilelink", "1"),),
                "source_status": "reference",
                "source_paths": ("third_party/boom",),
                "implemented": False,
            },
            "rocket.rv64imafdc": {
                "vendor": "UC Berkeley",
                "xlen": (64,),
                "extensions": ("I", "M", "A", "F", "D", "C"),
                "core_native_protocols": (("tilelink", "1"),),
                "integration_protocols": (("tilelink", "1"), ("axi4", "1")),
                "source_status": "reference",
                "source_paths": ("third_party/rocket-chip",),
                "implemented": False,
            },
            "picorv32.rv32i": {
                "vendor": "YosysHQ",
                "xlen": (32,),
                "extensions": ("I",),
                "core_native_protocols": (("ready-valid-mmio", "1"),),
                "integration_protocols": (("axi4-lite", "1"), ("wishbone", "classic-b3")),
                "source_status": "reference",
                "source_paths": ("third_party/picorv32",),
                "implemented": False,
            },
            "cv32e40p.rv32imc": {
                "vendor": "OpenHW Group",
                "xlen": (32,),
                "extensions": ("I", "M", "C"),
                "core_native_protocols": (("obi", "1.2"),),
                "integration_protocols": (("obi", "1.2"),),
                "source_status": "reference",
                "source_paths": ("third_party/cv32e40p",),
                "implemented": False,
            },
        }
        catalog = load_builtin_cpu_catalog()

        for cpu_id, fields in expected.items():
            with self.subTest(cpu_id=cpu_id):
                profile = catalog.require(cpu_id)
                for field, value in fields.items():
                    self.assertEqual(value, getattr(profile, field), field)

    def test_missing_ibex_upstream_source_list_disables_runtime(self) -> None:
        profile = load_builtin_cpu_catalog().require("ibex.rv32imc")

        self.assertIn("third_party/rfuzz/upstream/ibex/sources.f", profile.source_paths)
        self.assertFalse(profile.implemented)
        self.assertEqual(
            (),
            load_builtin_cpu_catalog().compatible_protocols(
                "ibex.rv32imc", runtime_only=True
            ),
        )

    def test_profiles_preserve_documented_native_and_integration_boundaries(self) -> None:
        catalog = load_builtin_cpu_catalog()
        ibex = catalog.require("ibex.rv32imc")
        cva6 = catalog.require("cva6.rv64imafdc")
        boom = catalog.require("boom.rv64imafdc")

        self.assertIn(("ready-valid-mmio", "1"), ibex.core_native_protocols)
        self.assertNotIn(("apb", "4"), ibex.core_native_protocols)
        self.assertIn(("tl-ul", "1"), ibex.integration_protocols)
        self.assertIn(("apb", "4"), ibex.integration_protocols)
        self.assertIn(("axi4-lite", "1"), ibex.integration_protocols)

        self.assertEqual((("axi4", "1"),), cva6.core_native_protocols)
        self.assertNotIn(("tl-ul", "1"), cva6.core_native_protocols)

        self.assertEqual((("boom-tile", "1"),), boom.core_native_protocols)
        self.assertIn(("tilelink", "1"), boom.integration_protocols)
        self.assertNotEqual(boom.core_native_protocols, boom.integration_protocols)

    def test_runtime_protocols_require_an_implemented_profile(self) -> None:
        catalog = load_builtin_cpu_catalog()

        self.assertFalse(catalog.require("ibex.rv32imc").implemented)
        self.assertEqual((), catalog.compatible_protocols("ibex.rv32imc"))
        self.assertEqual((), catalog.compatible_protocols("cva6.rv64imafdc"))
        self.assertIn(
            ("axi4", "1"),
            catalog.compatible_protocols("cva6.rv64imafdc", runtime_only=False),
        )

    def test_runtime_protocols_filter_to_tested_runtime_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            profiles = root / "profiles"
            profiles.mkdir()
            source = root / "rtl" / "cpu.sv"
            source.parent.mkdir()
            source.write_text("// test source\n", encoding="utf-8")
            path = profiles / "test.json"
            path.write_text(
                json.dumps(
                    _profile_document(
                        core_native_protocols=[
                            ["ready-valid-mmio", "1"],
                            ["axi4", "1"],
                            ["tilelink", "1"],
                        ],
                        integration_protocols=[
                            ["apb", "4"],
                            ["axi4-lite", "1"],
                            ["tl-ul", "1"],
                            ["obi", "1.2"],
                            ["ready-valid-mmio", "1"],
                        ],
                        source_status="implemented",
                        source_paths=["rtl/cpu.sv"],
                        implemented=True,
                    )
                ),
                encoding="utf-8",
            )

            catalog = load_cpu_catalog(root)

            self.assertEqual(
                (("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")),
                catalog.compatible_protocols("test.rv32i", runtime_only=True),
            )
            self.assertEqual(
                (
                    ("ready-valid-mmio", "1"),
                    ("axi4", "1"),
                    ("tilelink", "1"),
                    ("apb", "4"),
                    ("axi4-lite", "1"),
                    ("tl-ul", "1"),
                    ("obi", "1.2"),
                ),
                catalog.compatible_protocols("test.rv32i", runtime_only=False),
            )

    def test_unknown_cpu_id_fails_closed(self) -> None:
        with self.assertRaises(CpuDefinitionError):
            load_builtin_cpu_catalog().require("unknown.rv32i")

    def test_duplicate_json_keys_fail_closed(self) -> None:
        duplicate_document = (
            '{"cpu_id":"test.rv32i","cpu_id":"test.rv64i",'
            '"vendor":"test-vendor","xlen":[32],"extensions":["I"],'
            '"core_native_protocols":[["ready-valid-mmio","1"]],'
            '"integration_protocols":[],"source_status":"reference",'
            '"source_paths":["third_party/test-cpu"],"implemented":false}'
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "duplicate.json"
            path.write_text(duplicate_document, encoding="utf-8")

            with self.assertRaises(CpuDefinitionError):
                load_cpu_catalog(path.parent)

    def test_unknown_fields_and_invalid_protocol_tuples_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            unknown_path = directory / "unknown.json"
            unknown_path.write_text(
                json.dumps(_profile_document(unknown_field=True)), encoding="utf-8"
            )
            with self.assertRaises(CpuDefinitionError):
                load_cpu_catalog(directory)

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            invalid_path = directory / "invalid.json"
            invalid_path.write_text(
                json.dumps(_profile_document(integration_protocols=[["apb"]])),
                encoding="utf-8",
            )
            with self.assertRaises(CpuDefinitionError):
                load_cpu_catalog(directory)

    def test_invalid_status_and_source_path_traversal_fail_closed(self) -> None:
        cases = (
            {"source_status": "not-a-status"},
            {"source_paths": ["../outside"]},
            {"source_paths": ["/absolute/source"]},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temporary_directory:
                directory = Path(temporary_directory)
                path = directory / "invalid.json"
                path.write_text(json.dumps(_profile_document(**overrides)), encoding="utf-8")
                with self.assertRaises(CpuDefinitionError):
                    load_cpu_catalog(directory)

    def test_implementation_status_must_match_implemented_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            path = directory / "inconsistent.json"
            path.write_text(
                json.dumps(_profile_document(source_status="reference", implemented=True)),
                encoding="utf-8",
            )

            with self.assertRaises(CpuDefinitionError):
                load_cpu_catalog(directory)

    def test_protocol_ids_and_versions_must_be_well_formed(self) -> None:
        cases = (
            [["bad protocol", "1"]],
            [["apb", ""]],
        )
        for protocols in cases:
            with self.subTest(protocols=protocols), tempfile.TemporaryDirectory() as temporary_directory:
                directory = Path(temporary_directory)
                path = directory / "invalid.json"
                path.write_text(
                    json.dumps(_profile_document(integration_protocols=protocols)),
                    encoding="utf-8",
                )
                with self.assertRaises(CpuDefinitionError):
                    load_cpu_catalog(directory)

    def test_missing_implemented_sources_are_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            profiles = root / "profiles"
            profiles.mkdir()
            path = profiles / "test.json"
            path.write_text(
                json.dumps(
                    _profile_document(
                        source_status="implemented",
                        source_paths=["rtl/missing.sv"],
                        implemented=True,
                    )
                ),
                encoding="utf-8",
            )

            profile = load_cpu_catalog(profiles).require("test.rv32i")

            self.assertFalse(profile.implemented)
            self.assertEqual((), load_cpu_catalog(profiles).compatible_protocols("test.rv32i"))


if __name__ == "__main__":
    unittest.main()
