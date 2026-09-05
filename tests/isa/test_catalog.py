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

        self.assertTrue(catalog.require("ibex.rv32imc").implemented)
        self.assertIn(("apb", "4"), catalog.compatible_protocols("ibex.rv32imc"))
        self.assertIn(("tl-ul", "1"), catalog.compatible_protocols("ibex.rv32imc"))
        self.assertEqual((), catalog.compatible_protocols("cva6.rv64imafdc"))
        self.assertIn(
            ("axi4", "1"),
            catalog.compatible_protocols("cva6.rv64imafdc", runtime_only=False),
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
