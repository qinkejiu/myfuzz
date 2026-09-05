from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.components import (
    ComponentDefinitionError,
    load_builtin_component_catalog,
    load_component_catalog,
)
from myfuzz.contracts import canonical_bytes, content_hash


ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "src" / "myfuzz" / "components" / "profiles"
COMMON_COMPONENTS = {
    "ram",
    "timer",
    "gpio",
    "uart",
    "spi",
    "pwm",
    "i2c",
    "dma",
    "clint",
    "plic",
    "ethernet_mac",
}
RUNTIME_BINDINGS = {
    "ram": ("tl-ul", "1"),
    "timer": ("apb", "4"),
    "gpio": ("apb", "4"),
    "uart": ("axi4-lite", "1"),
    "spi": ("axi4-lite", "1"),
}


def _profile_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "component_type": "fixture",
        "module_name": "fixture_module",
        "protocols": [["apb", "4"]],
        "address_alignment": 4,
        "default_size": 4096,
        "irq_capable": False,
        "requires": [],
        "source_status": "implemented",
        "source_paths": ["fixture.sv"],
        "implemented": True,
        "parameter_limits": {"WIDTH": [1, 32]},
    }
    document.update(overrides)
    return document


def _write_document(directory: Path, filename: str, document: dict[str, object]) -> None:
    (directory / filename).write_text(json.dumps(document), encoding="utf-8")


def _catalog_document(catalog: object) -> list[dict[str, object]]:
    return [
        {
            "component_type": profile.component_type,
            "module_name": profile.module_name,
            "protocols": [list(protocol) for protocol in profile.protocols],
            "address_alignment": profile.address_alignment,
            "default_size": profile.default_size,
            "irq_capable": profile.irq_capable,
            "requires": list(profile.requires),
            "source_status": profile.source_status,
            "source_paths": list(profile.source_paths),
            "implemented": profile.implemented,
            "parameter_limits": {
                name: list(bounds) for name, bounds in profile.parameter_limits.items()
            },
        }
        for profile in catalog.profiles
    ]


class ComponentCatalogTest(unittest.TestCase):
    def test_builtin_catalog_contains_common_profiles_in_deterministic_order(self) -> None:
        catalog = load_builtin_component_catalog()

        self.assertEqual({profile.component_type for profile in catalog.profiles}, COMMON_COMPONENTS)
        self.assertEqual(
            [profile.component_type for profile in catalog.profiles],
            sorted(COMMON_COMPONENTS),
        )
        self.assertEqual(
            content_hash(_catalog_document(catalog)),
            content_hash(_catalog_document(load_builtin_component_catalog())),
        )

    def test_runtime_profiles_expose_existing_ibex_bindings_and_sources(self) -> None:
        catalog = load_builtin_component_catalog()

        for component_type, protocol in RUNTIME_BINDINGS.items():
            with self.subTest(component_type=component_type):
                profile = catalog.require(component_type)
                self.assertIn(protocol, profile.protocols)
                self.assertTrue(profile.implemented)
                self.assertEqual(profile.source_status, "implemented")
                self.assertTrue(profile.source_paths)
                self.assertEqual(
                    catalog.available(component_type, root=ROOT, protocol=protocol),
                    profile,
                )

    def test_reference_profiles_remain_metadata_only(self) -> None:
        catalog = load_builtin_component_catalog()

        for component_type in ("dma", "plic", "ethernet_mac"):
            with self.subTest(component_type=component_type):
                profile = catalog.require(component_type)
                self.assertFalse(profile.implemented)
                self.assertEqual(profile.source_status, "reference")
                with self.assertRaises(ComponentDefinitionError):
                    catalog.available(component_type, root=ROOT)

    def test_dependencies_are_unique_and_refer_to_known_components(self) -> None:
        catalog = load_builtin_component_catalog()

        for profile in catalog.profiles:
            with self.subTest(component_type=profile.component_type):
                self.assertEqual(len(profile.requires), len(set(profile.requires)))
                self.assertTrue(set(profile.requires) <= COMMON_COMPONENTS)

    def test_available_rejects_unsupported_protocol(self) -> None:
        catalog = load_builtin_component_catalog()

        with self.assertRaises(ComponentDefinitionError):
            catalog.available("ram", root=ROOT, protocol=("apb", "4"))

    def test_loader_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            document = _profile_document(unexpected_field=True)
            _write_document(directory, "fixture.json", document)

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_loader_rejects_invalid_protocol_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _write_document(directory, "fixture.json", _profile_document(protocols=[["apb"]]))

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_loader_rejects_duplicate_component_types(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            document = _profile_document()
            _write_document(directory, "a.json", document)
            _write_document(directory, "b.json", document)

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_loader_rejects_source_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            document = _profile_document(source_paths=["../outside.sv"])
            _write_document(directory, "fixture.json", document)

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_canonical_bytes_ignore_profile_member_order(self) -> None:
        document = _profile_document()
        reordered = dict(reversed(list(document.items())))

        self.assertEqual(canonical_bytes(document), canonical_bytes(reordered))
        self.assertEqual(content_hash(document), content_hash(reordered))

    def test_require_unknown_component_fails_with_typed_error(self) -> None:
        with self.assertRaises(ComponentDefinitionError):
            load_builtin_component_catalog().require("does-not-exist")


if __name__ == "__main__":
    unittest.main()
