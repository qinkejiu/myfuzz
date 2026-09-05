from __future__ import annotations

import json
import os
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

EXPECTED_PROFILES = {
    "clint": {
        "module_name": "clint",
        "protocols": (("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "reference",
        "source_paths": ("third_party/reference/riscv-aclint/clint.sv",),
        "implemented": False,
        "parameter_limits": {"HARTS": (1, 256), "COUNTER_WIDTH": (32, 64)},
    },
    "dma": {
        "module_name": "dma_engine",
        "protocols": (("axi4", "1"), ("tl-ul", "1"), ("avalon-mm", "1")),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": ("ram",),
        "source_status": "reference",
        "source_paths": ("third_party/reference/dma/dma_engine.sv",),
        "implemented": False,
        "parameter_limits": {"CHANNELS": (1, 16), "ADDRESS_WIDTH": (16, 64)},
    },
    "ethernet_mac": {
        "module_name": "ethernet_mac",
        "protocols": (
            ("axi4", "1"),
            ("axi4-lite", "1"),
            ("axi-stream", "1"),
            ("tl-ul", "1"),
        ),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": ("dma",),
        "source_status": "reference",
        "source_paths": ("third_party/reference/ethernet/ethernet_mac.sv",),
        "implemented": False,
        "parameter_limits": {
            "DATA_WIDTH": (8, 128),
            "TX_DEPTH": (1, 4096),
            "RX_DEPTH": (1, 4096),
        },
    },
    "gpio": {
        "module_name": "ibex_mcip_gpio",
        "protocols": (("apb", "4"),),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "implemented",
        "source_paths": (
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_gpio.sv",
        ),
        "implemented": True,
        "parameter_limits": {},
    },
    "i2c": {
        "module_name": "i2c_controller",
        "protocols": (("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "reference",
        "source_paths": ("third_party/reference/i2c/i2c_controller.sv",),
        "implemented": False,
        "parameter_limits": {"FIFO_DEPTH": (1, 1024), "CLOCK_DIVIDER": (1, 65535)},
    },
    "plic": {
        "module_name": "plic",
        "protocols": (("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "reference",
        "source_paths": ("third_party/reference/riscv-plic/plic.sv",),
        "implemented": False,
        "parameter_limits": {"SOURCES": (1, 1024), "TARGETS": (1, 256)},
    },
    "pwm": {
        "module_name": "pwm_controller",
        "protocols": (("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "reference",
        "source_paths": ("third_party/reference/pwm/pwm_controller.sv",),
        "implemented": False,
        "parameter_limits": {"CHANNELS": (1, 16), "COUNTER_WIDTH": (8, 32)},
    },
    "ram": {
        "module_name": "ibex_mcip_ram",
        "protocols": (("tl-ul", "1"),),
        "address_alignment": 4,
        "default_size": 65536,
        "irq_capable": False,
        "requires": (),
        "source_status": "implemented",
        "source_paths": (
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_ram.sv",
        ),
        "implemented": True,
        "parameter_limits": {"WORDS": (4, 16384)},
    },
    "spi": {
        "module_name": "ibex_mcip_spi",
        "protocols": (("axi4-lite", "1"),),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "implemented",
        "source_paths": ("configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_spi.sv",),
        "implemented": True,
        "parameter_limits": {},
    },
    "timer": {
        "module_name": "ibex_mcip_timer",
        "protocols": (("apb", "4"),),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "implemented",
        "source_paths": (
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_timer.sv",
        ),
        "implemented": True,
        "parameter_limits": {},
    },
    "uart": {
        "module_name": "ibex_mcip_uart",
        "protocols": (("axi4-lite", "1"),),
        "address_alignment": 4096,
        "default_size": 4096,
        "irq_capable": True,
        "requires": (),
        "source_status": "implemented",
        "source_paths": (
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_uart.sv",
        ),
        "implemented": True,
        "parameter_limits": {},
    },
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
    def test_builtin_catalog_matches_exact_inventory_metadata(self) -> None:
        catalog = load_builtin_component_catalog()

        self.assertEqual(
            [profile.component_type for profile in catalog.profiles],
            sorted(EXPECTED_PROFILES),
        )
        for profile in catalog.profiles:
            with self.subTest(component_type=profile.component_type):
                expected = EXPECTED_PROFILES[profile.component_type]
                self.assertEqual(profile.module_name, expected["module_name"])
                self.assertEqual(profile.protocols, expected["protocols"])
                self.assertEqual(profile.address_alignment, expected["address_alignment"])
                self.assertEqual(profile.default_size, expected["default_size"])
                self.assertEqual(profile.irq_capable, expected["irq_capable"])
                self.assertEqual(profile.requires, expected["requires"])
                self.assertEqual(profile.source_status, expected["source_status"])
                self.assertEqual(profile.source_paths, expected["source_paths"])
                self.assertEqual(profile.implemented, expected["implemented"])
                self.assertEqual(profile.parameter_limits, expected["parameter_limits"])

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

    def test_loader_rejects_duplicate_json_keys(self) -> None:
        duplicate_document = """{
            "component_type": "fixture",
            "module_name": "fixture_module",
            "protocols": [["apb", "4"]],
            "address_alignment": 4,
            "default_size": 4096,
            "irq_capable": false,
            "requires": [],
            "source_status": "implemented",
            "source_paths": ["fixture.sv"],
            "implemented": true,
            "implemented": true,
            "parameter_limits": {"WIDTH": [1, 32]}
        }"""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "fixture.json").write_text(duplicate_document, encoding="utf-8")

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_loader_rejects_invalid_booleans_numbers_status_and_ranges(self) -> None:
        invalid_documents = {
            "invalid_irq_boolean": {"irq_capable": 1},
            "invalid_implemented_boolean": {"implemented": 0},
            "invalid_alignment_number": {"address_alignment": 4.0},
            "invalid_default_size_number": {"default_size": "4096"},
            "invalid_source_status": {"source_status": "generated"},
            "invalid_range_number": {"parameter_limits": {"WIDTH": [1, 32.0]}},
            "invalid_range_order": {"parameter_limits": {"WIDTH": [32, 1]}},
        }
        for filename, overrides in invalid_documents.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _write_document(directory, f"{filename}.json", _profile_document(**overrides))

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

    def test_loader_rejects_non_normalized_source_path_aliases(self) -> None:
        aliases = (
            ["."],
            ["./fixture.sv"],
            ["dir//fixture.sv"],
            ["fixture.sv", "./fixture.sv"],
        )
        for index, source_paths in enumerate(aliases):
            with self.subTest(source_paths=source_paths), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _write_document(
                    directory,
                    f"alias_{index}.json",
                    _profile_document(source_paths=source_paths),
                )

                with self.assertRaises(ComponentDefinitionError):
                    load_component_catalog(directory)

    def test_loader_rejects_standalone_dot_slash_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _write_document(
                directory,
                "dot_slash.json",
                _profile_document(source_paths=["./"]),
            )

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_loader_rejects_trailing_source_path_separator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _write_document(
                directory,
                "trailing_separator.json",
                _profile_document(source_paths=["fixture.sv/"]),
            )

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_loader_rejects_nul_in_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _write_document(directory, "fixture.json", _profile_document(source_paths=["bad\x00.sv"]))

            with self.assertRaises(ComponentDefinitionError):
                load_component_catalog(directory)

    def test_available_rejects_missing_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ComponentDefinitionError):
                load_builtin_component_catalog().available("ram", root=Path(temporary))

    def test_available_rejects_source_symlink_escape_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            outside_source = Path(outside) / "outside.sv"
            outside_source.write_text("module outside; endmodule\n", encoding="utf-8")
            source_path = root / "fixture.sv"
            try:
                os.symlink(outside_source, source_path)
            except (NotImplementedError, OSError):
                self.skipTest("symbolic links are not supported")
            _write_document(root, "fixture.json", _profile_document())
            catalog = load_component_catalog(root)

            with self.assertRaises(ComponentDefinitionError):
                catalog.available("fixture", root=root)

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
