from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.protocol_manifest import (
    ProtocolCompositionError,
    load_protocol_composition,
    validate_protocol_composition,
)
from myfuzz.composition.registry import default_component_registry
from myfuzz.protocols.catalog import load_protocol_catalog


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "src" / "myfuzz" / "protocols" / "plugins"
SCHEMA_PATH = ROOT / "schemas" / "protocol_composition.v1.schema.json"


def approved_manifest() -> dict[str, object]:
    return {
        "schema_version": "protocol_composition.v1",
        "target": {
            "kind": "ibex_core",
            "base_config": "ibex_multicomponent_ip",
            "address_width": 32,
            "data_width": 32,
        },
        "components": [
            {
                "component_id": "uart0",
                "component_type": "uart",
                "protocol": {"id": "axi4-lite", "version": "1"},
                "base": 0x80030000,
                "size": 0x1000,
                "irq": 3,
                "parameters": {},
                "external_input": True,
            },
            {
                "component_id": "ram0",
                "component_type": "ram",
                "protocol": {"id": "tl-ul", "version": "1"},
                "base": 0x00000000,
                "size": 0x10000,
                "parameters": {"WORDS": 4096},
                "external_input": False,
            },
            {
                "component_id": "gpio0",
                "component_type": "gpio",
                "protocol": {"id": "apb", "version": "4"},
                "base": 0x80020000,
                "size": 0x1000,
                "irq": 2,
                "parameters": {},
                "external_input": True,
            },
            {
                "component_id": "timer0",
                "component_type": "timer",
                "protocol": {"id": "apb", "version": "4"},
                "base": 0x80010000,
                "size": 0x1000,
                "irq": 1,
                "parameters": {},
                "external_input": True,
            },
            {
                "component_id": "spi0",
                "component_type": "spi",
                "protocol": {"id": "axi4-lite", "version": "1"},
                "base": 0x80040000,
                "size": 0x1000,
                "irq": 4,
                "parameters": {},
                "external_input": True,
            },
        ],
        "runtime": {
            "seed": 7,
            "duration_seconds": 3600,
            "checkpoint_seconds": 30,
        },
    }


class ProtocolCompositionManifestTests(unittest.TestCase):
    def write_manifest(self, document: dict[str, object]) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            json.dump(document, temporary)
        path = Path(temporary.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def load_and_validate(self, document: dict[str, object]):
        manifest = load_protocol_composition(self.write_manifest(document))
        validate_protocol_composition(
            manifest,
            load_protocol_catalog(PLUGIN_DIR),
            default_component_registry(ROOT),
        )
        return manifest

    def test_loads_and_sorts_approved_five_component_manifest(self) -> None:
        manifest = self.load_and_validate(approved_manifest())

        self.assertEqual(manifest.target_kind, "ibex_core")
        self.assertEqual([component.component_id for component in manifest.components], [
            "gpio0", "ram0", "spi0", "timer0", "uart0",
        ])
        self.assertEqual(manifest.components[1].parameters, {"WORDS": 4096})

    def test_schema_matches_optional_irq_contract(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual(
            schema["properties"]["components"]["items"]["properties"]["irq"]["type"],
            ["integer", "null"],
        )

    def test_rejects_unknown_top_level_field(self) -> None:
        document = approved_manifest()
        document["compiler_args"] = ["-evil"]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^manifest:unknown-field:compiler_args$"):
            load_protocol_composition(self.write_manifest(document))

    def test_rejects_duplicate_component_id(self) -> None:
        document = approved_manifest()
        document["components"][1]["component_id"] = "uart0"  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[1\]\.component_id:duplicate-id:uart0$"):
            self.load_and_validate(document)

    def test_rejects_unknown_component_type(self) -> None:
        document = approved_manifest()
        document["components"][0]["component_type"] = "dma"  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[0\]\.component_type:unknown:dma$"):
            self.load_and_validate(document)

    def test_rejects_unknown_or_unregistered_protocol(self) -> None:
        document = approved_manifest()
        document["components"][0]["protocol"] = {"id": "apb", "version": "3"}  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[0\]\.protocol:unsupported:apb@3$"):
            self.load_and_validate(document)

    def test_rejects_misaligned_or_wrong_sized_window(self) -> None:
        document = approved_manifest()
        document["components"][0]["base"] = 0x80030004  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[0\]\.base:not-4k-aligned$"):
            self.load_and_validate(document)

        document = approved_manifest()
        document["components"][1]["size"] = 0x1000  # type: ignore[index]
        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[1\]\.size:invalid-for:ram$"):
            self.load_and_validate(document)

    def test_rejects_overlapping_address_regions(self) -> None:
        document = approved_manifest()
        document["components"][2]["base"] = 0x80030000  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[2\]\.base:overlaps:uart0$"):
            self.load_and_validate(document)

    def test_rejects_duplicate_irq(self) -> None:
        document = approved_manifest()
        document["components"][2]["irq"] = 3  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[2\]\.irq:duplicate:3$"):
            self.load_and_validate(document)

    def test_rejects_out_of_range_parameter_and_zero_duration(self) -> None:
        document = approved_manifest()
        document["components"][1]["parameters"] = {"WORDS": 16385}  # type: ignore[index]

        with self.assertRaisesRegex(ProtocolCompositionError, r"^components\[1\]\.parameters\.WORDS:out-of-range$"):
            self.load_and_validate(document)

        document = approved_manifest()
        document["runtime"]["duration_seconds"] = 0  # type: ignore[index]
        with self.assertRaisesRegex(ProtocolCompositionError, r"^runtime\.duration_seconds:not-positive$"):
            load_protocol_composition(self.write_manifest(document))

    def test_rejects_ram_word_counts_not_supported_by_rtl(self) -> None:
        document = approved_manifest()
        document["components"][1]["parameters"] = {"WORDS": 1}  # type: ignore[index]
        with self.assertRaisesRegex(
            ProtocolCompositionError,
            r"^components\[1\]\.parameters\.WORDS:out-of-range$",
        ):
            self.load_and_validate(document)

        document = approved_manifest()
        document["components"][1]["parameters"] = {"WORDS": 6}  # type: ignore[index]
        with self.assertRaisesRegex(
            ProtocolCompositionError,
            r"^components\[1\]\.parameters\.WORDS:not-power-of-two$",
        ):
            self.load_and_validate(document)

    def test_rejects_invalid_utf8_as_manifest_error(self) -> None:
        temporary = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        with temporary:
            temporary.write(b"\xff")
        path = Path(temporary.name)
        self.addCleanup(path.unlink, missing_ok=True)

        with self.assertRaisesRegex(ProtocolCompositionError, r"^manifest:read:"):
            load_protocol_composition(path)

    def test_rejects_duplicate_json_keys(self) -> None:
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            temporary.write('{"schema_version":"protocol_composition.v1", "schema_version":"protocol_composition.v1"}')
        path = Path(temporary.name)
        self.addCleanup(path.unlink, missing_ok=True)

        with self.assertRaisesRegex(ProtocolCompositionError, r"^manifest:duplicate-key:schema_version$"):
            load_protocol_composition(path)

    def test_rejects_registry_with_missing_source_before_generation(self) -> None:
        manifest = load_protocol_composition(self.write_manifest(approved_manifest()))

        with self.assertRaisesRegex(ProtocolCompositionError, r"^registry\.uart:missing-source:"):
            validate_protocol_composition(
                manifest,
                load_protocol_catalog(PLUGIN_DIR),
                default_component_registry(ROOT / "missing-root"),
            )


if __name__ == "__main__":
    unittest.main()
