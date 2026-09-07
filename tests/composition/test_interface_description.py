from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from myfuzz.composition.interface_description import (
    ElaborationSettings,
    EndpointDescription,
    FieldHint,
    InterfaceDescription,
    SourceLocator,
    interface_description_document,
    load_interface_description,
)


def interface_document() -> dict[str, object]:
    return {
        "schema_version": "interface_description.v1",
        "source": {
            "root": "third_party/cpu",
            "revision": "sha256:" + "a" * 64,
            "top_module": "cpu_top",
            "files": ["rtl/top.sv", "rtl/bus.sv"],
            "include_roots": ["rtl/include"],
        },
        "endpoints": [
            {
                "endpoint_id": "cpu.z",
                "function": "debug",
                "fields": [{"role": "status"}, {"role": "address"}],
            },
            {
                "endpoint_id": "cpu.a",
                "function": "memory_master",
                "module": "cpu_top",
                "hierarchy": ["core", "data_bus"],
                "aliases": ["data_master", "dbus"],
                "protocol": ["ready-valid-mmio", "1"],
                "fields": [{"role": "write_data", "required": False}],
            },
        ],
    }


class InterfaceDescriptionTests(unittest.TestCase):
    def test_loads_and_canonicalizes_elaboration_settings(self) -> None:
        document = interface_document()
        document["source"]["elaboration"] = {
            "frontend": "verilator-json",
            "defines": [{"name": "ZED", "value": "ON"}, {"name": "ALPHA", "value": "1"}],
            "parameters": [{"name": "WIDTH", "value": "13"}],
        }

        value = load_interface_description(document)

        self.assertEqual((("ALPHA", "1"), ("ZED", "ON")), value.source.elaboration.defines)
        serialized = interface_description_document(value)
        self.assertEqual(["ALPHA", "ZED"], [item["name"] for item in serialized["source"]["elaboration"]["defines"]])

    def test_rejects_duplicate_and_unsafe_elaboration_pairs(self) -> None:
        for entries in (
            [{"name": "WIDTH", "value": "1"}, {"name": "WIDTH", "value": "2"}],
            [{"name": "BAD-NAME", "value": "1"}],
            [{"name": "WIDTH", "value": "1+2"}],
        ):
            with self.subTest(entries=entries):
                document = interface_document()
                document["source"]["elaboration"] = {"frontend": "verilator-json", "parameters": entries}
                with self.assertRaises(ValueError):
                    load_interface_description(document)

    def test_direct_elaboration_settings_are_validated_and_normalized(self) -> None:
        settings = ElaborationSettings("verilator-json", (("Z", "1"), ("A", "2")))
        self.assertEqual((("A", "2"), ("Z", "1")), settings.defines)
        with self.assertRaisesRegex(ValueError, "unsupported-elaboration-frontend"):
            ElaborationSettings("other")
        with self.assertRaisesRegex(ValueError, "duplicate-elaboration-define"):
            ElaborationSettings("verilator-json", (("A", "1"), ("A", "2")))
    def write_document(self, document: dict[str, object]) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            json.dump(document, temporary)
        path = Path(temporary.name)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_loads_semantic_description_without_hdl_facts(self) -> None:
        value = load_interface_description(interface_document())

        self.assertIsInstance(value, InterfaceDescription)
        self.assertIsInstance(value.source, SourceLocator)
        self.assertEqual(value.source.files, ("rtl/top.sv", "rtl/bus.sv"))
        self.assertEqual(value.endpoints[0].endpoint_id, "cpu.z")
        self.assertEqual(value.endpoints[0].fields[0], FieldHint(role="status"))
        self.assertEqual(value.endpoints[1].protocol, ("ready-valid-mmio", "1"))
        with self.assertRaises((FrozenInstanceError, TypeError)):
            value.source.source_root = "other"  # type: ignore[misc]

    def test_loads_json_path_and_canonicalizes_only_serialization_order(self) -> None:
        value = load_interface_description(self.write_document(interface_document()))

        self.assertEqual([endpoint.endpoint_id for endpoint in value.endpoints], ["cpu.z", "cpu.a"])
        self.assertEqual([field.role for field in value.endpoints[0].fields], ["status", "address"])
        self.assertEqual(
            interface_description_document(value),
            {
                "schema_version": "interface_description.v1",
                "source": {
                    "root": "third_party/cpu",
                    "revision": "sha256:" + "a" * 64,
                    "top_module": "cpu_top",
                    "files": ["rtl/top.sv", "rtl/bus.sv"],
                    "include_roots": ["rtl/include"],
                },
                "endpoints": [
                    {
                        "endpoint_id": "cpu.a",
                        "function": "memory_master",
                        "module": "cpu_top",
                        "hierarchy": ["core", "data_bus"],
                        "aliases": ["data_master", "dbus"],
                        "protocol": ["ready-valid-mmio", "1"],
                        "fields": [{"role": "write_data", "required": False}],
                    },
                    {
                        "endpoint_id": "cpu.z",
                        "function": "debug",
                        "fields": [{"role": "address"}, {"role": "status"}],
                    },
                ],
            },
        )

    def test_serializer_omits_empty_optional_members(self) -> None:
        value = InterfaceDescription(
            source=SourceLocator("third_party/cpu", "sha256:" + "b" * 64, "cpu_top"),
            endpoints=(EndpointDescription("cpu.debug", "debug"),),
        )

        self.assertEqual(
            interface_description_document(value),
            {
                "schema_version": "interface_description.v1",
                "source": {
                    "root": "third_party/cpu",
                    "revision": "sha256:" + "b" * 64,
                    "top_module": "cpu_top",
                },
                "endpoints": [{"endpoint_id": "cpu.debug", "function": "debug"}],
            },
        )


if __name__ == "__main__":
    unittest.main()
