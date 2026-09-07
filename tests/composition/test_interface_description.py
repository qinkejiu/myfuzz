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
    PhysicalSelector,
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
    def test_warning_policy_defaults_omitted_and_recorded_mode_round_trips(self) -> None:
        document = interface_document()
        document["source"]["elaboration"] = {"frontend": "verilator-json"}
        fatal = load_interface_description(document)
        self.assertEqual("fatal", fatal.source.elaboration.warning_policy)
        self.assertNotIn("warning_policy", interface_description_document(fatal)["source"]["elaboration"])
        document["source"]["elaboration"]["warning_policy"] = "recorded-nonfatal"
        recorded = load_interface_description(document)
        self.assertEqual("recorded-nonfatal", recorded.source.elaboration.warning_policy)
        self.assertEqual("recorded-nonfatal", interface_description_document(recorded)["source"]["elaboration"]["warning_policy"])
        document["source"]["elaboration"]["warning_policy"] = "ignore"
        with self.assertRaises(ValueError):
            load_interface_description(document)
    def test_loads_explicit_physical_member_selector(self) -> None:
        document = interface_document()
        document["source"]["elaboration"] = {"frontend": "verilator-json"}
        document["endpoints"][0]["fields"][0]["physical"] = {"port": "req_o", "member_path": ["aw", "addr"]}
        value = load_interface_description(document)
        self.assertEqual(PhysicalSelector("req_o", ("aw", "addr")), value.endpoints[0].fields[0].physical)
        fields = [field for endpoint in interface_description_document(value)["endpoints"] for field in endpoint.get("fields", [])]
        selected = next(field for field in fields if field["role"] == "status")
        self.assertEqual({"port": "req_o", "member_path": ["aw", "addr"]}, selected["physical"])

    def test_rejects_malformed_or_alias_mixed_physical_selectors(self) -> None:
        cases = (
            {"port": "req", "member_path": []},
            {"port": "bad-port", "member_path": ["data"]},
            {"port": "req"},
            {"port": "req", "member_path": ["data"], "extra": True},
        )
        for physical in cases:
            with self.subTest(physical=physical):
                document = interface_document()
                document["source"]["elaboration"] = {"frontend": "verilator-json"}
                document["endpoints"][0]["fields"][0]["physical"] = physical
                with self.assertRaises(ValueError):
                    load_interface_description(document)
        document = interface_document()
        document["source"]["elaboration"] = {"frontend": "verilator-json"}
        document["endpoints"][0]["fields"][0].update({"aliases": [], "physical": {"port": "req", "member_path": ["data"]}})
        with self.assertRaises(ValueError):
            load_interface_description(document)
        with self.assertRaisesRegex(ValueError, "invalid-physical-selector"):
            PhysicalSelector("req", "data")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "physical-aliases-mutually-exclusive"):
            FieldHint("status", ("req",), physical=PhysicalSelector("req", ("data",)))
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
