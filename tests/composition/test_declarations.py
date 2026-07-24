from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.declarations import DeclarationError, load_declarations
from myfuzz.composition.facts import normalize_facts


def facts_document() -> dict[str, object]:
    return {
        "schema_version": "hdl_facts.v2",
        "tool": {
            "frontend": "test",
            "verilator_revision": "test",
            "input_hash": "sha256:" + "0" * 64,
        },
        "modules": [{"id": 1, "ports": [10, 11], "instances": []}],
        "parameters": [],
        "ports": [
            {"id": 10, "module_id": 1, "direction": "input", "width": 1,
             "signed": False, "declared_role": "clock"},
            {"id": 11, "module_id": 1, "direction": "output", "width": 32,
             "signed": False, "declared_role": "response.data"},
        ],
        "instances": [],
        "pin_bindings": [],
        "expressions": [],
        "dataflow_edges": [],
        "control_edges": [],
        "clock_reset_checks": [],
        "local_address_facts": [],
        "source_locations": [],
        "source_symbols": [],
        "diagnostics": {"errors": [], "warnings": [], "unsupported": []},
    }


def valid_declarations() -> dict[str, object]:
    return {
        "schema_version": "composition_declarations.v1",
        "components": [
            {
                "id": "component-token-1",
                "module_id": 1,
                "role": "initiator",
                "ports": [
                    {"port_id": 10, "role": "clock", "required": True},
                    {"port_id": 11, "role": "response.data", "required": True},
                ],
                "protocol_bindings": [
                    {
                        "id": "endpoint-token-1",
                        "protocol_id": "ready-valid-mmio",
                        "side": "initiator",
                        "fields": [{"field_role": "response.data", "port_id": 11}],
                    },
                ],
                "clock_reset": [
                    {
                        "port_id": 10,
                        "kind": "clock",
                        "domain_id": "domain-token-1",
                        "active_level": "high",
                        "synchronous": True,
                    },
                ],
            },
        ],
    }


class DeclarationTests(unittest.TestCase):
    def write_declarations(self, document: dict[str, object]) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            json.dump(document, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_loads_explicit_component_port_protocol_and_clock_declarations(self) -> None:
        declarations = load_declarations(self.write_declarations(valid_declarations()))
        facts = normalize_facts(facts_document())

        declarations.validate_against(facts)

        self.assertEqual(len(declarations.components), 1)
        component = declarations.components[0]
        self.assertIsInstance(component.id, int)
        self.assertEqual(component.module_id, 1)
        self.assertEqual(component.role, "initiator")
        self.assertEqual(component.ports[0].port_id, 10)
        self.assertEqual(component.protocol_bindings[0].fields[0].port_id, 11)

    def test_rejects_component_without_explicit_role(self) -> None:
        document = valid_declarations()
        del document["components"][0]["role"]  # type: ignore[index]

        with self.assertRaisesRegex(DeclarationError, r"^components\[0\]\.role:missing$"):
            load_declarations(self.write_declarations(document))

    def test_rejects_duplicate_declared_component_id(self) -> None:
        document = valid_declarations()
        duplicate = dict(document["components"][0])  # type: ignore[index]
        duplicate["module_id"] = 2
        document["components"].append(duplicate)  # type: ignore[index]

        with self.assertRaisesRegex(DeclarationError, r"^components\[1\]\.id:duplicate-id$"):
            load_declarations(self.write_declarations(document))

    def test_rejects_component_port_without_explicit_role(self) -> None:
        document = valid_declarations()
        del document["components"][0]["ports"][1]["role"]  # type: ignore[index]

        with self.assertRaisesRegex(DeclarationError, r"^components\[0\]\.ports\[1\]\.role:missing$"):
            load_declarations(self.write_declarations(document))

    def test_rejects_undeclared_fact_port_for_component(self) -> None:
        document = valid_declarations()
        document["components"][0]["ports"].pop()  # type: ignore[index]
        declarations = load_declarations(self.write_declarations(document))

        with self.assertRaisesRegex(DeclarationError, r"^components\[0\]\.ports:missing-fact-port:11$"):
            declarations.validate_against(normalize_facts(facts_document()))

    def test_explicit_declaration_binds_uninterpreted_external_role(self) -> None:
        facts = facts_document()
        for port in facts["ports"]:  # type: ignore[union-attr]
            port["declared_role"] = "uninterpreted_external"
        declarations = load_declarations(self.write_declarations(valid_declarations()))

        declarations.validate_against(normalize_facts(facts))

    def test_rejects_conflict_with_non_placeholder_fact_role(self) -> None:
        document = valid_declarations()
        document["components"][0]["ports"][1]["role"] = "request.data"  # type: ignore[index]
        declarations = load_declarations(self.write_declarations(document))

        with self.assertRaisesRegex(DeclarationError, r"^components\[0\]\.ports:11:role-conflict$"):
            declarations.validate_against(normalize_facts(facts_document()))


if __name__ == "__main__":
    unittest.main()
