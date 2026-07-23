from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.contracts import ContractError, canonical_bytes, content_hash, validate_contract


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"
SCHEMAS = (
    "hdl_facts.v2",
    "protocol.v1",
    "composition_ir.v1",
    "candidate_manifest.v1",
)


def load_fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ContractTests(unittest.TestCase):
    def test_valid_documents_are_accepted(self) -> None:
        for schema_id in SCHEMAS:
            with self.subTest(schema_id=schema_id):
                validate_contract(load_fixture(f"{schema_id}.valid.json"), schema_id)

    def test_missing_versions_are_rejected(self) -> None:
        for schema_id in SCHEMAS:
            with self.subTest(schema_id=schema_id):
                with self.assertRaisesRegex(ContractError, rf"^{schema_id}:schema_version:missing$"):
                    validate_contract(load_fixture(f"{schema_id}.missing.json"), schema_id)

    def test_incompatible_major_versions_are_rejected(self) -> None:
        for schema_id in SCHEMAS:
            with self.subTest(schema_id=schema_id):
                with self.assertRaisesRegex(ContractError, rf"^{schema_id}:schema_version:unsupported$"):
                    validate_contract(load_fixture(f"{schema_id}.version.json"), schema_id)

    def test_missing_explicit_role_is_rejected(self) -> None:
        document = load_fixture("hdl_facts.v2.role.json")
        with self.assertRaisesRegex(ContractError, r"^hdl_facts.v2:ports\[0\]:declared_role:missing$"):
            validate_contract(document, "hdl_facts.v2")

    def test_missing_explicit_binding_is_rejected(self) -> None:
        document = load_fixture("composition_ir.v1.binding.json")
        with self.assertRaisesRegex(ContractError, r"^composition_ir.v1:endpoint_bindings\[0\]:fields:missing$"):
            validate_contract(document, "composition_ir.v1")

    def test_duplicate_stable_ids_are_rejected(self) -> None:
        for schema_id in SCHEMAS:
            with self.subTest(schema_id=schema_id):
                with self.assertRaisesRegex(ContractError, rf"^{schema_id}:.*:duplicate-id$"):
                    validate_contract(load_fixture(f"{schema_id}.duplicate.json"), schema_id)

    def test_invalid_direction_is_rejected(self) -> None:
        document = load_fixture("hdl_facts.v2.direction.json")
        with self.assertRaisesRegex(ContractError, r"^hdl_facts.v2:ports\[0\]:direction:invalid$"):
            validate_contract(document, "hdl_facts.v2")

    def test_unknown_members_are_forward_compatible(self) -> None:
        document = load_fixture("protocol.v1.valid.json")
        document["future_member"] = {"wire_version": 2}
        validate_contract(document, "protocol.v1")

    def test_canonical_hash_is_order_independent(self) -> None:
        document = load_fixture("protocol.v1.valid.json")
        reordered = dict(reversed(list(document.items())))
        self.assertEqual(canonical_bytes(document), canonical_bytes(reordered))
        self.assertEqual(content_hash(document), content_hash(reordered))
        self.assertRegex(content_hash(document), r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
