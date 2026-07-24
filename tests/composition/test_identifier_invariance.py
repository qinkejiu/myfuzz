from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.declarations import load_declarations
from myfuzz.composition.facts import normalize_facts
from myfuzz.composition.ids import canonical_id
from tests.composition.test_declarations import facts_document, valid_declarations


class IdentifierInvarianceTests(unittest.TestCase):
    def load(self, document: dict[str, object]):
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        with temporary:
            json.dump(document, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return load_declarations(Path(temporary.name))

    def test_misleading_rtl_symbols_do_not_change_normalized_facts(self) -> None:
        neutral = facts_document()
        renamed = copy.deepcopy(neutral)
        neutral["modules"][0]["name"] = "unit_0"  # type: ignore[index]
        neutral["ports"][0]["name"] = "pin_0"  # type: ignore[index]
        neutral["ports"][1]["name"] = "pin_1"  # type: ignore[index]
        neutral["source_symbols"] = [{"id": 10, "name": "pin_0"}]
        renamed["modules"][0]["name"] = "uart_cpu_reset_mmio"  # type: ignore[index]
        renamed["ports"][0]["name"] = "axi_clock_request"  # type: ignore[index]
        renamed["ports"][1]["name"] = "debug_irq_response"  # type: ignore[index]
        renamed["source_symbols"] = [{"id": 10, "name": "axi_clock_request"}]

        self.assertEqual(normalize_facts(neutral), normalize_facts(renamed))

    def test_source_rename_with_same_explicit_bindings_keeps_declarations_equal(self) -> None:
        original = valid_declarations()
        renamed = copy.deepcopy(original)
        # This label is intentionally diagnostic-only and must not affect bindings.
        original["components"][0]["diagnostic_label"] = "module_0"  # type: ignore[index]
        renamed["components"][0]["diagnostic_label"] = "uart_cpu_axi"  # type: ignore[index]

        self.assertEqual(self.load(original), self.load(renamed))

    def test_canonical_id_hashes_whole_opaque_declaration_without_tokenizing(self) -> None:
        declared_id = "uart_cpu_axi_0007"
        self.assertEqual(canonical_id("component", declared_id), canonical_id("component", declared_id))
        self.assertNotEqual(canonical_id("component", declared_id), canonical_id("endpoint", declared_id))


if __name__ == "__main__":
    unittest.main()
