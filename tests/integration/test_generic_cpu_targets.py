from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.composition import load_interface_description, write_generic_composition
from tests.composition.test_protocol_composer import ContractCompositionTests
from tests.integration.test_processor_auto_wiring import _unified_ready_valid_fixture


ROOT = Path(__file__).resolve().parents[2]


class GenericCpuTargetTests(unittest.TestCase):
    def test_cpu_neutral_manifests_describe_split_and_unified_topologies(self) -> None:
        cv32 = load_interface_description(
            ROOT / "configs/cpus/cv32e40p/official_core_interface_description.json"
        )
        pico = load_interface_description(
            ROOT / "configs/cpus/picorv32/official_core_interface_description.json"
        )
        cv32_functions = {endpoint.function for endpoint in cv32.endpoints}
        self.assertIn("instruction_memory_master", cv32_functions)
        self.assertIn("data_memory_master", cv32_functions)
        pico_memory = next(endpoint for endpoint in pico.endpoints if endpoint.function == "memory_master")
        self.assertEqual(pico_memory.protocol, ("ready-valid-memory", "1"))
        self.assertIn(
            "instruction_identity",
            {field.role for field in pico_memory.fields},
        )

    def test_unified_fixture_composes_and_compiles_with_explicit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _unified_ready_valid_fixture(root)
            output = root / "composition"
            summary = write_generic_composition(
                plan,
                output,
                base_dir=root,
                contract_transducer=ContractCompositionTests()._contract(),
            )
            self.assertTrue(summary["complete"])
            execution = json.loads(
                (output / "processor_execution.v1.json").read_text(encoding="utf-8")
            )
            self.assertEqual(execution["classification"]["mode"], "explicit_signal")
            self.assertEqual(execution["classification"]["field_role"], "instruction_identity")
            if shutil.which("iverilog") is not None:
                result = subprocess.run(
                    ("iverilog", "-g2012", "-s", "generic_composition_top", "-o", "composition.vvp", "-f", "sources.f"),
                    cwd=output, capture_output=True, text=True, check=False, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_usage_guide_documents_generic_flow_and_diagnostics(self) -> None:
        guide = (ROOT / "docs/superpowers/examples/generic-riscv-cpu-direct-integration.md").read_text(
            encoding="utf-8"
        )
        for phrase in (
            "plan_generic_composition", "write_generic_composition",
            "compile_contract_transducer", "mem_instr", "missing-instruction-identity",
        ):
            self.assertIn(phrase, guide)


if __name__ == "__main__":
    unittest.main()
