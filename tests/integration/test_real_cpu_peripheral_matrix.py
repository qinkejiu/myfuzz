from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import unittest

from myfuzz.components import load_real_component_catalog
from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
)

from scripts.run_real_cpu_peripheral_matrix import COMBINATIONS


ROOT = Path(__file__).resolve().parents[2]
PROCESSOR_BEAT = ("processor-memory-beat", "1")
REAL_PROFILES = (
    "real_ram",
    "real_uart",
    "real_spi",
    "real_timer",
    "real_gpio",
    "real_ram64",
    "real_uart64",
    "real_spi64",
    "real_timer64",
    "real_gpio64",
)


class RealCpuPeripheralMatrixTests(unittest.TestCase):
    def test_schedule_reuses_each_cpu_and_32_bit_peripheral(self) -> None:
        cpu_counts = Counter(case["cpu"] for case in COMBINATIONS)
        peripheral_counts = Counter(
            peripheral
            for case in COMBINATIONS
            for peripheral in case["peripherals"]
        )
        self.assertEqual(set(cpu_counts), {"ibex", "cv32e40p", "cv32e20", "cva6"})
        self.assertTrue(all(count >= 2 for count in cpu_counts.values()))
        for peripheral in ("real_ram", "real_uart", "real_spi", "real_timer", "real_gpio"):
            self.assertGreaterEqual(peripheral_counts[peripheral], 2)

    def test_real_profiles_are_source_backed_common_targets(self) -> None:
        catalog = load_real_component_catalog()
        for component_type in REAL_PROFILES:
            profile = catalog.require(component_type)
            self.assertTrue(profile.implemented)
            self.assertEqual(profile.source_status, "implemented")
            self.assertEqual(profile.protocols, (PROCESSOR_BEAT,))
            self.assertFalse(profile.irq_capable)
            for source_path in profile.source_paths:
                self.assertTrue(
                    (ROOT / source_path).is_file(),
                    f"missing source for {component_type}: {source_path}",
                )

    def test_ibex_generic_plan_binds_two_real_targets(self) -> None:
        description = load_interface_description(
            ROOT / "configs/cpus/ibex/official_core_interface_description.json"
        )
        plan = plan_generic_composition(
            GenericCompositionRequest(
                description,
                ("real_ram", "real_uart"),
                (PROCESSOR_BEAT,),
                seed=20260909,
            ),
            base_dir=ROOT,
            component_catalog=load_real_component_catalog(),
        )
        self.assertTrue(plan.complete)
        self.assertEqual(len(plan.components), 2)
        self.assertEqual(
            {component["component_type"] for component in plan.components},
            {"real_ram", "real_uart"},
        )
        self.assertEqual(len(plan.processor_execution.routes), 2)

    def test_cv32e20_manifest_declares_split_obi_errors(self) -> None:
        manifest_path = ROOT / "configs/cpus/cv32e20/official_core_interface_description.json"
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(document["source"]["top_module"], "cve2_top")
        endpoints = {endpoint["function"]: endpoint for endpoint in document["endpoints"]}
        data_roles = {field["role"] for field in endpoints["data_memory_master"]["fields"]}
        instruction_roles = {
            field["role"] for field in endpoints["instruction_memory_master"]["fields"]
        }
        self.assertTrue({"req", "gnt", "addr", "rvalid", "rdata", "error"} <= instruction_roles)
        self.assertTrue(
            {"req", "gnt", "addr", "we", "wdata", "be", "rvalid", "rdata", "error"}
            <= data_roles
        )


if __name__ == "__main__":
    unittest.main()
