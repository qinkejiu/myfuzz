"""Schema and provenance checks for the eight P12 composition cells."""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "configs/soc/matrix.json"


class SocMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_matrix_covers_two_cpus_three_families_and_two_mixed_cells(self):
        document = self.document
        self.assertEqual(document["schema_version"], "soc_matrix.v1")
        self.assertEqual(set(document["cpus"]), {"ibex", "cva6"})
        self.assertEqual(set(document["families"]), {"opentitan", "pulp", "zipcpu"})
        cells = document["cells"]
        self.assertEqual(len(cells), 8)
        ids = {cell["cell_id"] for cell in cells}
        self.assertEqual(len(ids), 8)
        regular = [cell for cell in cells if cell["family"] != "mixed"]
        self.assertEqual({(cell["cpu"], cell["family"]) for cell in regular},
                         {(cpu, family) for cpu in document["cpus"] for family in document["families"]})
        self.assertEqual({cell["cpu"] for cell in cells if cell["family"] == "mixed"},
                         {"ibex", "cva6"})

    def test_each_cell_has_distinct_real_ip_evidence_and_three_modes(self):
        lock_ids = {
            item["id"] for item in json.loads((ROOT / "configs/soc/sources.lock.json").read_text())["components"]
        }
        for cell in self.document["cells"]:
            with self.subTest(cell=cell["cell_id"]):
                path = ROOT / cell["config"]
                self.assertTrue(path.is_file(), cell["config"])
                config = json.loads(path.read_text(encoding="utf-8"))
                cpu = config["cpu"]["id"] if isinstance(config["cpu"], dict) else config["cpu"]
                self.assertEqual(cpu, cell["cpu"])
                self.assertEqual(config["distinct_ip_count"], cell["distinct_ip_count"])
                self.assertEqual(config.get("modes"), ["cpu_only", "mmio_only", "mixed"])
                self.assertEqual(len(config["peripherals"]), cell["distinct_ip_count"])
                ids = [item["id"] if isinstance(item, dict) else item
                       for item in config["peripherals"]]
                self.assertEqual(len(ids), len(set(ids)))
                self.assertEqual(len(config["source_locks"]), 1 + len(ids))
                self.assertTrue(set(config["source_locks"]).issubset(lock_ids))
                if cell["family"] == "mixed":
                    self.assertEqual(set(config["families"]), {"opentitan", "pulp", "zipcpu"})
                    self.assertEqual(len(set(config["families"])), len(config["peripherals"]))
                else:
                    self.assertEqual(config["families"], [cell["family"]])

    def test_matrix_declares_real_acceptance_as_opt_in_and_does_not_fake_runtime(self):
        self.assertEqual(self.document["acceptance"]["environment"], "MYFUZZ_SOC_REAL=1")
        for cell in self.document["cells"]:
            config = json.loads((ROOT / cell["config"]).read_text(encoding="utf-8"))
            self.assertEqual(config.get("runtime_status", config.get("status")),
                             "preflight_only" if "runtime_status" in config else "source_locked_render_profile")
            self.assertTrue(config["acceptance"]["requires_runtime"])


if __name__ == "__main__":
    unittest.main()
