"""CVA6 source-bound boundary checks; runtime remains opt-in until executed."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from myfuzz.composition.processor_adapters import ProcessorAdapterDefinition


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/soc/cva6-pulp.json"
INTERFACE = ROOT / "configs/cpus/cva6/official_core_interface_description.json"


class Cva6BoundaryTests(unittest.TestCase):
    def test_profile_is_rv64_axi4_and_rejects_unproven_fetch_bursts(self):
        profile = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(profile["cpu"]["xlen"], 64)
        self.assertEqual(profile["cpu"]["protocol"], ["axi4", "1"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["container_request"], "noc_req_o")
        self.assertTrue(profile["cpu"]["memory_boundary"]["packed_members_compiler_proven"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["burst_policy"], "reject_non_single_beat")
        self.assertFalse(profile["cpu"]["memory_boundary"]["fetch_burst_required"])

    def test_official_interface_keeps_all_packed_axi_fields_on_declared_containers(self):
        document = json.loads(INTERFACE.read_text(encoding="utf-8"))
        memory = next(endpoint for endpoint in document["endpoints"]
                      if endpoint.get("function") == "memory_master")
        packed = [field for field in memory["fields"] if "physical" in field]
        self.assertEqual(len(packed), 45)
        self.assertEqual({field["physical"]["port"] for field in packed},
                         {"noc_req_o", "noc_resp_i"})
        self.assertTrue(all(field["physical"].get("member_path") for field in packed))
        self.assertEqual({field["physical"]["port"] for field in packed
                          if (field["role"].startswith("aw") and field["role"] != "awready")
                          or field["role"] in {"wdata", "wstrb", "wlast", "wvalid", "wuser"}},
                         {"noc_req_o"})

    def test_mmio_profiles_explicitly_reject_unsupported_wide_crossing(self):
        profile = json.loads(CONFIG.read_text(encoding="utf-8"))
        for peripheral in profile["peripherals"]:
            self.assertEqual(peripheral["data_width"], 32)
            self.assertEqual(peripheral["width_conversion"],
                             {"spanning_write": "reject", "spanning_read": "reject"})
        self.assertEqual(profile["acceptance"]["environment"], "MYFUZZ_SOC_REAL=1")
        self.assertTrue(profile["acceptance"]["requires_runtime"])


if __name__ == "__main__":
    unittest.main()
