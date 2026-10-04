import json
from copy import deepcopy
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import (
    ComponentProfileError, bind_profile, elaborate_profile, load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import PortDispositionError, build_port_dispositions

ROOT = Path(__file__).resolve().parents[2]
TOPS = {
    "picorv32": ("picorv32", "ready-valid-memory", "1"),
    "picorv32_axi": ("picorv32_axi", "axi4-lite", "1"),
    "picorv32_wb": ("picorv32_wb", "wishbone", "classic"),
}


class PicoRV32SourceProfileTests(unittest.TestCase):
    def test_each_variant_is_pinned_and_classifies_every_bit(self):
        for name, (top, protocol, version) in TOPS.items():
            with self.subTest(name=name):
                profile = load_component_profile(
                    ROOT / f"configs/cpus/{name}/component_profile.json")
                self.assertEqual(profile.source.revision,
                                 "git:ef203c2b0a3fb793280f5114941416c425c5b461")
                facts = elaborate_profile(profile, base_dir=ROOT)
                self.assertEqual(facts.selection, "all")
                self.assertEqual(facts.top_module, top)
                expected_counts = {
                    "picorv32": (27, 409),
                    "picorv32_axi": (32, 384),
                    "picorv32_wb": (24, 341),
                }
                self.assertEqual((len(facts.ports), sum(p.width for p in facts.ports)),
                                 expected_counts[name])
                port_names = {p.name for p in facts.ports}
                self.assertFalse(any(p.startswith("rvfi_") for p in port_names))
                if name == "picorv32_axi":
                    self.assertTrue({"mem_axi_bresp", "mem_axi_rresp"}.isdisjoint(port_names))
                if name == "picorv32_wb":
                    self.assertTrue({"wbm_err_i", "wbm_stall_i"}.isdisjoint(port_names))
                binding = bind_profile(profile, facts)
                self.assertEqual(binding.endpoint("processor.memory").protocol,
                                 (protocol, version))
                ledger = build_port_dispositions(
                    name + "_0", binding, clock_domain="core",
                    reset_domain="sys_rst",
                    profile_port_actions=profile.port_actions)
                self.assertTrue(ledger)
                self.assertEqual(sum(entry.bit_hi - entry.bit_lo + 1 for entry in ledger),
                                 sum(port.width for port in facts.ports))

    def test_wrong_source_revision_is_rejected(self):
        for name in TOPS:
            with self.subTest(name=name):
                document = json.loads((ROOT / f"configs/cpus/{name}/component_profile.json").read_text())
                document["source"]["revision"] = "git:" + "0" * 40
                with self.assertRaisesRegex(ComponentProfileError, "git-revision-mismatch"):
                    elaborate_profile(load_component_profile(document), base_dir=ROOT)

    def test_missing_input_action_is_rejected(self):
        for name in TOPS:
            with self.subTest(name=name):
                document = json.loads((ROOT / f"configs/cpus/{name}/component_profile.json").read_text())
                document["port_actions"] = [action for action in document["port_actions"]
                                            if action["port"] != "pcpi_ready"]
                profile = load_component_profile(document)
                binding = bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))
                with self.assertRaisesRegex(PortDispositionError,
                                            f"undisposed-port-bits:{name}_0:pcpi_ready:0:0"):
                    build_port_dispositions(
                        name + "_0", binding, clock_domain="core", reset_domain="sys_rst",
                        profile_port_actions=profile.port_actions)

    def test_duplicate_physical_memory_output_is_rejected(self):
        roles = {
            "picorv32": ("addr", "wdata", "mem_addr"),
            "picorv32_axi": ("awaddr", "araddr", "mem_axi_awaddr"),
            "picorv32_wb": ("adr", "dat_w", "wbm_adr_o"),
        }
        for name, (owner, duplicate, port) in roles.items():
            with self.subTest(name=name):
                document = json.loads((ROOT / f"configs/cpus/{name}/component_profile.json").read_text())
                endpoint = next(item for item in document["endpoints"]
                                if item["endpoint_id"] == "processor.memory")
                fields = {item["role"]: item for item in endpoint["fields"]}
                fields[duplicate]["aliases"] = deepcopy(fields[owner]["aliases"])
                with self.assertRaisesRegex(ComponentProfileError,
                                            f"duplicate-port-binding:{port}:"):
                    profile = load_component_profile(document)
                    bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))


if __name__ == "__main__":
    unittest.main()
