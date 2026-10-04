from pathlib import Path
import unittest

from myfuzz.composition.component_profile import (
    bind_profile, elaborate_profile, load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import build_port_dispositions

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
                self.assertTrue(build_port_dispositions(
                    name + "_0", binding, clock_domain="core",
                    reset_domain="sys_rst",
                    profile_port_actions=profile.port_actions))


if __name__ == "__main__":
    unittest.main()
