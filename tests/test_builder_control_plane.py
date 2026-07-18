import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import CONTROL_OPCODES, DiscoveryResult, build_control_plane, build_soc_ir_v2, plan_system  # noqa: E402
from builder_fixtures import module_spec, rtl_module, system_spec  # noqa: E402


def soc_fixture():
    modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
    spec = system_spec(modules)
    discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"), (rtl_module("cpu", "initiator"), rtl_module("ram", "target")))
    plan = plan_system(spec, discovery)
    return build_soc_ir_v2(spec, discovery, plan, source_digests={"cpu": "1" * 64, "ram": "2" * 64}, analysis_manifest_digest="3" * 64)


class ControlPlaneTest(unittest.TestCase):
    def test_layout_is_derived_and_mode_is_not_fuzz_entropy(self):
        generated = build_control_plane(soc_fixture(), cpu_profile_digest="4" * 64)
        names = {field.name for field in generated.layout.fields}
        self.assertIn("opcode", names)
        self.assertIn("target_region", names)
        self.assertIn("fault_kind", names)
        self.assertNotIn("mode", names)
        self.assertTrue(generated.control_ir.provenance["mode_out_of_band"])
        operations = {item["name"] for item in generated.control_ir.operations}
        self.assertEqual(operations, set(CONTROL_OPCODES))
        self.assertIn("POLL", operations)
        self.assertIn("PULSE_EXTERNAL", operations)
        self.assertIn("RESET_DOMAIN", operations)

    def test_region_width_depends_on_soc_structure_not_ip_names(self):
        soc = soc_fixture()
        one = build_control_plane(soc, cpu_profile_digest="4" * 64)
        view = dict(soc.address_views[0]); view["instance_id"] = "unseen_target"
        many_soc = replace(soc, address_views=tuple(dict(view, global_base=i * 4096) for i in range(9)), digest="")
        from myfuzz.builder.contracts import seal_contract
        many = build_control_plane(seal_contract(many_soc), cpu_profile_digest="4" * 64)
        widths = {field.name: field.width for field in many.layout.fields}
        self.assertEqual(widths["target_region"], 4)
        self.assertNotEqual(one.layout.digest, many.layout.digest)

    def test_same_inputs_are_canonical(self):
        soc = soc_fixture()
        first = build_control_plane(soc, cpu_profile_digest="4" * 64)
        second = build_control_plane(soc, cpu_profile_digest="4" * 64)
        self.assertEqual(first.control_ir.canonical_bytes(), second.control_ir.canonical_bytes())
        self.assertEqual(first.layout.digest, second.layout.digest)


if __name__ == "__main__":
    unittest.main()
