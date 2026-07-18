import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    DiscoveryResult,
    add_system_services_to_soc_ir,
    build_soc_ir_v2,
    builtin_cpu_execution_profile,
    plan_system,
    plan_system_services,
)
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from builder_fixtures import module_spec, rtl_module, system_spec  # noqa: E402


def _soc_fixture():
    specs = [
        module_spec("cpu", "cpu", "initiator"),
        module_spec("ram", "ram", "target", {"mode": "fixed", "base": 0x20000000,
                                                "size": 0x1000, "alignment": 0x1000}),
    ]
    spec = system_spec(specs)
    discovery = DiscoveryResult(("/cpu.sv", "/ram.sv"),
                                (rtl_module("cpu", "initiator"), rtl_module("ram", "target")))
    base = build_soc_ir_v2(spec, discovery, plan_system(spec, discovery),
                           source_digests={"cpu": "1" * 64, "ram": "2" * 64},
                           analysis_manifest_digest="3" * 64)
    return base


class SystemServicesTest(unittest.TestCase):
    VIEWS = (
        {"instance_id": "unseen_axi", "global_base": 0x20000000, "size": 0x1000},
        {"instance_id": "unseen_apb", "global_base": 0x20010000, "size": 0x1000},
    )

    def test_both_cpu_profiles_produce_same_service_map(self):
        pico = plan_system_services(self.VIEWS, builtin_cpu_execution_profile("picorv32"))
        ultra = plan_system_services(self.VIEWS, builtin_cpu_execution_profile("ultra_riscv"))
        self.assertEqual([(item.kind, item.base, item.size) for item in pico.regions],
                         [(item.kind, item.base, item.size) for item in ultra.regions])
        self.assertNotEqual(pico.profile_digest, ultra.profile_digest)
        self.assertEqual(next(item.base for item in pico.regions if item.kind == "boot_rom"), 0)
        self.assertEqual(next(item.base for item in pico.regions if item.kind == "control_mailbox"), 0x10000000)
        self.assertTrue(all(not item.coverage_scope for item in pico.regions))

    def test_auto_regions_avoid_leaf_and_fixed_service_windows(self):
        views = self.VIEWS + ({"instance_id": "low_ip", "global_base": 0x10000, "size": 0x10000},)
        plan = plan_system_services(views, builtin_cpu_execution_profile("picorv32"))
        ram = next(item for item in plan.regions if item.kind == "data_ram")
        self.assertEqual(ram.base, 0x20000)
        intervals = [(item.base, item.base + item.size) for item in plan.regions]
        self.assertTrue(all(a1 <= b0 or b1 <= a0 for index, (a0, a1) in enumerate(intervals)
                            for b0, b1 in intervals[index + 1:]))

    def test_result_is_deterministic_and_rename_independent(self):
        first = plan_system_services(self.VIEWS, builtin_cpu_execution_profile("picorv32"))
        second = plan_system_services(tuple(reversed(self.VIEWS)), builtin_cpu_execution_profile("picorv32"))
        renamed = tuple(dict(item, instance_id=f"renamed_{index}") for index, item in enumerate(self.VIEWS))
        third = plan_system_services(renamed, builtin_cpu_execution_profile("picorv32"))
        self.assertEqual(first.digest, second.digest)
        self.assertEqual([(item.kind, item.base) for item in first.regions],
                         [(item.kind, item.base) for item in third.regions])

    def test_fixed_service_overlap_fails_closed(self):
        with self.assertRaisesRegex(InputValidationError, "overlap"):
            plan_system_services((
                {"instance_id": "bad", "global_base": 0x10000000, "size": 0x1000},
            ), builtin_cpu_execution_profile("picorv32"))

    def test_services_become_explicit_socir_truth(self):
        soc = _soc_fixture()
        plan = plan_system_services(soc.address_views, builtin_cpu_execution_profile("picorv32"))
        augmented = add_system_services_to_soc_ir(soc, plan)
        node_ids = {item["node_id"] for item in augmented.service_nodes}
        endpoint_ids = {item["endpoint_id"] for item in augmented.endpoints}
        view_ids = {item["instance_id"] for item in augmented.address_views}
        self.assertIn("__myfuzz_boot_rom", node_ids)
        self.assertIn("__myfuzz_boot_rom.bus", endpoint_ids)
        self.assertIn("__myfuzz_control_mailbox", view_ids)
        self.assertEqual(augmented.provenance["system_service_plan_digest"], plan.digest)
        self.assertNotEqual(augmented.digest, soc.digest)


if __name__ == "__main__":
    unittest.main()
