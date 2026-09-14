from __future__ import annotations

import copy
import json
import unittest

from myfuzz.composition.soc_fabric import SocFabricError, build_soc_fabric


def route(route_id: int, function: str, width: int, read_only: bool = False) -> dict:
    return {
        "route_id": route_id,
        "function": function,
        "target_protocol": ["processor-memory-beat", "1"],
        "parameters": {"READ_ONLY": int(read_only)},
        "widths": {"address": 32, "data": width},
        "backend_contract": {
            "mode": "single_outstanding_request_response",
            "protocol": ["processor-memory-beat", "1"],
            "capabilities": {"max_outstanding": 1, "max_wait_cycles": 19},
        },
    }


def execution(width: int = 32, unified: bool = False) -> dict:
    routes = ([route(7, "processor_memory_master", width)] if unified else [
        route(8, "instruction_memory_master", width, True),
        route(4, "data_memory_master", width),
    ])
    return {
        "schema_version": "processor_execution.v1",
        "execution_hash": "sha256:" + "1" * 64,
        "routes": routes,
    }


def spec(width: int = 32, unified: bool = False) -> dict:
    cpu = ([{"source_id": "cpu", "kind": "cpu_unified", "data_width": width,
             "address_width": 32, "protocol": ["axi4", "1"]}]
           if unified else [
               {"source_id": "ifetch", "kind": "cpu_instruction", "data_width": width,
                "address_width": 32, "protocol": ["obi", "1"]},
               {"source_id": "data", "kind": "cpu_data", "data_width": width,
                "address_width": 32, "protocol": ["obi", "1"]},
           ])
    masters = cpu + [{"source_id": "fuzz", "kind": "fuzz_mmio", "data_width": width,
                      "address_width": 32, "protocol": ["processor-memory-beat", "1"]}]
    all_sources = [m["source_id"] for m in masters]
    return {
        "masters": masters,
        "memory_regions": [
            {"region_id": "ram_alias_b", "component_id": "ram", "base": 0x2000,
             "size": 0x1000, "permissions": {"read": True, "write": True, "execute": True},
             "physical_memory_id": "ram0", "initialization_policy": "on_demand"},
            {"region_id": "ram_alias_a", "component_id": "ram", "base": 0,
             "size": 0x1000, "permissions": {"read": True, "write": True, "execute": True},
             "physical_memory_id": "ram0", "initialization_policy": "on_demand"},
        ],
        "targets": [
            {"target_id": "uart", "component_id": "uart", "window": {"base": 0x4000, "size": 0x100},
             "request_sources": all_sources, "data_width": 32,
             "permissions": {"read": True, "write": True, "execute": False}},
            {"target_id": "ram_b", "component_id": "ram", "window": {"base": 0x2000, "size": 0x1000},
             "request_sources": all_sources, "data_width": width},
            {"target_id": "ram_a", "component_id": "ram", "window": {"base": 0, "size": 0x1000},
             "request_sources": all_sources, "data_width": width},
        ],
        "resources": {"limits": {"max_wait_cycles": 31}},
    }


class SocFabricPlanTests(unittest.TestCase):
    def test_reordering_is_deterministic_and_aliases_share_target(self) -> None:
        first = build_soc_fabric(spec(), execution())
        reordered = spec()
        for key in ("masters", "memory_regions", "targets"):
            reordered[key].reverse()
        second = build_soc_fabric(reordered, execution())
        self.assertEqual(first, second)
        self.assertEqual(["ifetch", "data", "fuzz"], [x["source_id"] for x in first["sources"]])
        windows = {w["window_id"]: w for w in first["decode"]["windows"]}
        self.assertEqual(windows["ram_alias_a"]["target_index"], windows["ram_alias_b"]["target_index"])
        self.assertEqual(0, windows["ram_alias_a"]["target_base"])
        self.assertEqual(0, windows["ram_alias_b"]["target_base"])
        json.dumps(first)

    def test_32_bit_has_no_width_adapter_and_mmio_is_non_executable(self) -> None:
        plan = build_soc_fabric(spec(), execution())
        self.assertEqual([], plan["width_adapters"])
        uart = next(w for w in plan["decode"]["windows"] if w["window_id"] == "uart")
        self.assertEqual({"read": True, "write": True, "execute": False}, uart["permissions"])
        self.assertNotIn("MAX_WAIT_CYCLES", plan["rtl"]["parameters"])
        self.assertEqual(0, plan["rtl"]["parameters"]["RESET_CLEARS_TARGETS"])
        self.assertEqual("external_runtime_watchdog", plan["watchdog"]["enforcement"])
        self.assertFalse(plan["watchdog"]["rtl_enforced"])

    def test_caller_claim_cannot_enable_reset_clear_without_physical_proof(self) -> None:
        claimed = spec()
        claimed["resources"]["reset_distribution"] = {
            "fabric_and_all_targets_verified": True,
        }
        plan = build_soc_fabric(claimed, execution())
        self.assertEqual(0, plan["rtl"]["parameters"]["RESET_CLEARS_TARGETS"])
        self.assertFalse(plan["reset_recovery"]["scope_verified"])

    def test_64_to_32_mmio_requires_explicit_safe_split_policy(self) -> None:
        wide = spec(64, unified=True)
        wide["targets"][0]["width_conversion"] = {
            "spanning_write": "split_side_effect_free",
            "spanning_read": "reject",
        }
        plan = build_soc_fabric(wide, execution(64, unified=True))
        adapter = plan["width_adapters"][0]
        self.assertEqual("mmio_width_adapter", adapter["module"])
        self.assertEqual(1, adapter["parameters"]["ALLOW_SPANNING_WRITE_SPLIT"])
        self.assertEqual(0, adapter["parameters"]["ALLOW_SPANNING_READ_ASSEMBLE"])

    def test_rejects_bad_width_and_missing_cpu_capability(self) -> None:
        bad_width = spec()
        bad_width["masters"][0]["data_width"] = 16
        missing = execution()
        del missing["routes"][0]["backend_contract"]["capabilities"]["max_outstanding"]
        for expected, candidate_spec, candidate_execution in (
            ("master-width-mismatch", bad_width, execution()),
            ("backend-contract:outstanding", spec(), missing),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(SocFabricError, expected):
                build_soc_fabric(candidate_spec, candidate_execution)

    def test_requires_explicit_physical_width_and_valid_identifiers(self) -> None:
        missing_width = spec()
        del missing_width["targets"][0]["data_width"]
        negative = spec()
        negative["targets"][0]["window"]["base"] = -4
        duplicate = spec()
        duplicate["targets"][1]["target_id"] = duplicate["targets"][0]["target_id"]
        bad_kind = spec()
        bad_kind["masters"][-1]["kind"] = "dma"
        for expected, candidate in (("target-width", missing_width), ("target-window", negative),
                                    ("duplicate-target-id", duplicate), ("master-kind", bad_kind)):
            with self.subTest(expected=expected), self.assertRaisesRegex(SocFabricError, expected):
                build_soc_fabric(candidate, execution())

    def test_window_capacity_tracks_actual_configured_count(self) -> None:
        many = spec()
        uart = many["targets"][0]
        many["targets"] = [copy.deepcopy(uart) for _ in range(9)]
        for index, target in enumerate(many["targets"]):
            target["target_id"] = f"uart{index}"
            target["window"] = {"base": 0x10000 + index * 0x100, "size": 0x100}
        plan = build_soc_fabric(many, execution())
        self.assertEqual(9, plan["rtl"]["parameters"]["MAX_WINDOWS"])

    def test_encodes_request_source_filter_in_window_masks(self) -> None:
        restricted = spec()
        restricted["targets"][0]["request_sources"] = ["data", "fuzz"]
        plan = build_soc_fabric(restricted, execution())
        uart = next(w for w in plan["decode"]["windows"] if w["window_id"] == "uart")
        self.assertEqual(0b110, uart["allowed_source_mask"])
        masks = [w["allowed_source_mask"] for w in plan["decode"]["windows"]]
        expected_packed = sum(mask << (index * 3) for index, mask in enumerate(masks))
        self.assertEqual(expected_packed, plan["rtl"]["parameters"]["WINDOW_SOURCE_MASK"])


if __name__ == "__main__":
    unittest.main()
