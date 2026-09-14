"""P6 integration must publish fabric facts through the public SoC planner."""
import unittest

from myfuzz.composition.soc_contracts import SocContractError, validate_soc_plan
from myfuzz.composition.soc_plan import build_soc_plan
from tests.composition.test_soc_contracts import (
    processor_execution_fixture, spec_fixture, target_contracts_fixture,
)


def connected_fixture():
    spec = spec_fixture()
    execution = processor_execution_fixture()
    contracts = target_contracts_fixture()
    for target in spec["targets"]:
        target["data_width"] = 32
    for route in execution["routes"]:
        route["parameters"]["READ_ONLY"] = int(route["function"] == "instruction_memory_master")
        route["backend_contract"] = {
            "mode": "single_outstanding_request_response",
            "protocol": ["processor-memory-beat", "1"],
            "capabilities": {"max_outstanding": 1, "max_wait_cycles": 32},
        }
    return spec, execution, contracts


class SocPlanFabricTests(unittest.TestCase):
    def test_public_plan_connects_cpu_and_fuzz_to_one_fabric(self):
        plan = build_soc_plan(*connected_fixture())
        fabric = plan["fabric"]
        self.assertEqual(2, len(plan["processor_execution"]["bindings"]))
        self.assertEqual({"cpu_ifetch", "cpu_data", "fuzz_mmio"},
                         {source["source_id"] for source in fabric["sources"]})
        uart = next(row for row in fabric["decode"]["windows"] if row["target_id"] == "uart0_win")
        self.assertFalse(uart["permissions"]["execute"])
        permitted = {source["source_id"] for source in fabric["sources"]
                     if uart["allowed_source_mask"] & (1 << source["index"])}
        self.assertEqual({"cpu_data", "fuzz_mmio"}, permitted)
        self.assertEqual(len(fabric["targets"]), len(fabric["downstream_adapters"]))
        self.assertTrue(all(item["role"] == "shared_fabric_to_target"
                            for item in fabric["downstream_adapters"]))
        self.assertEqual(
            sorted(net["net_id"] for net in plan["nets"] if net["kind"] == "master_ingress"),
            sorted(fabric["network"]["ingress_nets"]),
        )

    def test_public_plan_validation_rejects_fabric_permission_forgery(self):
        plan = build_soc_plan(*connected_fixture())
        uart = next(row for row in plan["fabric"]["decode"]["windows"]
                    if row["target_id"] == "uart0_win")
        uart["allowed_source_mask"] = 7
        with self.assertRaises(SocContractError):
            validate_soc_plan(plan)

    def test_public_plan_rejects_missing_cpu_backend_capability(self):
        spec, execution, contracts = connected_fixture()
        del execution["routes"][0]["backend_contract"]["capabilities"]
        with self.assertRaises(ValueError):
            build_soc_plan(spec, execution, contracts)

    def test_target_width_must_be_explicit_and_consistent(self):
        spec, execution, contracts = connected_fixture()
        target_id = spec["targets"][0]["target_id"]
        target = next(item for item in spec["targets"] if item["target_id"] == target_id)
        contract = next(item for item in contracts if item["target_id"] == target_id)
        del target["data_width"]
        del contract["capabilities"]["data_width"]
        with self.assertRaisesRegex(SocContractError, "missing-target-capability"):
            build_soc_plan(spec, execution, contracts)

        spec, execution, contracts = connected_fixture()
        contracts[0]["capabilities"]["data_width"] = 64
        with self.assertRaisesRegex(SocContractError, "target-contract-mismatch"):
            build_soc_plan(spec, execution, contracts)

    def test_public_plan_validation_rejects_packed_mask_forgery(self):
        plan = build_soc_plan(*connected_fixture())
        plan["fabric"]["rtl"]["parameters"]["WINDOW_SOURCE_MASK"] ^= 1
        with self.assertRaisesRegex(SocContractError, "fabric-parameter-mismatch"):
            validate_soc_plan(plan)

    def test_validation_rejects_translation_and_width_adapter_forgery(self):
        for mutate in (
            lambda fabric: fabric["rtl"]["parameters"].__setitem__("WINDOW_TARGET_BASE", 0),
            lambda fabric: fabric["decode"]["windows"][0].__setitem__("target_base", 123),
            lambda fabric: fabric["decode"]["windows"][0].__setitem__("target_index", 99),
            lambda fabric: fabric["targets"][0].__setitem__("backing_id", "forged"),
            lambda fabric: fabric["width_adapters"].append({"parameters": {"ALLOW_SPANNING_WRITE_SPLIT": 1}}),
        ):
            plan = build_soc_plan(*connected_fixture())
            mutate(plan["fabric"])
            with self.assertRaises(SocContractError):
                validate_soc_plan(plan)

    def test_spec_only_width_is_preserved_with_provenance(self):
        spec, execution, contracts = connected_fixture()
        for contract in contracts:
            contract["capabilities"].pop("data_width", None)
        plan = build_soc_plan(spec, execution, contracts)
        self.assertTrue(all(value["data_width_provenance"] == "soc_spec.targets"
                            for value in plan["target_capabilities"].values()))
        validate_soc_plan(plan)

    def test_validation_rejects_width_provenance_and_policy_copy_drift(self):
        plan = build_soc_plan(*connected_fixture())
        target = next(iter(plan["target_capabilities"].values()))
        target["data_width_provenance"] = "caller-says-trust-me"
        with self.assertRaisesRegex(SocContractError, "target-width-provenance-mismatch"):
            validate_soc_plan(plan)

        plan = build_soc_plan(*connected_fixture())
        plan["address_map"]["windows"][0]["width_conversion"] = {
            "spanning_write": "split_side_effect_free"
        }
        with self.assertRaisesRegex(SocContractError, "target-width-policy-mismatch"):
            validate_soc_plan(plan)

    def test_equal_width_target_still_rejects_invalid_conversion_policy(self):
        spec, execution, contracts = connected_fixture()
        spec["targets"][0]["width_conversion"] = {"spanning_write": "unsafe_split"}
        with self.assertRaisesRegex(SocContractError, "invalid-width-conversion"):
            build_soc_plan(spec, execution, contracts)

    def test_retained_width_capability_matches_original_capability_fact(self):
        plan = build_soc_plan(*connected_fixture())
        target = next(iter(plan["target_capabilities"].values()))
        self.assertEqual(32, target["capabilities"]["data_width"])
        target["capability_data_width"] = None
        with self.assertRaisesRegex(SocContractError, "target-capability-mismatch"):
            validate_soc_plan(plan)

    def test_shared_adapter_uses_only_normalized_beat_mapping(self):
        spec, execution, contracts = connected_fixture()
        for contract in contracts:
            contract.pop("adapter_module", None)
            contract["adapter_modules"] = {
                "obi@1": "wrong_cpu_side_module",
                "processor-memory-beat@1": "beat_shared_module",
            }
        plan = build_soc_plan(spec, execution, contracts)
        self.assertTrue(all(item["module"] == "beat_shared_module"
                            for item in plan["fabric"]["downstream_adapters"]))

        del contracts[0]["adapter_modules"]["processor-memory-beat@1"]
        with self.assertRaisesRegex(SocContractError, "missing.*adapter-module"):
            build_soc_plan(spec, execution, contracts)
