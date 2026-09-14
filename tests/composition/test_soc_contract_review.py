"""Regression tests for the P3 contract-review findings."""
from __future__ import annotations

import copy
import unittest

from myfuzz.composition.soc_contracts import SocContractError, soc_spec_hash, validate_soc_plan, validate_soc_spec
from myfuzz.composition.soc_plan import build_soc_plan
from tests.composition.test_soc_contracts import (
    processor_execution_fixture,
    spec_fixture,
    target_contracts_fixture,
)


class ContractReviewTests(unittest.TestCase):
    def build(self, spec=None, execution=None):
        return build_soc_plan(
            spec_fixture() if spec is None else spec,
            processor_execution_fixture() if execution is None else execution,
            target_contracts_fixture(),
        )

    def assert_rejected(self, reason, operation):
        with self.assertRaises(SocContractError) as raised:
            operation()
        self.assertTrue(str(raised.exception).startswith(reason), str(raised.exception))

    def test_response_is_driven_by_target_and_routed_to_accepted_source(self):
        plan = self.build()
        uart = next(net for net in plan["nets"] if net["net_id"] == "target:uart0_win")
        self.assertEqual(uart["response_driver"], {"role": "target", "target_id": "uart0_win"})
        self.assertEqual(uart["response_routing"], "accepted_source")
        window = next(w for w in plan["address_map"]["windows"] if w["target_id"] == "uart0_win")
        self.assertEqual(window["response_routing"], "accepted_source")
        self.assertNotIn("response_owner", window)

    def test_cpu_boundary_rejects_missing_ambiguous_and_incompatible_routes(self):
        execution = processor_execution_fixture()
        execution["routes"] = execution["routes"][:1]
        self.assert_rejected("missing-cpu-route", lambda: self.build(execution=execution))

        execution = processor_execution_fixture()
        execution["routes"].append(copy.deepcopy(execution["routes"][1]))
        execution["routes"][-1]["route_id"] = 99
        self.assert_rejected("ambiguous-cpu-route", lambda: self.build(execution=execution))

        execution = processor_execution_fixture()
        execution["routes"][0]["source_protocol"] = ["axi4", "1"]
        self.assert_rejected("cpu-route-mismatch", lambda: self.build(execution=execution))

        execution = processor_execution_fixture()
        execution["routes"][0]["widths"]["data"] = 64
        self.assert_rejected("cpu-route-mismatch", lambda: self.build(execution=execution))

    def test_source_lock_membership_is_mandatory(self):
        spec = spec_fixture()
        del spec["source_locks"]
        self.assert_rejected("missing-source-locks", lambda: validate_soc_spec(spec))

    def test_ordered_parameter_array_changes_hash(self):
        baseline = spec_fixture()
        baseline["components"][0]["instances"][0]["parameters"]["LANE_MAP"] = [0, 1]
        swapped = copy.deepcopy(baseline)
        swapped["components"][0]["instances"][0]["parameters"]["LANE_MAP"] = [1, 0]
        self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(swapped))

    def test_opaque_named_arrays_are_never_treated_as_schema_collections(self):
        for key in ("routes", "components", "rules", "sinks"):
            with self.subTest(key=key):
                baseline = spec_fixture()
                baseline["components"][0]["instances"][0]["parameters"][key] = [0, 1]
                swapped = copy.deepcopy(baseline)
                swapped["components"][0]["instances"][0]["parameters"][key] = [1, 0]
                self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(swapped))

    def test_source_lock_component_records_are_unordered_but_their_payload_arrays_are_ordered(self):
        baseline = spec_fixture()
        baseline["source_locks"] = {
            "components": [
                {"id": lock_id, "files": [f"{lock_id}/a.sv", f"{lock_id}/b.sv"]}
                for lock_id in baseline["source_locks"]
            ]
        }
        reordered = copy.deepcopy(baseline)
        reordered["source_locks"]["components"].reverse()
        self.assertEqual(soc_spec_hash(baseline), soc_spec_hash(reordered))

        payload_reordered = copy.deepcopy(baseline)
        payload_reordered["source_locks"]["components"][0]["files"].reverse()
        self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(payload_reordered))

    def test_cpu_reset_sinks_only_cpu_instances_even_on_shared_domain(self):
        spec = spec_fixture()
        spec["components"][3]["reset_domain"] = "cpu_rst"
        plan = self.build(spec=spec)
        self.assertEqual(plan["reset"]["cpu_reset"]["sinks"], ["cpu0"])
        cpu_distribution = [d["sink"] for d in plan["reset"]["distribution"] if d["role"] == "cpu"]
        self.assertEqual(cpu_distribution, ["cpu0"])

    def test_plan_rejects_ghosts_incomplete_capabilities_and_driver_drift(self):
        plan = self.build()
        plan["adapters"][0]["target_id"] = "ghost"
        self.assert_rejected("unknown-plan-target", lambda: validate_soc_plan(plan))

        plan = self.build()
        del plan["target_capabilities"]["uart0_win"]
        self.assert_rejected("target-capability-mismatch", lambda: validate_soc_plan(plan))

        plan = self.build()
        plan["net_drivers"][0]["driver"] = {"role": "ghost"}
        self.assert_rejected("net-driver-mismatch", lambda: validate_soc_plan(plan))

    def test_plan_requires_truthful_response_driver_and_routing_metadata(self):
        for collection, select in (
            ("nets", lambda plan: next(n for n in plan["nets"] if n["kind"] == "target_request")),
            ("windows", lambda plan: plan["address_map"]["windows"][0]),
        ):
            for field in ("response_driver", "response_routing"):
                with self.subTest(collection=collection, field=field):
                    plan = self.build()
                    del select(plan)[field]
                    self.assert_rejected("missing-field", lambda plan=plan: validate_soc_plan(plan))

            plan = self.build()
            select(plan)["response_driver"] = {"role": "target", "target_id": "ghost"}
            self.assert_rejected("response-driver-mismatch", lambda: validate_soc_plan(plan))

            plan = self.build()
            select(plan)["response_routing"] = "fixed_requester"
            self.assert_rejected("response-routing-mismatch", lambda: validate_soc_plan(plan))

    def test_target_request_nets_are_a_bijection_with_address_windows(self):
        plan = self.build()
        uart = next(n for n in plan["nets"] if n["net_id"] == "target:uart0_win")
        uart["sink"]["target_id"] = "ram0_win"
        uart["response_driver"]["target_id"] = "ram0_win"
        self.assert_rejected("target-net-mismatch", lambda: validate_soc_plan(plan))

        plan = self.build()
        plan["nets"] = [n for n in plan["nets"] if n["net_id"] != "target:uart0_win"]
        plan["net_drivers"] = [n for n in plan["net_drivers"] if n["net_id"] != "target:uart0_win"]
        self.assert_rejected("target-net-mismatch", lambda: validate_soc_plan(plan))

        mutations = (
            ("net_id", "target:ghost"),
            ("component_id", "ram"),
            ("port", "wrong"),
            ("request_sources", ["cpu_data"]),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                plan = self.build()
                uart = next(n for n in plan["nets"] if n["net_id"] == "target:uart0_win")
                if field in ("component_id", "port"):
                    uart["sink"][field] = value
                else:
                    uart[field] = value
                if field == "net_id":
                    next(n for n in plan["net_drivers"] if n["net_id"] == "target:uart0_win")["net_id"] = value
                self.assert_rejected("target-net-mismatch", lambda plan=plan: validate_soc_plan(plan))

    def test_external_lock_ids_cannot_replace_embedded_lock_membership(self):
        spec = spec_fixture()
        del spec["source_locks"]
        self.assert_rejected(
            "missing-source-locks",
            lambda: validate_soc_spec(spec, source_lock_ids=list({c["source_lock"] for c in spec["components"]})),
        )

        spec = spec_fixture()
        self.assert_rejected(
            "unknown-source-lock",
            lambda: validate_soc_spec(spec, source_lock_ids=["ibex"]),
        )


if __name__ == "__main__":
    unittest.main()
