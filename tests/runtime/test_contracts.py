"""G1: closed data contracts, strict parsing and detached documentary copies.

These tests are software-only.  A passing contract test proves a shape, never a
source admission, a native token or an executed effect.
"""
from __future__ import annotations

import copy
import dataclasses
from hashlib import sha256
import json
import unittest

from myfuzz.runtime.adapters.contracts import (
    PreparedTargetOperation,
    ProviderProgress,
    TargetRequest,
    operation_id_for,
    request_digest,
)
from myfuzz.runtime.contracts import (
    AdapterSelection,
    CapabilityRequirement,
    GenericExecutionPlan,
    GenericRuntimeRefused,
    ProcessLocalIssuance,
    VerifiedComponent,
    canonical_json_bytes,
    parse_closed_json,
    strict_json_loads,
)
from myfuzz.runtime.evidence.contracts import EvidenceRef, parse_evidence_ref
from myfuzz.runtime.semantics.contracts import SemanticContract, validate_semantic_document
from myfuzz.scenario.ledger import TransactionKey

KEY = TransactionKey("exec-1", "case-1", "processor", 0, "processor.data", 1)


def plan_document(**overrides) -> dict:
    document = {
        "schema_version": "generic_execution_plan.v1",
        "components": [],
        "selections": [],
        "paths": [],
        "sources": [],
        "constraints": [],
        "seeds": [],
        "assertions": [],
        "memory": {},
        "scheduling": {},
        "termination": {},
        "evidence_obligations": [],
        "input_digests": {"d2": "1" * 64, "d3": "2" * 64},
    }
    document.update(overrides)
    return document


def endpoint_document(**overrides) -> dict:
    document = {
        "endpoint_id": "timer.bus",
        "role": "target",
        "protocol": ["apb", "3"],
        "template": ["target.apb3", "1", "full-word"],
        "semantic_kind": "storage.rw.v1",
        "operations": ["read", "write"],
        "data_width": 32,
        "address_width": 12,
        "address_units": "byte",
        "max_outstanding": 1,
        "completion_kind": "response",
        "byte_enable": True,
        "evidence_capabilities": [
            "component_semantic_effect",
            "cross_component_source",
            "physical_protocol_sample",
        ],
    }
    document.update(overrides)
    return document


def descriptor_document(**overrides) -> dict:
    document = {
        "schema_version": "verified_component_descriptor.v1",
        "instance_id": "peripheral",
        "source_sha256": "a" * 64,
        "profile_sha256": "b" * 64,
        "artifact_sha256": "c" * 64,
        "semantic_contract_sha256": "d" * 64,
        "source_verifier": {
            "id": "apb.storage.source.v1",
            "version": "1",
            "implementation_sha256": "e" * 64,
        },
        "endpoints": [endpoint_document()],
    }
    document.update(overrides)
    return document


def verified_component(*, instance_id: str = "peripheral", **overrides) -> VerifiedComponent:
    descriptor = descriptor_document(instance_id=instance_id, **overrides)
    frozen = canonical_json_bytes(descriptor)
    return VerifiedComponent(
        instance_id,
        descriptor["source_sha256"],
        descriptor["profile_sha256"],
        descriptor["artifact_sha256"],
        descriptor["semantic_contract_sha256"],
        frozen,
    )


def semantic_document(**overrides) -> dict:
    document = {
        "schema_version": "semantic_contract.v1",
        "kind": "storage.rw.v1",
        "source": {
            "contract_id": "pulp-apb-timer.ctrl0.source.v1",
            "root": "third_party/soc-pulp-apb-timer",
            "revision": "git:03eba2e6965f5363df12621882bc70498c551a73",
            "top_module": "apb_timer",
            "files": {"src/timer.sv": "f" * 64},
            "verifier": {
                "id": "apb.storage.source.v1",
                "version": "1",
                "implementation_sha256": "e" * 64,
            },
            "identity_basis": "exact_reviewed_bytes_not_native_verified",
        },
        "endpoint": {
            "endpoint_id": "timer.bus",
            "role": "target",
            "protocol": ["apb", "3"],
            "template": ["target.apb3", "1", "full-word"],
            "semantic_kind": "storage.rw.v1",
        },
        "decode": {
            "address_width": 12,
            "address_units": "byte",
            "alignment_bytes": 4,
            "mask": 0x1C,
            "value": 4,
            "alias_period_bytes": 32,
            "expression": "PADDR[4:2] == 3'b001",
        },
        "operations": [
            {
                "operation": "read",
                "width_bits": 32,
                "read_mask": 0xFFFFFFFF,
                "write_mask": 0,
                "byte_enable": True,
                "value_origin": "target_register_read",
            },
            {
                "operation": "write",
                "width_bits": 32,
                "read_mask": 0xFFFFFFFF,
                "write_mask": 0xFFFFFFFF,
                "byte_enable": True,
                "value_origin": "cpu_transaction_wdata",
            },
        ],
        "reset": {
            "declared": True,
            "port": "HRESETn",
            "polarity": "active_low",
            "observed": False,
            "evidence_ref": None,
            "case_begin_is_reset": False,
        },
        "side_effects": [
            {"kind": "stable_storage", "scope": "TIMER0_CTRL selected storage"}
        ],
        "observations": [
            {
                "name": "storage_probes",
                "layer": "component_semantic_effect",
                "native": True,
                "reference": "generated_expression_source_mapped",
            }
        ],
        "issuer_contract": {
            "issuer_id": "ApbStorageRegisterVersionAuthority",
            "version": "1",
            "implementation_sha256": "9" * 64,
            "token_scope": "existing_gpio_process_local_single_use",
            "single_use": True,
            "authority": False,
        },
    }
    document.update(overrides)
    return document


def requirement(**overrides) -> CapabilityRequirement:
    document = {
        "role": "target",
        "endpoint_id": "timer.bus",
        "protocol": ("apb", "3"),
        "template": ("target.apb3", "1", "full-word"),
        "semantic_kind": "storage.rw.v1",
        "operations": ("read", "write"),
        "data_width": 32,
        "address_width": 12,
        "max_outstanding": 1,
        "completion_kind": "response",
        "byte_enable_required": True,
        "address_units": "byte",
        "evidence_obligations": ("component_semantic_effect",
                                 "physical_protocol_sample"),
    }
    document.update(overrides)
    return CapabilityRequirement(**document)


class FrozenPlanTests(unittest.TestCase):
    def test_frozen_plan_is_detached_from_callers(self):
        from hashlib import sha256
        from myfuzz.runtime.contracts import GenericExecutionPlan
        import json
        raw = {
            "schema_version": "generic_execution_plan.v1",
            "components": [], "selections": [], "paths": [], "sources": [],
            "constraints": [], "seeds": [], "assertions": [], "memory": {},
            "scheduling": {}, "termination": {}, "evidence_obligations": [],
            "input_digests": {"d2": "1" * 64, "d3": "2" * 64},
        }
        frozen = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        plan = GenericExecutionPlan("generic_execution_plan.v1", frozen, sha256(frozen).hexdigest())
        raw["input_digests"]["d2"] = "3" * 64
        assert json.loads(plan.document_bytes)["input_digests"]["d2"] == "1" * 64

    def test_same_input_same_canonical_bytes(self):
        first = plan_document(memory={"regions": [{"id": "ram", "base": 65536}],
                                      "seed": 0})
        reordered = {key: first[key] for key in reversed(list(first))}
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(reordered))
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(copy.deepcopy(first)))

    def test_freeze_does_not_track_caller_mutation(self):
        raw = plan_document(memory={"regions": [{"id": "ram"}]})
        plan = GenericExecutionPlan.freeze(raw)
        raw["memory"]["regions"].append({"id": "second"})
        raw["paths"].append({"path_id": "F4:ram.image", "flow_id": "F4"})
        self.assertEqual([], plan.document()["paths"])
        self.assertEqual(1, len(plan.document()["memory"]["regions"]))
        self.assertEqual(sha256(plan.document_bytes).hexdigest(), plan.identity_sha256)

    def test_plan_identity_must_match_bytes(self):
        frozen = canonical_json_bytes(plan_document())
        with self.assertRaises(GenericRuntimeRefused) as caught:
            GenericExecutionPlan("generic_execution_plan.v1", frozen, "0" * 64)
        self.assertEqual("generic-contract-mismatch", caught.exception.code)
        self.assertEqual("/identity_sha256", caught.exception.pointer)

    def test_plan_bytes_must_be_canonical(self):
        document = plan_document()
        pretty = json.dumps(document, sort_keys=True, indent=2).encode()
        with self.assertRaises(GenericRuntimeRefused) as caught:
            GenericExecutionPlan("generic_execution_plan.v1", pretty,
                                 sha256(pretty).hexdigest())
        self.assertEqual("generic-contract-shape", caught.exception.code)

    def test_plan_duplicate_obligations_rejected(self):
        document = plan_document(evidence_obligations=[
            "physical_protocol_sample", "physical_protocol_sample"])
        with self.assertRaises(GenericRuntimeRefused) as caught:
            GenericExecutionPlan.freeze(document)
        self.assertEqual("generic-contract-shape", caught.exception.code)
        self.assertEqual("/plan/evidence_obligations", caught.exception.pointer)

    def test_plan_duplicate_list_items_rejected(self):
        row = {"path_id": "F4:ram.image", "flow_id": "F4"}
        with self.assertRaises(GenericRuntimeRefused) as caught:
            GenericExecutionPlan.freeze(plan_document(paths=[row, copy.deepcopy(row)]))
        self.assertEqual("generic-contract-duplicate", caught.exception.code)
        self.assertEqual("/paths", caught.exception.pointer)

    def test_plan_rejects_bool_digest_and_extra_field(self):
        document = plan_document(input_digests={"d2": True, "d3": "2" * 64})
        with self.assertRaises(GenericRuntimeRefused):
            GenericExecutionPlan.freeze(document)
        document = plan_document(extra_field=1)
        with self.assertRaises(GenericRuntimeRefused) as caught:
            GenericExecutionPlan.freeze(document)
        self.assertEqual("/plan/extra_field", caught.exception.pointer)

    def test_plan_document_non_object_root_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            GenericExecutionPlan.freeze(["not", "an", "object"])


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_json_key_rejected(self):
        raw = b'{"a": 1, "a": 2}'
        with self.assertRaises(GenericRuntimeRefused) as caught:
            strict_json_loads(raw)
        self.assertEqual("generic-contract-json-duplicate-key", caught.exception.code)
        self.assertEqual({"key": "a"}, caught.exception.detail)

    def test_nan_and_infinity_rejected(self):
        for text in (b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}'):
            with self.assertRaises(GenericRuntimeRefused) as caught:
                strict_json_loads(text)
            self.assertEqual("generic-contract-json", caught.exception.code)

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            strict_json_loads(b"\xff\xfe{}")

    def test_closed_shape_missing_and_extra(self):
        with self.assertRaises(GenericRuntimeRefused) as caught:
            parse_closed_json({"a": 1}, ("a", "b"))
        self.assertEqual("/b", caught.exception.pointer)
        with self.assertRaises(GenericRuntimeRefused) as caught:
            parse_closed_json({"a": 1, "c": 2}, ("a",))
        self.assertEqual("/c", caught.exception.pointer)
        with self.assertRaises(GenericRuntimeRefused):
            parse_closed_json([1], ("a",))


class CapabilityRequirementTests(unittest.TestCase):
    def test_valid_requirement_is_detached_and_digestable(self):
        value = requirement()
        document = value.document()
        document["operations"].append("write")
        self.assertEqual(("read", "write"), value.operations)
        self.assertEqual(
            requirement().sha256(), CapabilityRequirement(**{
                "role": value.role, "endpoint_id": value.endpoint_id,
                "protocol": value.protocol, "template": value.template,
                "semantic_kind": value.semantic_kind,
                "operations": value.operations,
                "data_width": value.data_width,
                "address_width": value.address_width,
                "max_outstanding": value.max_outstanding,
                "completion_kind": value.completion_kind,
                "byte_enable_required": value.byte_enable_required,
                "address_units": value.address_units,
                "evidence_obligations": value.evidence_obligations,
            }).sha256())

    def test_bool_is_not_int(self):
        for name in ("data_width", "address_width", "max_outstanding"):
            with self.assertRaises(GenericRuntimeRefused) as caught:
                requirement(**{name: True})
            self.assertEqual("generic-contract-type", caught.exception.code)

    def test_unknown_role_protocol_shape_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            requirement(role="peripheral")
        with self.assertRaises(GenericRuntimeRefused):
            requirement(protocol=("apb",))
        with self.assertRaises(GenericRuntimeRefused):
            requirement(template=("target.apb3", "1"))
        with self.assertRaises(GenericRuntimeRefused):
            requirement(address_units="beat")

    def test_list_container_and_duplicates_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            requirement(operations=["read", "write"])
        with self.assertRaises(GenericRuntimeRefused):
            requirement(evidence_obligations=("physical_protocol_sample",
                                              "physical_protocol_sample"))
        with self.assertRaises(GenericRuntimeRefused):
            requirement(operations=("write", "read"))

    def test_unknown_operation_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            requirement(operations=("read", "erase"))

    def test_overwide_values_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            requirement(data_width=8192)
        with self.assertRaises(GenericRuntimeRefused):
            requirement(address_width=65)
        with self.assertRaises(GenericRuntimeRefused):
            requirement(max_outstanding=0)


class VerifiedComponentTests(unittest.TestCase):
    def test_descriptor_shape_and_digest_are_enforced(self):
        component = verified_component()
        self.assertEqual("peripheral", component.instance_id)
        self.assertEqual(64, len(component.descriptor_sha256()))
        self.assertEqual(1, len(component.endpoints()))

    def test_sha_mismatch_between_fields_and_descriptor_rejected(self):
        descriptor = descriptor_document()
        frozen = canonical_json_bytes(descriptor)
        with self.assertRaises(GenericRuntimeRefused) as caught:
            VerifiedComponent("peripheral", "0" * 64, descriptor["profile_sha256"],
                              descriptor["artifact_sha256"],
                              descriptor["semantic_contract_sha256"], frozen)
        self.assertEqual("generic-contract-mismatch", caught.exception.code)
        self.assertEqual("/descriptor/source_sha256", caught.exception.pointer)

    def test_instance_rename_changes_descriptor_identity(self):
        first = verified_component()
        second = verified_component(instance_id="renamed-peripheral")
        self.assertNotEqual(first.descriptor_sha256(), second.descriptor_sha256())
        self.assertEqual("renamed-peripheral", second.instance_id)

    def test_descriptor_bool_width_duplicate_endpoint_and_extra_field(self):
        cases = (
            {"endpoints": [endpoint_document(data_width=True)]},
            {"endpoints": [endpoint_document(), endpoint_document()]},
            {"source_verifier": {"id": "x", "version": "1",
                                 "implementation_sha256": "e" * 64,
                                 "extra": 1}},
            {"endpoints": [endpoint_document(operations=["write", "read"])]},
            {"endpoints": [endpoint_document(byte_enable="yes")]},
            {"unexpected": True},
        )
        for overrides in cases:
            with self.assertRaises(GenericRuntimeRefused):
                verified_component(**overrides)

    def test_descriptor_round_trip_does_not_create_membership(self):
        component = verified_component()
        rebuilt = dataclasses.replace(component)
        issuance = ProcessLocalIssuance("verified-components")
        issuance.issue(component, snapshot=component.descriptor_bytes)
        self.assertTrue(issuance.holds(component))
        self.assertFalse(issuance.holds(rebuilt))
        with self.assertRaises(GenericRuntimeRefused) as caught:
            issuance.require(rebuilt)
        self.assertEqual("generic-binding-drift", caught.exception.code)
        self.assertEqual("not-issued-by-this-process",
                         caught.exception.detail["reason"])


class IssuanceTests(unittest.TestCase):
    def test_live_handle_cannot_be_reconstructed_from_fields(self):
        issuance = ProcessLocalIssuance("prepared-target-operations")
        handle = PreparedTargetOperation(KEY, "1" * 64, "2" * 64, "3" * 64, "4" * 64)
        issuance.issue(handle, snapshot=b"{}")
        self.assertTrue(issuance.holds(handle))
        clone = PreparedTargetOperation(KEY, "1" * 64, "2" * 64, "3" * 64, "4" * 64)
        self.assertEqual(handle, clone)
        self.assertFalse(issuance.holds(clone))
        snapshot = json.loads(issuance.snapshot(handle))
        self.assertEqual({}, snapshot)
        with self.assertRaises(GenericRuntimeRefused):
            issuance.issue(handle, snapshot="{not bytes}")

    def test_close_revokes_every_live_handle(self):
        issuance = ProcessLocalIssuance("prepared-target-operations")
        handle = PreparedTargetOperation(KEY, "1" * 64, "2" * 64, "3" * 64, "4" * 64)
        issuance.issue(handle, snapshot=b"{}")
        issuance.close()
        self.assertTrue(issuance.closed)
        self.assertFalse(issuance.holds(handle))
        self.assertEqual(0, len(issuance))


class AdapterSelectionTests(unittest.TestCase):
    def test_selection_validates_digests(self):
        selection = AdapterSelection("apb3.storage.v1", "1", "1" * 64, "2" * 64,
                                     "3" * 64)
        self.assertEqual("apb3.storage.v1", selection.document()["adapter_id"])
        for args in (("apb3.storage.v1", "1", "1" * 64, "2" * 64, "3" * 63),
                     ("apb3.storage.v1", "1", "XYZ", "2" * 64, "3" * 64),
                     ("", "1", "1" * 64, "2" * 64, "3" * 64)):
            with self.assertRaises(GenericRuntimeRefused):
                AdapterSelection(*args)


class TargetContractTests(unittest.TestCase):
    def test_read_request_requires_no_write_data(self):
        source_ref = EvidenceRef("processor", 7, "mmio_delivery")
        request = TargetRequest("F2:ram.image", source_ref, 0x40000004, "read",
                                None, 0xF, 4)
        self.assertEqual(64, len(request_digest(request)))
        with self.assertRaises(GenericRuntimeRefused):
            TargetRequest("F2:ram.image", source_ref, 0x40000004, "read", 1, 0xF, 4)
        with self.assertRaises(GenericRuntimeRefused):
            TargetRequest("F2:ram.image", source_ref, 0x40000004, "read", None, 0x1, 4)
        with self.assertRaises(GenericRuntimeRefused):
            TargetRequest("F2:ram.image", source_ref, 0x40000004, "write", None, 0xF, 4)
        with self.assertRaises(GenericRuntimeRefused):
            TargetRequest("F2:ram.image", source_ref, True, "read", None, 0xF, 4)
        with self.assertRaises(GenericRuntimeRefused):
            TargetRequest("F2:ram.image", source_ref, 0x40000004, "read", None, 0xF, 3)
        with self.assertRaises(GenericRuntimeRefused):
            TargetRequest("F2:ram.image", source_ref, 0x40000004, "read", None, 0x0, 4)
        request = TargetRequest("F2:ram.image", source_ref, 0x40000004, "write",
                                0xDEADBEEF, 0xF, 4)
        rebuilt = TargetRequest.from_document(request.document())
        self.assertEqual(request.canonical_bytes(), rebuilt.canonical_bytes())

    def test_operation_identity_is_over_complete_key(self):
        first = operation_id_for(key=KEY, request_sha256="1" * 64,
                                 route_sha256="2" * 64, binding_sha256="3" * 64)
        other_key = TransactionKey("exec-2", "case-1", "processor", 0,
                                   "processor.data", 1)
        second = operation_id_for(key=other_key, request_sha256="1" * 64,
                                  route_sha256="2" * 64, binding_sha256="3" * 64)
        self.assertNotEqual(first, second)

    def test_progress_shape_is_closed(self):
        ref = EvidenceRef("peripheral", 3, "apb_storage_probe")
        progress = ProviderProgress(KEY, "completed", 5, b"\x00\x00\x00\x01",
                                    (ref,), None)
        self.assertEqual("completed", progress.status)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "done", 5, b"\x00\x00\x00\x01", (ref,), None)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "completed", True, b"\x00\x00\x00\x01", (ref,), None)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "completed", 5, None, (ref,), None)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "pending", 5, b"\x00\x00\x00\x01", (ref,), None)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "pending", 5, None, (ref, ref), None)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "pending", -1, None, (ref,), None)
        with self.assertRaises(GenericRuntimeRefused):
            ProviderProgress(KEY, "pending", 0, None, [], None)


class SemanticContractTests(unittest.TestCase):
    def test_valid_storage_contract_is_canonical_and_detached(self):
        raw = semantic_document()
        contract = SemanticContract.freeze(raw)
        self.assertEqual(("read", "write"), contract.operations())
        self.assertEqual(("stable_storage",), contract.side_effect_kinds())
        self.assertEqual(("storage_probes",), contract.observation_names())
        raw["decode"]["mask"] = 0
        self.assertEqual(0x1C, contract.document()["decode"]["mask"])
        again = SemanticContract.freeze(copy.deepcopy(contract.document()))
        self.assertEqual(contract.sha256_hex, again.sha256_hex)

    def test_missing_side_effects_is_not_storage(self):
        with self.assertRaises(GenericRuntimeRefused) as caught:
            validate_semantic_document(semantic_document(side_effects=[]))
        self.assertEqual("generic-contract-shape", caught.exception.code)

    def test_w1c_or_fifo_cannot_pose_as_storage(self):
        for kind in ("w1c", "fifo_push"):
            with self.assertRaises(GenericRuntimeRefused):
                validate_semantic_document(semantic_document(
                    side_effects=[{"kind": "stable_storage", "scope": "x"},
                                  {"kind": kind, "scope": "x"}]))
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(semantic_document(
                side_effects=[{"kind": "w1c", "scope": "x"}]))

    def test_kind_and_endpoint_semantic_must_agree(self):
        document = semantic_document(kind="fifo.push.v1")
        with self.assertRaises(GenericRuntimeRefused) as caught:
            validate_semantic_document(document)
        self.assertEqual("generic-contract-mismatch", caught.exception.code)
        self.assertEqual("/semantic/endpoint/semantic_kind", caught.exception.pointer)

    def test_static_contract_never_carries_authority(self):
        document = semantic_document()
        document["issuer_contract"]["authority"] = True
        with self.assertRaises(GenericRuntimeRefused) as caught:
            validate_semantic_document(document)
        self.assertEqual("/semantic/issuer_contract/authority",
                         caught.exception.pointer)

    def test_case_begin_cannot_pose_as_reset(self):
        document = semantic_document()
        document["reset"]["case_begin_is_reset"] = True
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)
        document = semantic_document()
        document["reset"]["observed"] = True
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)

    def test_operations_and_decode_mismatches_rejected(self):
        document = semantic_document()
        document["operations"][0]["write_mask"] = 0xFFFFFFFF
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)
        document = semantic_document()
        document["operations"] = document["operations"][:1]
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)
        document = semantic_document()
        document["decode"]["alignment_bytes"] = 0
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)

    def test_issuer_digest_and_source_digest_required(self):
        document = semantic_document()
        document["issuer_contract"]["implementation_sha256"] = "9" * 63
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)
        document = semantic_document()
        document["source"]["files"]["src/timer.sv"] = "xyz"
        with self.assertRaises(GenericRuntimeRefused):
            validate_semantic_document(document)


class RefusalTests(unittest.TestCase):
    def test_refusal_is_typed_value_error_with_pointer(self):
        refusal = GenericRuntimeRefused("generic-source-unverified",
                                        "/components/0/source",
                                        {"reason": "sha-mismatch"})
        self.assertIsInstance(refusal, ValueError)
        self.assertEqual("generic-source-unverified", refusal.code)
        self.assertEqual("/components/0/source", refusal.pointer)
        self.assertEqual({"code": "generic-source-unverified",
                          "pointer": "/components/0/source",
                          "detail": {"reason": "sha-mismatch"}},
                         refusal.document())
        self.assertIn("generic-source-unverified at /components/0/source",
                      str(refusal))

    def test_evidence_ref_bool_event_id_rejected(self):
        with self.assertRaises(GenericRuntimeRefused):
            EvidenceRef("processor", True, "mmio_delivery")
        with self.assertRaises(GenericRuntimeRefused):
            parse_evidence_ref({"component": "processor", "event_id": 1,
                                "kind": "x", "extra": 1})
        parsed = parse_evidence_ref({"component": "processor", "event_id": 1,
                                     "kind": "x"})
        self.assertEqual(1, parsed.event_id)


if __name__ == "__main__":
    unittest.main()
