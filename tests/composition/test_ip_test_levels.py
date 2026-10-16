from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.composition.ip_test_levels import (
    MinimumCapabilityLevelError,
    RuntimeCapabilitySnapshot,
    VerifiedCapabilitySnapshot,
    assess_ip_test_level,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "examples" / "soc_generation" / "profiles" / "novauart.json"


def profile_document(*, register_map: bool = False, protocol: tuple[str, str] = ("apb", "4")):
    document = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    document["component_id"] = "anonymous_peripheral"
    document["endpoints"][0]["protocol"] = list(protocol)
    if register_map:
        document["address"]["registers"] = [{
            "name": "CTRL", "offset": 0, "width": 32, "access": "rw",
            "side_effect": "none", "reset_value": 0, "writable_bits": 1,
        }]
    else:
        document["address"]["registers"] = []
    return document


def sidecar_document(profile, *, with_register_semantics: bool = False,
                     operations: dict[str, list[str]] | None = None):
    operations = operations or {"uart.pins": ["sample"]}
    register_semantics = []
    if with_register_semantics:
        register_semantics = [{
            "register": "CTRL", "field": "enable", "lsb": 0, "width": 1,
            "access": "rw", "read_mask": 1, "write_mask": 1,
            "reset_value": 0, "side_effect": "none",
            "evidence_ref": "rtl:anonymous.ctrl.enable",
        }]
    return {
        "schema_version": "ip_test_capability.v1",
        "component_id": profile.component_id,
        "profile_fingerprint": profile.profile_fingerprint,
        "endpoint_capabilities": [
            {"endpoint_id": endpoint_id, "operations": operation_list}
            for endpoint_id, operation_list in operations.items()
        ],
        "register_semantics": register_semantics,
        "observation_mappings": [],
    }


def feature_sidecar_document(profile, *, include_register_semantics: bool = True):
    document = sidecar_document(profile, with_register_semantics=include_register_semantics)
    document["schema_version"] = "ip_test_capability.v2"
    document["observation_mappings"] = [{
        "mapping_id": "uart-tx-change", "endpoint_id": "uart.pins",
        "role": "tx", "observation_kind": "signal_change",
        "evidence_ref": "rtl:anonymous.tx",
    }]
    document["feature_contract"] = {
        "provider_id": "example.sha",
        "provider_version": "1.0",
        "operations": [{
            "endpoint_id": "uart.bus", "operation": "completion",
            "required_observation_mappings": ["uart-tx-change"],
            "evidence_ref": "plugin-manifest:sha256:abc123",
        }],
    }
    return document


def runtime(profile, *, protocols=(("apb", "4"),), endpoint_operations=None,
            sidecar=None, observation_mappings=()):
    return RuntimeCapabilitySnapshot.from_mapping(
        profile,
        supported_protocols=protocols,
        endpoint_operations=endpoint_operations or {
            "uart.bus": ("request", "accept", "response"),
        },
        sidecar=sidecar,
        observation_mappings=observation_mappings,
    )


class IPTestLevelAssessmentTests(unittest.TestCase):
    def test_anonymous_profile_can_run_l1_without_register_map_or_function_plugin(self):
        profile = load_component_profile(profile_document())
        preflight = runtime(profile)

        assessment = assess_ip_test_level(
            profile, runtime_support=preflight, requested_minimum_level="L1")

        self.assertEqual("L1", assessment.declared_level)
        self.assertEqual("L1", assessment.effective_level)
        self.assertIsNone(assessment.verified_level)
        self.assertEqual("L1", assessment.requested_minimum_level)
        self.assertTrue(assessment.minimum_level_met)
        assessment.require_minimum()

    def test_sidecar_and_profile_declarations_never_promote_to_effective_without_preflight(self):
        profile = load_component_profile(profile_document(register_map=True))
        sidecar = load_ip_test_capability(
            sidecar_document(profile, with_register_semantics=True), profile=profile)

        assessment = assess_ip_test_level(profile, sidecar=sidecar)

        self.assertEqual("L2", assessment.declared_level)
        self.assertIsNone(assessment.effective_level)
        self.assertIsNone(assessment.verified_level)
        self.assertIn("runtime-preflight-not-supplied", assessment.gaps)
        self.assertTrue(all(not row.effective for row in assessment.support_matrix))

    def test_checked_register_semantics_add_l2_when_runtime_supports_field_access(self):
        profile = load_component_profile(profile_document(register_map=True))
        sidecar = load_ip_test_capability(
            sidecar_document(profile, with_register_semantics=True), profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response",
                         ("register_read", "CTRL.enable"),
                         ("register_write", "CTRL.enable")),
        })

        assessment = assess_ip_test_level(profile, sidecar=sidecar,
                                          runtime_support=preflight)

        self.assertEqual("L2", assessment.declared_level)
        self.assertEqual("L2", assessment.effective_level)
        self.assertIsNone(assessment.verified_level)
        self.assertTrue(assessment.operation("uart.bus", "register_read",
                                              "CTRL.enable").effective)
        self.assertTrue(assessment.operation("uart.bus", "register_write",
                                              "CTRL.enable").effective)
        self.assertIn("level-3-plugin-contract-not-declared", assessment.gaps)

    def test_missing_l2_runtime_operation_preserves_sibling_operation_and_refuses_l2(self):
        profile = load_component_profile(profile_document(register_map=True))
        sidecar = load_ip_test_capability(
            sidecar_document(profile, with_register_semantics=True), profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response",
                         ("register_read", "CTRL.enable")),
        })

        assessment = assess_ip_test_level(
            profile, sidecar=sidecar, runtime_support=preflight,
            requested_minimum_level="L2")

        self.assertEqual("L2", assessment.declared_level)
        self.assertEqual("L1", assessment.effective_level)
        self.assertEqual("L2", assessment.requested_minimum_level)
        self.assertFalse(assessment.minimum_level_met)
        self.assertTrue(assessment.operation("uart.bus", "register_read",
                                              "CTRL.enable").effective)
        self.assertFalse(assessment.operation("uart.bus", "register_write",
                                               "CTRL.enable").effective)
        self.assertIn("runtime-operation-unavailable:uart.bus:register_write:CTRL.enable",
                      assessment.gaps)
        with self.assertRaisesRegex(MinimumCapabilityLevelError,
                                    "requested-minimum-not-met:L2:L1"):
            assessment.require_minimum()

    def test_partial_endpoint_support_does_not_erase_supported_bus_operations(self):
        profile = load_component_profile(profile_document())
        sidecar = load_ip_test_capability(
            sidecar_document(profile, operations={"uart.pins": ["sample"]}),
            profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response"),
            "uart.pins": ("drive",),
        })

        assessment = assess_ip_test_level(profile, sidecar=sidecar,
                                          runtime_support=preflight)

        bus_request = assessment.operation("uart.bus", "request")
        pin_sample = assessment.operation("uart.pins", "sample")
        self.assertTrue(bus_request.declared)
        self.assertTrue(bus_request.effective)
        self.assertTrue(pin_sample.declared)
        self.assertFalse(pin_sample.effective)
        self.assertIn("runtime-operation-unavailable:uart.pins:sample", pin_sample.gaps)
        undeclared_drive = assessment.operation("uart.pins", "drive")
        self.assertFalse(undeclared_drive.declared)
        self.assertFalse(undeclared_drive.effective)
        self.assertIn("operation-not-declared", undeclared_drive.gaps)
        self.assertEqual("L1", assessment.effective_level)

    def test_missing_required_protocol_endpoint_blocks_level_but_keeps_other_rows(self):
        profile = load_component_profile(profile_document())
        extra_endpoint = replace(profile.endpoints[0], endpoint_id="uart.backup_bus")
        profile = replace(profile, endpoints=profile.endpoints + (extra_endpoint,))
        preflight = runtime(profile)

        assessment = assess_ip_test_level(profile, runtime_support=preflight)

        self.assertTrue(assessment.operation("uart.bus", "request").effective)
        self.assertFalse(assessment.operation("uart.backup_bus", "request").effective)
        self.assertIsNone(assessment.effective_level)
        self.assertIn("runtime-operation-unavailable:uart.backup_bus:request",
                      assessment.gaps)

    def test_unknown_protocol_cannot_become_effective_from_operation_names_alone(self):
        profile = load_component_profile(profile_document(protocol=("private_bus", "9")))
        preflight = runtime(
            profile, protocols=(),
            endpoint_operations={"uart.bus": ("request", "accept", "response")})

        assessment = assess_ip_test_level(profile, runtime_support=preflight)

        self.assertEqual("L1", assessment.declared_level)
        self.assertIsNone(assessment.effective_level)
        self.assertIn("unsupported-protocol:private_bus@9", assessment.gaps)
        with self.assertRaises(MinimumCapabilityLevelError):
            assess_ip_test_level(profile, runtime_support=preflight,
                                 requested_minimum_level="L1").require_minimum()

    def test_verified_level_requires_bound_verifier_evidence_for_effective_operations(self):
        profile = load_component_profile(profile_document())
        preflight = runtime(profile)
        verified = VerifiedCapabilitySnapshot.from_mapping(
            profile,
            operations={
                ("uart.bus", "request"): ("trace:case-1:request",),
                ("uart.bus", "accept"): ("trace:case-1:accept",),
                ("uart.bus", "response"): ("trace:case-1:response",),
            },
        )

        assessment = assess_ip_test_level(
            profile, runtime_support=preflight, verification=verified)

        self.assertEqual("L1", assessment.verified_level)
        self.assertTrue(assessment.operation("uart.bus", "request").verified)
        self.assertEqual(("trace:case-1:request",),
                         assessment.operation("uart.bus", "request").evidence_refs)
        self.assertEqual(assessment.to_document()["effective_level"], "L1")

    def test_partial_verification_is_reported_as_insufficient_for_complete_level(self):
        profile = load_component_profile(profile_document())
        preflight = runtime(profile)
        verified = VerifiedCapabilitySnapshot.from_mapping(
            profile,
            operations={
                ("uart.bus", "request"): ("trace:case-1:request",),
            },
        )

        assessment = assess_ip_test_level(
            profile, runtime_support=preflight, verification=verified)

        self.assertIsNone(assessment.verified_level)
        self.assertTrue(assessment.operation("uart.bus", "request").verified)
        self.assertIn("verified-operations-insufficient-for-complete-level",
                      assessment.gaps)
        self.assertNotIn("no-effective-operations-verified", assessment.gaps)

    def test_operation_names_cannot_claim_l3_without_a_feature_plugin_contract(self):
        profile = load_component_profile(profile_document())
        sidecar = load_ip_test_capability(
            sidecar_document(profile, operations={"uart.bus": ["retire"]}),
            profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response", "retire", "completion"),
        })

        assessment = assess_ip_test_level(profile, sidecar=sidecar,
                                          runtime_support=preflight)

        self.assertEqual("L1", assessment.declared_level)
        self.assertEqual("L1", assessment.effective_level)
        self.assertNotEqual("L3", assessment.declared_level)
        self.assertNotEqual("L3", assessment.effective_level)
        self.assertIn("level-3-plugin-contract-not-declared", assessment.gaps)
        completion = assessment.operation("uart.bus", "completion")
        self.assertEqual("L3", completion.level)
        self.assertFalse(completion.declared)
        self.assertFalse(completion.effective)
        self.assertIn("operation-not-declared", completion.gaps)

    def test_register_names_do_not_infer_functional_completion(self):
        document = profile_document(register_map=True)
        document["address"]["registers"][0]["name"] = "DONE"
        profile = load_component_profile(document)
        capability_document = sidecar_document(profile)
        capability_document["register_semantics"] = [{
            "register": "DONE", "field": "ready", "lsb": 0, "width": 1,
            "access": "rw", "read_mask": 1, "write_mask": 1,
            "side_effect": "none", "evidence_ref": "rtl:anonymous.done.ready",
        }]
        sidecar = load_ip_test_capability(capability_document, profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response", "completion",
                         ("register_read", "DONE.ready"),
                         ("register_write", "DONE.ready")),
        })

        assessment = assess_ip_test_level(profile, sidecar=sidecar,
                                          runtime_support=preflight)

        self.assertEqual(("L2", "L2"),
                         (assessment.declared_level, assessment.effective_level))
        self.assertTrue(assessment.operation("uart.bus", "register_read",
                                             "DONE.ready").effective)
        completion = assessment.operation("uart.bus", "completion")
        self.assertFalse(completion.declared)
        self.assertFalse(completion.effective)
        self.assertIn("level-3-plugin-contract-not-declared", assessment.gaps)

    def test_l3_requires_l2_contract_feature_operation_and_runtime_observations(self):
        profile = load_component_profile(profile_document(register_map=True))
        sidecar = load_ip_test_capability(feature_sidecar_document(profile), profile=profile)
        endpoint_operations = {
            "uart.bus": (
                "request", "accept", "response", "completion",
                ("register_read", "CTRL.enable"),
                ("register_write", "CTRL.enable"),
            ),
        }
        without_mapping = runtime(profile, sidecar=sidecar,
                                  endpoint_operations=endpoint_operations)

        incomplete = assess_ip_test_level(
            profile, sidecar=sidecar, runtime_support=without_mapping,
            requested_minimum_level="L3")

        self.assertEqual(("L3", "L2"),
                         (incomplete.declared_level, incomplete.effective_level))
        completion = incomplete.operation("uart.bus", "completion")
        self.assertTrue(completion.declared)
        self.assertFalse(completion.effective)
        self.assertIn("runtime-observation-mapping-unavailable:uart-tx-change",
                      completion.gaps)
        with self.assertRaises(MinimumCapabilityLevelError):
            incomplete.require_minimum()

        complete_runtime = runtime(
            profile, sidecar=sidecar, endpoint_operations=endpoint_operations,
            observation_mappings=("uart-tx-change",))
        verification = VerifiedCapabilitySnapshot.from_mapping(
            profile, sidecar=sidecar, operations={
                ("uart.bus", "request"): ("trace:case-1:request",),
                ("uart.bus", "accept"): ("trace:case-1:accept",),
                ("uart.bus", "response"): ("trace:case-1:response",),
                ("uart.bus", "completion"): ("trace:case-1:completion",),
                ("uart.bus", "register_read", "CTRL.enable"):
                    ("trace:case-1:register-read",),
                ("uart.bus", "register_write", "CTRL.enable"):
                    ("trace:case-1:register-write",),
            })
        complete = assess_ip_test_level(
            profile, sidecar=sidecar, runtime_support=complete_runtime,
            verification=verification, requested_minimum_level="L3")

        self.assertEqual(("L3", "L3", "L3"),
                         (complete.declared_level, complete.effective_level,
                          complete.verified_level))
        self.assertTrue(complete.minimum_level_met)

    def test_l3_feature_contract_cannot_skip_the_l2_register_level(self):
        profile = load_component_profile(profile_document(register_map=False))
        sidecar = load_ip_test_capability(
            feature_sidecar_document(profile, include_register_semantics=False),
            profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response", "completion"),
        }, observation_mappings=("uart-tx-change",))

        assessment = assess_ip_test_level(profile, sidecar=sidecar,
                                          runtime_support=preflight)

        self.assertEqual("L1", assessment.declared_level)
        self.assertEqual("L1", assessment.effective_level)
        self.assertIn("level-3-requires-level-2-contract", assessment.gaps)

    def test_verifier_cannot_promote_an_operation_the_runtime_did_not_enable(self):
        profile = load_component_profile(profile_document())
        preflight = runtime(profile)
        verified = VerifiedCapabilitySnapshot.from_mapping(
            profile,
            operations={
                ("uart.bus", "read"): ("trace:case-1:read",),
            },
        )

        with self.assertRaisesRegex(ValueError,
                                    "verification-exceeds-effective-capability:uart.bus:read"):
            assess_ip_test_level(profile, runtime_support=preflight,
                                 verification=verified)

    def test_runtime_and_verification_snapshots_are_bound_to_profile_identity(self):
        profile = load_component_profile(profile_document())
        altered = copy.deepcopy(profile_document())
        altered["description"] = "different contract identity"
        other_profile = load_component_profile(altered)
        stale_runtime = runtime(profile)
        stale_verification = VerifiedCapabilitySnapshot.from_mapping(
            profile, operations={})

        with self.assertRaisesRegex(ValueError, "runtime-capability-profile-mismatch"):
            assess_ip_test_level(other_profile, runtime_support=stale_runtime)
        with self.assertRaisesRegex(ValueError, "verification-profile-mismatch"):
            assess_ip_test_level(other_profile, verification=stale_verification)

    def test_generic_bus_read_write_evidence_cannot_be_relabelled_as_l2(self):
        profile = load_component_profile(profile_document(register_map=True))
        sidecar = load_ip_test_capability(
            sidecar_document(profile, with_register_semantics=True), profile=profile)
        preflight = runtime(profile, sidecar=sidecar, endpoint_operations={
            "uart.bus": ("request", "accept", "response", "read", "write"),
        })
        verification = VerifiedCapabilitySnapshot.from_mapping(
            profile,
            sidecar=sidecar,
            operations={
                ("uart.bus", "request"): ("trace:case-1:request",),
                ("uart.bus", "accept"): ("trace:case-1:accept",),
                ("uart.bus", "response"): ("trace:case-1:response",),
                ("uart.bus", "read"): ("trace:case-1:read",),
                ("uart.bus", "write"): ("trace:case-1:write",),
            },
        )

        assessment = assess_ip_test_level(
            profile, sidecar=sidecar, runtime_support=preflight,
            verification=verification, requested_minimum_level="L2")

        self.assertEqual(("L2", "L1", "L1"),
                         (assessment.declared_level, assessment.effective_level,
                          assessment.verified_level))
        self.assertFalse(assessment.minimum_level_met)
        self.assertTrue(assessment.operation("uart.bus", "read").verified)
        self.assertFalse(assessment.operation("uart.bus", "register_read",
                                              "CTRL.enable").effective)
        with self.assertRaises(MinimumCapabilityLevelError):
            assessment.require_minimum()

    def test_runtime_snapshot_is_bound_to_the_exact_sidecar(self):
        profile = load_component_profile(profile_document(register_map=True))
        sidecar = load_ip_test_capability(
            sidecar_document(profile, with_register_semantics=True), profile=profile)
        changed_document = sidecar_document(profile, with_register_semantics=True)
        changed_document["register_semantics"][0]["evidence_ref"] = "rtl:other-evidence"
        changed_sidecar = load_ip_test_capability(changed_document, profile=profile)
        self.assertNotEqual(sidecar.sidecar_fingerprint, changed_sidecar.sidecar_fingerprint)
        preflight = runtime(profile, sidecar=sidecar)

        with self.assertRaisesRegex(ValueError, "runtime-capability-sidecar-mismatch"):
            assess_ip_test_level(profile, sidecar=changed_sidecar,
                                 runtime_support=preflight)

        verification = VerifiedCapabilitySnapshot.from_mapping(
            profile, sidecar=sidecar, operations={})
        with self.assertRaisesRegex(ValueError, "verification-sidecar-mismatch"):
            assess_ip_test_level(profile, sidecar=changed_sidecar,
                                 verification=verification)

    def test_replaced_sidecar_typed_semantics_cannot_reuse_original_fingerprint(self):
        profile = load_component_profile(profile_document(register_map=True))
        original = load_ip_test_capability(
            sidecar_document(profile, with_register_semantics=True), profile=profile)
        changed_document = sidecar_document(profile, with_register_semantics=True)
        changed_document["register_semantics"][0]["width"] = 2
        changed_document["register_semantics"][0]["read_mask"] = 3
        changed = load_ip_test_capability(changed_document, profile=profile)
        forged = replace(original, register_semantics=changed.register_semantics)
        preflight = runtime(profile, sidecar=original, endpoint_operations={
            "uart.bus": ("request", "accept", "response",
                         ("register_read", "CTRL.enable"),
                         ("register_write", "CTRL.enable")),
        })
        verification = VerifiedCapabilitySnapshot.from_mapping(
            profile, sidecar=original, operations={
                ("uart.bus", "request"): ("trace:case-1:request",),
                ("uart.bus", "accept"): ("trace:case-1:accept",),
                ("uart.bus", "response"): ("trace:case-1:response",),
                ("uart.bus", "register_read", "CTRL.enable"):
                    ("trace:case-1:register-read",),
                ("uart.bus", "register_write", "CTRL.enable"):
                    ("trace:case-1:register-write",),
            })

        with self.assertRaisesRegex(ValueError,
                                    "test-capability-typed-contract-mismatch"):
            assess_ip_test_level(profile, sidecar=forged,
                                 runtime_support=preflight, verification=verification,
                                 requested_minimum_level="L2")

    def test_empty_runtime_operation_group_still_rejects_unknown_endpoint(self):
        profile = load_component_profile(profile_document())

        with self.assertRaisesRegex(ValueError,
                                    "runtime-capability-unknown-endpoint:never.existed"):
            RuntimeCapabilitySnapshot.from_mapping(
                profile, supported_protocols=(),
                endpoint_operations={"never.existed": ()})


if __name__ == "__main__":
    unittest.main()
