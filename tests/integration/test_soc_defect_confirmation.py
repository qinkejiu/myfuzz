"""A component candidate is not confirmed without independent controls."""
from __future__ import annotations

import unittest
import hashlib
from dataclasses import replace

from myfuzz.composition.soc_defect_confirmation import (
    COMPONENT_CONFIRMED, confirm_component_defect, record_component_confirmation,
    validate_component_confirmation,
)
from myfuzz.composition.soc_failure_evidence import (
    COMPOSITION_DEFECT, COMPONENT_CANDIDATE, UNDIAGNOSED,
)
from tests.integration.test_soc_failure_evidence import _package


_NORM = "The CPU reaches the declared poll state within one cycle."
_ORIGINAL = "module p; assign result = input_value; endmodule"
_MUTANT = "module p; assign result = 1'b0; endmodule"
_CRITERION = {"criterion_id": "criterion-1",
              "specification_text": _NORM,
              "specification_hash": "sha256:" + hashlib.sha256(_NORM.encode()).hexdigest(),
              "independent_of_profile": True,
              "expected": 3, "observed": 2}
_ISOLATION = {"replay_status": "agreement",
              "baseline_status": "pass", "mutant_status": "fail",
              "isolated_status": "fail", "component_boundary_legal": True,
              "source_only_mutation": True,
              "baseline_input_hash": "sha256:" + "4" * 64,
              "mutant_input_hash": "sha256:" + "4" * 64,
              "baseline_environment_hash": "sha256:" + "5" * 64,
              "mutant_environment_hash": "sha256:" + "5" * 64,
              "structure_audit_status": "pass",
              "structure_audit_top_hash": "sha256:" + "f" * 64,
              "original_source_text": _ORIGINAL,
              "mutant_source_text": _MUTANT,
              "original_source_hash": "sha256:" + hashlib.sha256(_ORIGINAL.encode()).hexdigest(),
              "mutant_source_hash": "sha256:" + hashlib.sha256(_MUTANT.encode()).hexdigest()}


class DefectConfirmationTests(unittest.TestCase):
    def candidate(self):
        package = _package()
        identity = dict(package.identity)
        runtime = dict(identity["runtime"])
        runtime["source_hashes"] = {"isolated-mutant.sv":
                                    _ISOLATION["mutant_source_hash"]}
        identity["runtime"] = runtime
        return replace(package, identity=identity)

    def test_self_reported_evidence_never_confirms_candidate(self) -> None:
        status, reason = confirm_component_defect(
            self.candidate(), isolation=_ISOLATION, criterion=_CRITERION)
        self.assertEqual((COMPONENT_CANDIDATE, "offline-verification-required"),
                         (status, reason))
        recorded = record_component_confirmation(
            self.candidate(), isolation=_ISOLATION, criterion=_CRITERION)
        self.assertEqual(COMPONENT_CANDIDATE,
                         recorded.attribution["component_confirmation"]["status"])
        self.assertEqual(COMPONENT_CANDIDATE,
                         validate_component_confirmation(recorded)[0])
        self.assertEqual("record-integrity-only", validate_component_confirmation(recorded)[1])

    def test_tampered_confirmation_record_is_rejected(self) -> None:
        recorded = record_component_confirmation(
            self.candidate(), isolation=_ISOLATION, criterion=_CRITERION)
        report = dict(recorded.attribution["component_confirmation"])
        report["status"] = "composition_defect"
        corrupted = replace(recorded, attribution={
            **dict(recorded.attribution), "component_confirmation": report})
        self.assertEqual(UNDIAGNOSED,
                         validate_component_confirmation(corrupted)[0])

    def test_missing_independent_specification_blocks_confirmation(self) -> None:
        criterion = dict(_CRITERION, specification_hash="")
        status, reason = confirm_component_defect(
            self.candidate(), isolation=_ISOLATION, criterion=criterion)
        self.assertEqual(COMPONENT_CANDIDATE, status)
        self.assertEqual("offline-verification-required", reason)

    def test_missing_build_source_hash_blocks_confirmation(self) -> None:
        status, reason = confirm_component_defect(
            _package(), isolation=_ISOLATION, criterion=_CRITERION)
        self.assertEqual(COMPONENT_CANDIDATE, status)
        self.assertEqual("offline-verification-required", reason)

    def test_gate_does_not_read_caller_assertions(self) -> None:
        class Unreadable(dict):
            def get(self, *args):
                raise AssertionError("caller assertion was read")
        self.assertEqual(
            (COMPONENT_CANDIDATE, "offline-verification-required"),
            confirm_component_defect(self.candidate(), isolation=Unreadable(),
                                     criterion=Unreadable()))

    def test_offline_record_is_a_snapshot_and_integrity_only(self) -> None:
        import json
        from myfuzz.composition import soc_offline_defect_confirmation as offline
        self.assertTrue(hasattr(offline, "record_offline_confirmation"))
        self.assertTrue(hasattr(offline, "validate_offline_confirmation"))
        evidence = {"baseline_structure_audit": {"status": "pass"},
                    "mutant_replay": {"status": "agreement"},
                    "isolation": {"baseline": {"executable_hash": "sha256:abc"}},
                    "baseline": {"top_hash": "sha256:def"}}
        result = offline.OfflineConfirmation(COMPONENT_CONFIRMED,
                                            "offline-isolation-confirmed", evidence)
        package = offline.record_offline_confirmation(self.candidate(), result)
        report = package.attribution["offline_confirmation"]
        self.assertEqual(evidence, report["evidence"])
        self.assertEqual(COMPONENT_CONFIRMED, report["status"])
        evidence["mutant_replay"]["status"] = "changed"
        self.assertEqual("agreement", report["evidence"]["mutant_replay"]["status"])
        saved = replace(package, attribution=json.loads(json.dumps(package.attribution)))
        self.assertEqual((COMPONENT_CANDIDATE, "record-integrity-only"),
                         offline.validate_offline_confirmation(saved))
        saved.attribution["offline_confirmation"]["status"] = COMPOSITION_DEFECT
        self.assertEqual((UNDIAGNOSED, "confirmation-record-hash-mismatch"),
                         offline.validate_offline_confirmation(saved))
        from myfuzz.contracts import canonical_bytes
        forged = saved.attribution["offline_confirmation"]
        forged.pop("report_hash")
        forged["report_hash"] = "sha256:" + hashlib.sha256(canonical_bytes(forged)).hexdigest()
        self.assertEqual((COMPONENT_CANDIDATE, "record-integrity-only"),
                         offline.validate_offline_confirmation(saved))

    def test_old_confirmed_record_is_not_offline_proof(self) -> None:
        from myfuzz.contracts import canonical_bytes
        recorded = record_component_confirmation(
            self.candidate(), isolation=_ISOLATION, criterion=_CRITERION)
        report = dict(recorded.attribution["component_confirmation"])
        report.update(status=COMPONENT_CONFIRMED, reason="historical confirmation")
        report.pop("report_hash")
        report["report_hash"] = "sha256:" + hashlib.sha256(canonical_bytes(report)).hexdigest()
        saved = replace(recorded, attribution={"component_confirmation": report})
        self.assertNotEqual(COMPONENT_CONFIRMED, validate_component_confirmation(saved)[0])

    def test_missing_isolation_or_replay_blocks_confirmation(self) -> None:
        for change in ({"isolated_status": "not_reproduced"},
                       {"replay_status": "divergence"},
                       {"mutant_environment_hash": "sha256:" + "6" * 64},
                       {"structure_audit_status": "fail"},
                       {"structure_audit_top_hash": "sha256:" + "7" * 64},
                       {"source_only_mutation": False}):
            with self.subTest(change=change):
                status, _ = confirm_component_defect(
                    self.candidate(), isolation=dict(_ISOLATION, **change),
                    criterion=_CRITERION)
                self.assertEqual(COMPONENT_CANDIDATE, status)

    def test_known_connection_finding_retains_composition_class(self) -> None:
        package = _package(attribution={"composition_findings": ["wrong IRQ latch bit"]})
        status, _ = confirm_component_defect(
            package, isolation=_ISOLATION, criterion=_CRITERION)
        self.assertEqual(COMPOSITION_DEFECT, status)

    def test_missing_package_identity_remains_undiagnosed(self) -> None:
        package = _package(identity={})
        status, _ = confirm_component_defect(
            package, isolation=_ISOLATION, criterion=_CRITERION)
        self.assertEqual(UNDIAGNOSED, status)


if __name__ == "__main__":
    unittest.main()
