"""Legacy caller-supplied records cannot confirm component defects.

Use ``confirm_component_offline`` for fresh execution of supported artifacts.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import replace

from myfuzz.contracts import canonical_bytes

from .soc_failure_evidence import (
    COMPONENT_CANDIDATE, UNDIAGNOSED, EvidencePackage, classify_boundary,
)

COMPONENT_CONFIRMED = "component_confirmed"


def confirm_component_defect(
        package: EvidencePackage, *, isolation: Mapping[str, object],
        criterion: Mapping[str, object]) -> tuple[str, str]:
    """Preserve boundary findings without trusting caller assertions."""
    boundary, reason = classify_boundary(package)
    if boundary != COMPONENT_CANDIDATE:
        return boundary, reason
    return COMPONENT_CANDIDATE, "offline-verification-required"


def record_component_confirmation(
        package: EvidencePackage, *, isolation: Mapping[str, object],
        criterion: Mapping[str, object]) -> EvidencePackage:
    """Persist the nonconfirming legacy gate and supplied facts."""
    status, reason = confirm_component_defect(
        package, isolation=isolation, criterion=criterion)
    report: dict[str, object] = {
        "schema_version": "soc_defect_confirmation.v1",
        "status": status, "reason": reason,
        "criterion": dict(criterion), "isolation": dict(isolation),
    }
    report["report_hash"] = "sha256:" + hashlib.sha256(canonical_bytes(report)).hexdigest()
    return replace(package, attribution={**dict(package.attribution),
                                         "component_confirmation": report})


def validate_component_confirmation(package: EvidencePackage) -> tuple[str, str]:
    """Re-evaluate a saved record; this is not independent run verification."""
    report = package.attribution.get("component_confirmation")
    if not isinstance(report, Mapping):
        return UNDIAGNOSED, "confirmation-record-missing"
    payload = {key: value for key, value in report.items() if key != "report_hash"}
    expected_hash = "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
    if report.get("report_hash") != expected_hash:
        return UNDIAGNOSED, "confirmation-record-hash-mismatch"
    criterion = report.get("criterion")
    isolation = report.get("isolation")
    if not isinstance(criterion, Mapping) or not isinstance(isolation, Mapping):
        return UNDIAGNOSED, "confirmation-record-evidence-missing"
    status, reason = confirm_component_defect(
        package, isolation=isolation, criterion=criterion)
    if report.get("status") != status or report.get("reason") != reason:
        return UNDIAGNOSED, "confirmation-record-verdict-mismatch"
    return status, "record-integrity-only"


__all__ = ["COMPONENT_CONFIRMED", "confirm_component_defect",
           "record_component_confirmation", "validate_component_confirmation"]
