"""System-level compose-v5 contract discovery report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .contract_discovery_v5 import (
    CONTRACT_V5_DISCOVERY_SCHEMA,
    ContractV5DiscoveryResult,
    discover_contract_v5_module,
)
from .contract_v5 import (
    CONTRACT_V5_AMBIGUITY_SCHEMA,
    CONTRACT_V5_GRAMMAR_VERSION,
    ContractV5AmbiguityReport,
)
from .contracts.experiment import content_digest
from .frontend_v5 import FrontendV5Behavior, FrontendV5ModuleBehavior
from .input_model import InputValidationError
from .rtl_analysis import RTLAnalysis, RTLModule


CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA = "myfuzz.contract-system-discovery/v5"


@dataclass(frozen=True)
class ContractV5SystemDiscoveryReport:
    top_module: str
    manifest_digest: str
    frontend_schema: str
    module_reports: tuple[ContractV5DiscoveryResult, ...]
    missing_behavior_modules: tuple[str, ...]
    extra_behavior_modules: tuple[str, ...]
    binding_conflict_modules: tuple[str, ...]
    module_count: int
    matched_count: int
    unique_count: int
    ambiguous_count: int
    empty_count: int
    status: str
    digest: str
    schema: str = CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA
    grammar_version: str = CONTRACT_V5_GRAMMAR_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.top_module, str) or not self.top_module:
            raise InputValidationError("system discovery top_module must be a non-empty string")
        if not isinstance(self.manifest_digest, str) or len(self.manifest_digest) != 64:
            raise InputValidationError("system discovery manifest_digest must be a SHA-256 hex digest")
        if not isinstance(self.frontend_schema, str) or not self.frontend_schema:
            raise InputValidationError("system discovery frontend_schema must be a non-empty string")
        if not isinstance(self.module_reports, tuple):
            raise InputValidationError("system discovery module_reports must be a tuple")
        if not isinstance(self.missing_behavior_modules, tuple):
            raise InputValidationError("system discovery missing_behavior_modules must be a tuple")
        if not isinstance(self.extra_behavior_modules, tuple):
            raise InputValidationError("system discovery extra_behavior_modules must be a tuple")
        if not isinstance(self.binding_conflict_modules, tuple):
            raise InputValidationError("system discovery binding_conflict_modules must be a tuple")
        if self.status not in {"empty", "partial", "unique", "ambiguous"}:
            raise InputValidationError("system discovery status is invalid")
        if self.module_count != len(self.module_reports):
            raise InputValidationError("system discovery module_count mismatch")
        if self.unique_count != sum(item.ambiguity.status == "unique" for item in self.module_reports):
            raise InputValidationError("system discovery unique_count mismatch")
        if self.ambiguous_count != sum(item.ambiguity.status == "ambiguous" for item in self.module_reports):
            raise InputValidationError("system discovery ambiguous_count mismatch")
        if self.empty_count != sum(item.ambiguity.status == "empty" for item in self.module_reports):
            raise InputValidationError("system discovery empty_count mismatch")
        if self.matched_count > self.module_count:
            raise InputValidationError("system discovery matched_count is inconsistent")
        if self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("system discovery digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "grammar_version": self.grammar_version,
            "top_module": self.top_module,
            "manifest_digest": self.manifest_digest,
            "frontend_schema": self.frontend_schema,
            "module_reports": [item.to_dict() for item in self.module_reports],
            "missing_behavior_modules": list(self.missing_behavior_modules),
            "extra_behavior_modules": list(self.extra_behavior_modules),
            "binding_conflict_modules": list(self.binding_conflict_modules),
            "module_count": self.module_count,
            "matched_count": self.matched_count,
            "unique_count": self.unique_count,
            "ambiguous_count": self.ambiguous_count,
            "empty_count": self.empty_count,
            "status": self.status,
        }

    def to_dict(self) -> dict[str, object]:
        value = self.payload_dict()
        value["digest"] = self.digest
        return value


def discover_contract_v5_system(
    analysis: RTLAnalysis,
    behavior: FrontendV5Behavior,
) -> ContractV5SystemDiscoveryReport:
    if not isinstance(analysis, RTLAnalysis):
        raise InputValidationError("system discovery requires RTLAnalysis")
    if not isinstance(behavior, FrontendV5Behavior):
        raise InputValidationError("system discovery requires FrontendV5Behavior")

    behavior_modules = tuple(sorted(behavior.modules, key=_behavior_sort_key))
    analysis_modules = tuple(sorted(analysis.modules, key=_analysis_sort_key))
    consumed_behavior_ids: set[int] = set()
    module_reports: list[ContractV5DiscoveryResult] = []
    missing: list[str] = []
    conflicts: list[str] = []
    matched_count = 0

    for module in analysis_modules:
        candidates = _behavior_candidates(module, behavior_modules)
        if len(candidates) == 1:
            matched_count += 1
            consumed_behavior_ids.add(id(candidates[0]))
            module_reports.append(discover_contract_v5_module(module, candidates[0]))
            continue
        if not candidates:
            missing.append(module.name)
            module_reports.append(_empty_module_result(
                module,
                behavior_module_names=(),
                reason="no frontend behavior module matched the analyzed module",
            ))
            continue
        conflicts.append(module.name)
        consumed_behavior_ids.update(id(item) for item in candidates)
        module_reports.append(_empty_module_result(
            module,
            behavior_module_names=tuple(sorted(item.name for item in candidates)),
            reason="multiple frontend behavior modules matched the analyzed module",
        ))

    extras = tuple(
        item.name for item in behavior_modules
        if id(item) not in consumed_behavior_ids
    )
    unique_count = sum(item.ambiguity.status == "unique" for item in module_reports)
    ambiguous_count = sum(item.ambiguity.status == "ambiguous" for item in module_reports)
    empty_count = sum(item.ambiguity.status == "empty" for item in module_reports)
    if ambiguous_count or conflicts:
        status = "ambiguous"
    elif matched_count == 0:
        status = "empty"
    elif missing or extras or empty_count:
        status = "partial"
    else:
        status = "unique"

    payload = {
        "schema": CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "top_module": analysis.top_module,
        "manifest_digest": analysis.manifest_digest,
        "frontend_schema": behavior.schema,
        "module_reports": [item.to_dict() for item in module_reports],
        "missing_behavior_modules": list(sorted(missing)),
        "extra_behavior_modules": list(sorted(extras)),
        "binding_conflict_modules": list(sorted(conflicts)),
        "module_count": len(module_reports),
        "matched_count": matched_count,
        "unique_count": unique_count,
        "ambiguous_count": ambiguous_count,
        "empty_count": empty_count,
        "status": status,
    }
    return ContractV5SystemDiscoveryReport(
        top_module=analysis.top_module,
        manifest_digest=analysis.manifest_digest,
        frontend_schema=behavior.schema,
        module_reports=tuple(module_reports),
        missing_behavior_modules=tuple(sorted(missing)),
        extra_behavior_modules=tuple(sorted(extras)),
        binding_conflict_modules=tuple(sorted(conflicts)),
        module_count=len(module_reports),
        matched_count=matched_count,
        unique_count=unique_count,
        ambiguous_count=ambiguous_count,
        empty_count=empty_count,
        status=status,
        digest=content_digest(payload),
    )


def _empty_module_result(
    module: RTLModule,
    *,
    behavior_module_names: tuple[str, ...],
    reason: str,
) -> ContractV5DiscoveryResult:
    ambiguity = _empty_ambiguity(reason)
    evidence = {
        "frontend_module": None,
        "behavior_module_names": list(behavior_module_names),
        "reason": reason,
        "discovery_rule": (
            "edge sensitivity for clock/reset plus guarded opposite-direction one-bit "
            "port pair for request accept"
        ),
    }
    payload = {
        "schema": CONTRACT_V5_DISCOVERY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "module": module.name,
        "original_module": module.original_name,
        "hypotheses": [],
        "ambiguity": ambiguity.to_dict(),
        "rejected_reasons": [reason],
        "evidence": evidence,
    }
    return ContractV5DiscoveryResult(
        module=module.name,
        original_module=module.original_name,
        hypotheses=(),
        ambiguity=ambiguity,
        rejected_reasons=(reason,),
        evidence=evidence,
        digest=content_digest(payload),
    )


def _empty_ambiguity(reason: str) -> ContractV5AmbiguityReport:
    payload = {
        "schema": CONTRACT_V5_AMBIGUITY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "status": "empty",
        "surviving_count": 0,
        "canonical_class_count": 0,
        "canonical_digests": (),
        "selected_digest": None,
        "reason": reason,
    }
    return ContractV5AmbiguityReport(**payload, digest=content_digest(payload))


def _behavior_candidates(
    module: RTLModule,
    behaviors: tuple[FrontendV5ModuleBehavior, ...],
) -> tuple[FrontendV5ModuleBehavior, ...]:
    module_ids = {module.name, module.original_name}
    result = [
        behavior for behavior in behaviors
        if not module_ids.isdisjoint({behavior.name, behavior.original_name})
    ]
    return tuple(result)


def _analysis_sort_key(module: RTLModule) -> tuple[str, str]:
    return (module.name, module.original_name)


def _behavior_sort_key(module: FrontendV5ModuleBehavior) -> tuple[str, str]:
    return (module.name, module.original_name)
