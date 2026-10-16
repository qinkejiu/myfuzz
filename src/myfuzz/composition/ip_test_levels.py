"""Resolve declared, executable and evidence-verified IP test levels.

Declarations remain descriptive.  A profile and its optional sidecar can only
raise ``declared_level``; effective operations must also appear in a
profile-bound runtime preflight snapshot, and verified operations must appear
in a profile-bound verifier snapshot with evidence references.

L3 operations can be declared only by the v2 feature contract, which binds each
operation to its provider identity and required observation mappings.  Runtime
preflight must confirm those mappings are available before L3 is executable.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re

from .component_profile import ComponentProfile
from .test_capability import (
    IP_TEST_CAPABILITY_SCHEMA,
    IP_TEST_CAPABILITY_SCHEMA_V2,
    IP_TEST_CAPABILITY_SCHEMA_V3,
    IP_TEST_OPERATIONS,
    IPTestCapability,
    IPTestCapabilityError,
    _revalidate_ip_test_capability,
)


IP_TEST_LEVEL_ASSESSMENT_SCHEMA = "ip_test_level_assessment.v1"
_LEVELS = ("L1", "L2", "L3")
_PROFILE_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REGISTER_OPERATIONS = frozenset(("register_read", "register_write"))
_FEATURE_OPERATIONS = frozenset(("transfer", "interrupt", "state_transition", "completion"))
_OPERATIONS = IP_TEST_OPERATIONS | _REGISTER_OPERATIONS | _FEATURE_OPERATIONS
_REGISTER_FIELD_SCOPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\Z")
_OBSERVATION_MAPPING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_PROTOCOL_CORE_OPERATIONS = frozenset(("request", "accept", "response"))


class CapabilityAssessmentError(ValueError):
    """A runtime or verifier capability snapshot is malformed or stale."""


class MinimumCapabilityLevelError(ValueError):
    """The requested minimum test level is not executable at preflight."""

    def __init__(self, assessment: "IPTestLevelAssessment") -> None:
        self.assessment = assessment
        actual = assessment.effective_level or "none"
        super().__init__(
            f"requested-minimum-not-met:{assessment.requested_minimum_level}:{actual}"
        )


@dataclass(frozen=True, slots=True)
class OperationClaim:
    endpoint_id: str
    operation: str
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeCapabilitySnapshot:
    """Trusted preflight output, bound to one exact component profile.

    Runtime code creates this snapshot after resolving actual executors and
    protocol adapters.  It is not a profile/sidecar input.  ``endpoint_operations``
    records the operations the runtime can execute for each endpoint;
    ``supported_protocols`` records the exact protocol/version pairs admitted
    by that runtime.
    """

    component_id: str
    profile_fingerprint: str
    supported_protocols: tuple[tuple[str, str], ...]
    endpoint_operations: tuple[OperationClaim, ...]
    sidecar_fingerprint: str | None = None
    observation_mappings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_snapshot_identity(self.component_id, self.profile_fingerprint,
                                    "runtime-capability")
        _validate_optional_sidecar_fingerprint(self.sidecar_fingerprint,
                                               "runtime-capability")
        protocols = _normalize_protocols(self.supported_protocols)
        claims = tuple(self.endpoint_operations)
        normalized_claims = _operation_claims_from_records(claims, "runtime")
        mappings = _normalize_observation_mapping_ids(self.observation_mappings, "runtime")
        object.__setattr__(self, "supported_protocols", protocols)
        object.__setattr__(self, "endpoint_operations", normalized_claims)
        object.__setattr__(self, "observation_mappings", mappings)

    @classmethod
    def from_mapping(
        cls,
        profile: ComponentProfile,
        *,
        supported_protocols: Iterable[tuple[str, str]],
        endpoint_operations: Mapping[str, Iterable[str | tuple[str, str]]],
        sidecar: IPTestCapability | None = None,
        observation_mappings: Iterable[str] = (),
    ) -> "RuntimeCapabilitySnapshot":
        _require_profile(profile)
        sidecar = _sidecar_for_profile(profile, sidecar)
        protocols = _normalize_protocols(supported_protocols)
        operations = _operation_claims(endpoint_operations)
        mappings = _normalize_observation_mapping_ids(observation_mappings, "runtime")
        endpoint_ids = {endpoint.endpoint_id for endpoint in profile.endpoints}
        unknown_endpoints = sorted(set(endpoint_operations) - endpoint_ids)
        if unknown_endpoints:
            raise CapabilityAssessmentError(
                f"runtime-capability-unknown-endpoint:{unknown_endpoints[0]}"
            )
        return cls(profile.component_id, profile.profile_fingerprint, protocols, operations,
                   sidecar.sidecar_fingerprint if sidecar is not None else None, mappings)


@dataclass(frozen=True, slots=True)
class VerifiedOperation:
    endpoint_id: str
    operation: str
    evidence_refs: tuple[str, ...]
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedCapabilitySnapshot:
    """Verifier output for operations backed by concrete execution evidence."""

    component_id: str
    profile_fingerprint: str
    operations: tuple[VerifiedOperation, ...]
    sidecar_fingerprint: str | None = None

    def __post_init__(self) -> None:
        _validate_snapshot_identity(self.component_id, self.profile_fingerprint,
                                    "verification")
        _validate_optional_sidecar_fingerprint(self.sidecar_fingerprint,
                                               "verification")
        normalized: list[VerifiedOperation] = []
        for item in tuple(self.operations):
            if not isinstance(item, VerifiedOperation):
                raise CapabilityAssessmentError("invalid-verification-operation")
            if not isinstance(item.endpoint_id, str) or not item.endpoint_id:
                raise CapabilityAssessmentError("invalid-verification-endpoint-id")
            operation = _require_operation(item.operation, "verification")
            scope = _normalize_operation_scope(item.operation, item.scope, "verification")
            refs = _normalize_evidence_refs(item.evidence_refs)
            normalized.append(VerifiedOperation(item.endpoint_id, operation, refs, scope))
        keys = [(item.endpoint_id, item.operation, item.scope) for item in normalized]
        if len(set(keys)) != len(keys):
            raise CapabilityAssessmentError("duplicate-verification-operation")
        normalized.sort(key=lambda item: (item.endpoint_id, item.operation,
                                          item.scope or ""))
        object.__setattr__(self, "operations", tuple(normalized))

    @classmethod
    def from_mapping(
        cls,
        profile: ComponentProfile,
        *,
        operations: Mapping[tuple[str, str] | tuple[str, str, str], Iterable[str]],
        sidecar: IPTestCapability | None = None,
    ) -> "VerifiedCapabilitySnapshot":
        _require_profile(profile)
        sidecar = _sidecar_for_profile(profile, sidecar)
        if not isinstance(operations, Mapping):
            raise CapabilityAssessmentError("invalid-verification-operations")
        endpoint_ids = {endpoint.endpoint_id for endpoint in profile.endpoints}
        verified: list[VerifiedOperation] = []
        for key, refs in operations.items():
            if (not isinstance(key, tuple) or len(key) not in (2, 3)
                    or any(not isinstance(part, str) or not part for part in key)):
                raise CapabilityAssessmentError("invalid-verification-operation-key")
            endpoint_id, operation = key[:2]
            scope = key[2] if len(key) == 3 else None
            if endpoint_id not in endpoint_ids:
                raise CapabilityAssessmentError(
                    f"verification-unknown-endpoint:{endpoint_id}"
                )
            _require_operation(operation, "verification")
            scope = _normalize_operation_scope(operation, scope, "verification")
            evidence_refs = _normalize_evidence_refs(refs)
            verified.append(VerifiedOperation(endpoint_id, operation, evidence_refs, scope))
        verified.sort(key=lambda item: (item.endpoint_id, item.operation, item.scope or ""))
        return cls(profile.component_id, profile.profile_fingerprint, tuple(verified),
                   sidecar.sidecar_fingerprint if sidecar is not None else None)


@dataclass(frozen=True, slots=True)
class EndpointOperationSupport:
    endpoint_id: str
    operation: str
    level: str
    declared: bool
    effective: bool
    verified: bool
    scope: str | None = None
    gaps: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IPTestLevelAssessment:
    schema_version: str
    component_id: str
    profile_fingerprint: str
    sidecar_fingerprint: str | None
    declared_level: str | None
    effective_level: str | None
    verified_level: str | None
    requested_minimum_level: str | None
    minimum_level_met: bool | None
    support_matrix: tuple[EndpointOperationSupport, ...]
    gaps: tuple[str, ...]

    def operation(self, endpoint_id: str, operation: str,
                  scope: str | None = None) -> EndpointOperationSupport:
        for row in self.support_matrix:
            if (row.endpoint_id, row.operation, row.scope) == (endpoint_id, operation, scope):
                return row
        raise KeyError((endpoint_id, operation, scope))

    def require_minimum(self) -> None:
        """Refuse startup when the caller's requested minimum is not met."""
        if self.minimum_level_met is False:
            raise MinimumCapabilityLevelError(self)

    def to_document(self) -> dict[str, object]:
        """Return the stable, JSON-compatible assessment contract."""
        return {
            "schema_version": self.schema_version,
            "component_id": self.component_id,
            "profile_fingerprint": self.profile_fingerprint,
            "sidecar_fingerprint": self.sidecar_fingerprint,
            "declared_level": self.declared_level,
            "effective_level": self.effective_level,
            "verified_level": self.verified_level,
            "requested_minimum_level": self.requested_minimum_level,
            "minimum_level_met": self.minimum_level_met,
            "support_matrix": [
                {
                    "endpoint_id": row.endpoint_id,
                    "operation": row.operation,
                    "scope": row.scope,
                    "level": row.level,
                    "declared": row.declared,
                    "effective": row.effective,
                    "verified": row.verified,
                    "gaps": list(row.gaps),
                    "evidence_refs": list(row.evidence_refs),
                }
                for row in self.support_matrix
            ],
            "gaps": list(self.gaps),
        }


def _require_profile(profile: object) -> ComponentProfile:
    if not isinstance(profile, ComponentProfile):
        raise CapabilityAssessmentError("component-profile-required")
    return profile


def _validate_snapshot_identity(component_id: object, fingerprint: object,
                                label: str) -> None:
    if not isinstance(component_id, str) or not component_id:
        raise CapabilityAssessmentError(f"invalid-{label}-component")
    if not isinstance(fingerprint, str) or _PROFILE_FINGERPRINT.fullmatch(fingerprint) is None:
        raise CapabilityAssessmentError(f"invalid-{label}-profile-fingerprint")


def _validate_optional_sidecar_fingerprint(fingerprint: object, label: str) -> None:
    if (fingerprint is not None
            and (not isinstance(fingerprint, str)
                 or _PROFILE_FINGERPRINT.fullmatch(fingerprint) is None)):
        raise CapabilityAssessmentError(f"invalid-{label}-sidecar-fingerprint")


def _require_operation(operation: object, label: str) -> str:
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise CapabilityAssessmentError(f"invalid-{label}-operation:{operation}")
    return operation


def _normalize_operation_scope(operation: str, scope: object,
                               label: str) -> str | None:
    if operation in _REGISTER_OPERATIONS:
        if not isinstance(scope, str) or _REGISTER_FIELD_SCOPE.fullmatch(scope) is None:
            raise CapabilityAssessmentError(f"{label}-register-field-scope-required")
        return scope
    if scope is not None:
        raise CapabilityAssessmentError(f"{label}-scope-only-for-register-operation")
    return None


def _operation_level(operation: str) -> str:
    if operation in _FEATURE_OPERATIONS:
        return "L3"
    return "L2" if operation in _REGISTER_OPERATIONS else "L1"


def _normalize_protocols(values: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    try:
        materialized = tuple(values)
    except TypeError as exc:
        raise CapabilityAssessmentError("invalid-runtime-protocols") from exc
    normalized: list[tuple[str, str]] = []
    for value in materialized:
        if (not isinstance(value, tuple) or len(value) != 2
                or any(not isinstance(part, str) or not part for part in value)):
            raise CapabilityAssessmentError("invalid-runtime-protocol")
        normalized.append((value[0], value[1]))
    if len(set(normalized)) != len(normalized):
        raise CapabilityAssessmentError("duplicate-runtime-protocol")
    return tuple(sorted(normalized))


def _normalize_observation_mapping_ids(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise CapabilityAssessmentError(f"invalid-{label}-observation-mappings")
    try:
        materialized = tuple(values)
    except TypeError as exc:
        raise CapabilityAssessmentError(f"invalid-{label}-observation-mappings") from exc
    if any(not isinstance(item, str) or _OBSERVATION_MAPPING_ID.fullmatch(item) is None
           for item in materialized):
        raise CapabilityAssessmentError(f"invalid-{label}-observation-mapping")
    if len(set(materialized)) != len(materialized):
        raise CapabilityAssessmentError(f"duplicate-{label}-observation-mapping")
    return tuple(sorted(materialized))


def _operation_claims(
    values: Mapping[str, Iterable[str | tuple[str, str]]],
) -> tuple[OperationClaim, ...]:
    if not isinstance(values, Mapping):
        raise CapabilityAssessmentError("invalid-runtime-endpoint-operations")
    claims: list[OperationClaim] = []
    for endpoint_id, operations in values.items():
        if not isinstance(endpoint_id, str) or not endpoint_id:
            raise CapabilityAssessmentError("invalid-runtime-endpoint-id")
        if isinstance(operations, (str, bytes, bytearray)):
            raise CapabilityAssessmentError(
                f"invalid-runtime-operations:{endpoint_id}"
            )
        try:
            items = tuple(operations)
        except TypeError as exc:
            raise CapabilityAssessmentError(
                f"invalid-runtime-operations:{endpoint_id}"
            ) from exc
        normalized: list[OperationClaim] = []
        for item in items:
            if isinstance(item, str):
                operation, scope = item, None
            elif (isinstance(item, tuple) and len(item) == 2
                  and isinstance(item[0], str)):
                operation, scope = item
            else:
                raise CapabilityAssessmentError(
                    f"invalid-runtime-operation-claim:{endpoint_id}"
                )
            operation = _require_operation(operation, "runtime")
            scope = _normalize_operation_scope(operation, scope, "runtime")
            normalized.append(OperationClaim(endpoint_id, operation, scope))
        keys = [(claim.operation, claim.scope) for claim in normalized]
        if len(set(keys)) != len(keys):
            raise CapabilityAssessmentError(f"duplicate-runtime-operation:{endpoint_id}")
        claims.extend(normalized)
    return tuple(sorted(claims, key=lambda item: (
        item.endpoint_id, item.operation, item.scope or "")))


def _operation_claims_from_records(values: Iterable[OperationClaim],
                                   label: str) -> tuple[OperationClaim, ...]:
    claims: list[OperationClaim] = []
    for item in tuple(values):
        if not isinstance(item, OperationClaim):
            raise CapabilityAssessmentError(f"invalid-{label}-operation-claim")
        if not isinstance(item.endpoint_id, str) or not item.endpoint_id:
            raise CapabilityAssessmentError(f"invalid-{label}-endpoint-id")
        operation = _require_operation(item.operation, label)
        scope = _normalize_operation_scope(operation, item.scope, label)
        claims.append(OperationClaim(item.endpoint_id, operation, scope))
    keys = [(item.endpoint_id, item.operation, item.scope) for item in claims]
    if len(set(keys)) != len(keys):
        raise CapabilityAssessmentError(f"duplicate-{label}-operation")
    claims.sort(key=lambda item: (item.endpoint_id, item.operation, item.scope or ""))
    return tuple(claims)


def _normalize_evidence_refs(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise CapabilityAssessmentError("invalid-verification-evidence-refs")
    try:
        refs = tuple(values)
    except TypeError as exc:
        raise CapabilityAssessmentError("invalid-verification-evidence-refs") from exc
    if not refs or any(not isinstance(value, str) or not value for value in refs):
        raise CapabilityAssessmentError("verification-evidence-required")
    if len(set(refs)) != len(refs):
        raise CapabilityAssessmentError("duplicate-verification-evidence-ref")
    return tuple(sorted(refs))


def _sidecar_for_profile(profile: ComponentProfile,
                         sidecar: IPTestCapability | None) -> IPTestCapability | None:
    if sidecar is None:
        return None
    if not isinstance(sidecar, IPTestCapability):
        raise CapabilityAssessmentError("loaded-test-capability-required")
    try:
        sidecar = _revalidate_ip_test_capability(sidecar, profile=profile)
    except IPTestCapabilityError as exc:
        raise CapabilityAssessmentError(str(exc)) from exc
    if sidecar.schema_version not in (IP_TEST_CAPABILITY_SCHEMA,
                                      IP_TEST_CAPABILITY_SCHEMA_V2,
                                      IP_TEST_CAPABILITY_SCHEMA_V3):
        raise CapabilityAssessmentError("unsupported-test-capability-schema")
    endpoint_ids = {endpoint.endpoint_id for endpoint in profile.endpoints}
    for item in sidecar.endpoint_capabilities:
        if item.endpoint_id not in endpoint_ids:
            raise CapabilityAssessmentError(
                f"test-capability-unknown-endpoint:{item.endpoint_id}"
            )
        for operation in item.operations:
            _require_operation(operation, "test-capability")
            if operation in _REGISTER_OPERATIONS:
                raise CapabilityAssessmentError(
                    "register-operations-derived-from-field-semantics"
                )
    for item in sidecar.observation_mappings:
        if item.endpoint_id not in endpoint_ids:
            raise CapabilityAssessmentError(
                f"test-capability-unknown-endpoint:{item.endpoint_id}"
            )
    return sidecar


def _declared_operations(
    profile: ComponentProfile,
    sidecar: IPTestCapability | None,
) -> tuple[dict[str, set[tuple[str, str | None]]], tuple[str, ...],
           dict[tuple[str, str, str | None], tuple[str, ...]]]:
    operations = {endpoint.endpoint_id: set() for endpoint in profile.endpoints}
    gaps: set[str] = set()
    observation_requirements: dict[tuple[str, str, str | None], tuple[str, ...]] = {}
    protocol_endpoints = tuple(
        endpoint for endpoint in profile.endpoints if endpoint.protocol is not None
    )
    for endpoint in protocol_endpoints:
        # These are protocol-level actions only.  Their presence does not assert
        # any component-specific register or function semantics.
        operations[endpoint.endpoint_id].update(
            (operation, None) for operation in ("request", "accept", "response"))
    if len(protocol_endpoints) == 1:
        endpoint_id = protocol_endpoints[0].endpoint_id
        if profile.capability("has_error") is True:
            operations[endpoint_id].add(("error", None))
        if profile.capability("read") is True:
            operations[endpoint_id].add(("read", None))
        if profile.capability("write") is True:
            operations[endpoint_id].add(("write", None))
        max_wait = profile.capability("max_wait_cycles")
        if isinstance(max_wait, int) and not isinstance(max_wait, bool) and max_wait > 0:
            operations[endpoint_id].add(("wait", None))
    elif protocol_endpoints and any(
        profile.capability(name) is not None
        for name in ("has_error", "read", "write", "max_wait_cycles")
    ):
        gaps.add("component-protocol-capabilities-endpoint-ambiguous")

    if sidecar is not None:
        for item in sidecar.endpoint_capabilities:
            operations[item.endpoint_id].update((operation, None)
                                                for operation in item.operations)
        for item in sidecar.observation_mappings:
            mapped_operation = {
                "port_sample": "sample",
                "signal_change": "observe",
                "binding_delivery": "deliver",
                "input_sample": "sample",
                "reset_observation": "observe",
                "clock_domain_progress": "observe",
            }.get(item.observation_kind)
            if mapped_operation is None:
                raise CapabilityAssessmentError(
                    f"unsupported-observation-kind:{item.observation_kind}"
                )
            operations[item.endpoint_id].add((mapped_operation, None))

        if sidecar.feature_contract is not None:
            for item in sidecar.feature_contract.operations:
                operations[item.endpoint_id].add((item.operation, None))
                observation_requirements[(item.endpoint_id, item.operation, None)] = (
                    item.required_observation_mappings)

    register_semantics = sidecar.register_semantics if sidecar is not None else ()
    mmio_endpoints = tuple(
        endpoint for endpoint in profile.endpoints if endpoint.function == "mmio_slave"
    )
    if register_semantics and len(mmio_endpoints) == 1:
        mmio_endpoint_id = mmio_endpoints[0].endpoint_id
        for item in register_semantics:
            scope = f"{item.register}.{item.field}"
            if item.access in ("ro", "rw") and item.read_mask:
                operations[mmio_endpoint_id].add(("register_read", scope))
            if item.access in ("wo", "rw") and item.write_mask:
                operations[mmio_endpoint_id].add(("register_write", scope))
    elif register_semantics:
        gaps.add("register-semantics-mmio-endpoint-ambiguous")

    if not register_semantics:
        gaps.add("register-field-semantics-not-declared")
    if sidecar is None or sidecar.feature_contract is None:
        gaps.add("level-3-plugin-contract-not-declared")
    elif not any(operation in _REGISTER_OPERATIONS
                 for endpoint_operations in operations.values()
                 for operation, _scope in endpoint_operations):
        gaps.add("level-3-requires-level-2-contract")
    return operations, tuple(sorted(gaps)), observation_requirements


def _highest_level(
    rows: tuple[EndpointOperationSupport, ...],
    profile: ComponentProfile,
    *,
    attribute: str,
) -> str | None:
    supported = {
        (row.endpoint_id, row.operation, row.scope)
        for row in rows if getattr(row, attribute)
    }
    required_protocol_ids = tuple(
        endpoint.endpoint_id for endpoint in profile.endpoints
        if endpoint.required and endpoint.protocol is not None
    )
    if required_protocol_ids:
        # A protocol-level test is complete only when every required protocol
        # endpoint has its own request/accept/response path.  The matrix still
        # preserves partial support when this aggregate level is unavailable.
        l1_complete = all(
            all((endpoint_id, operation, None) in supported
                for operation in _PROTOCOL_CORE_OPERATIONS)
            for endpoint_id in required_protocol_ids
        )
    else:
        candidate_ids = {
            endpoint.endpoint_id for endpoint in profile.endpoints if endpoint.required
        } or {endpoint.endpoint_id for endpoint in profile.endpoints}
        l1_complete = any(
            row.endpoint_id in candidate_ids and row.level == "L1"
            and getattr(row, attribute)
            for row in rows
        )
    if not l1_complete:
        return None
    l2_rows = tuple(row for row in rows if row.level == "L2" and row.declared)
    l2_supported = bool(l2_rows) and all(getattr(row, attribute) for row in l2_rows)
    if not l2_supported:
        return "L1"
    l3_rows = tuple(row for row in rows if row.level == "L3" and row.declared)
    l3_supported = bool(l3_rows) and all(getattr(row, attribute) for row in l3_rows)
    return "L3" if l3_supported else "L2"


def _protocol_gaps(
    profile: ComponentProfile,
    runtime_support: RuntimeCapabilitySnapshot | None,
) -> dict[str, str]:
    gaps: dict[str, str] = {}
    if runtime_support is None:
        return gaps
    supported = set(runtime_support.supported_protocols)
    for endpoint in profile.endpoints:
        if endpoint.protocol is not None and endpoint.protocol not in supported:
            protocol, version = endpoint.protocol
            gaps[endpoint.endpoint_id] = f"unsupported-protocol:{protocol}@{version}"
    return gaps


def assess_ip_test_level(
    profile: ComponentProfile,
    *,
    sidecar: IPTestCapability | None = None,
    runtime_support: RuntimeCapabilitySnapshot | None = None,
    verification: VerifiedCapabilitySnapshot | None = None,
    requested_minimum_level: str | None = None,
) -> IPTestLevelAssessment:
    """Resolve capability levels and a gap-preserving endpoint/operation matrix.

    ``runtime_support`` and ``verification`` must come from trusted runtime
    components, not from profile documents.  With no runtime snapshot, the
    assessment reports declarations and gaps but has no effective level.  With
    no verifier snapshot, it never promotes static claims to verified.
    """
    profile = _require_profile(profile)
    sidecar = _sidecar_for_profile(profile, sidecar)
    if requested_minimum_level is not None and requested_minimum_level not in _LEVELS:
        raise CapabilityAssessmentError(
            f"invalid-requested-minimum-level:{requested_minimum_level}"
        )
    if runtime_support is not None:
        if not isinstance(runtime_support, RuntimeCapabilitySnapshot):
            raise CapabilityAssessmentError("runtime-capability-snapshot-required")
        if runtime_support.component_id != profile.component_id:
            raise CapabilityAssessmentError("runtime-capability-component-mismatch")
        if runtime_support.profile_fingerprint != profile.profile_fingerprint:
            raise CapabilityAssessmentError("runtime-capability-profile-mismatch")
        expected_sidecar = sidecar.sidecar_fingerprint if sidecar is not None else None
        if runtime_support.sidecar_fingerprint != expected_sidecar:
            raise CapabilityAssessmentError("runtime-capability-sidecar-mismatch")
    if verification is not None:
        if not isinstance(verification, VerifiedCapabilitySnapshot):
            raise CapabilityAssessmentError("verified-capability-snapshot-required")
        if verification.component_id != profile.component_id:
            raise CapabilityAssessmentError("verification-component-mismatch")
        if verification.profile_fingerprint != profile.profile_fingerprint:
            raise CapabilityAssessmentError("verification-profile-mismatch")
        expected_sidecar = sidecar.sidecar_fingerprint if sidecar is not None else None
        if verification.sidecar_fingerprint != expected_sidecar:
            raise CapabilityAssessmentError("verification-sidecar-mismatch")

    declared, initial_gaps, observation_requirements = _declared_operations(profile, sidecar)
    runtime_operations = ({(item.endpoint_id, item.operation, item.scope)
                           for item in runtime_support.endpoint_operations}
                          if runtime_support is not None else set())
    runtime_protocols = (set(runtime_support.supported_protocols)
                         if runtime_support is not None else set())
    runtime_observation_mappings = (set(runtime_support.observation_mappings)
                                    if runtime_support is not None else set())
    declared_observation_mappings = ({item.mapping_id for item in sidecar.observation_mappings}
                                     if sidecar is not None else set())
    unknown_runtime_mappings = sorted(runtime_observation_mappings
                                      - declared_observation_mappings)
    if unknown_runtime_mappings:
        raise CapabilityAssessmentError(
            f"runtime-capability-unknown-observation-mapping:{unknown_runtime_mappings[0]}"
        )
    protocol_gaps = _protocol_gaps(profile, runtime_support)
    verification_operations = (
        {(item.endpoint_id, item.operation, item.scope): item.evidence_refs
         for item in verification.operations}
        if verification is not None else {}
    )

    endpoint_ids = {endpoint.endpoint_id for endpoint in profile.endpoints}
    for endpoint_id, operation, _scope in runtime_operations:
        if endpoint_id not in endpoint_ids:
            raise CapabilityAssessmentError(f"runtime-capability-unknown-endpoint:{endpoint_id}")
        # A runtime may report an executor operation that the contract never
        # declared; it is retained as a matrix gap rather than granting it.
        if operation not in _OPERATIONS:
            raise CapabilityAssessmentError(f"invalid-runtime-operation:{operation}")
    for endpoint_id, operation, _scope in verification_operations:
        if endpoint_id not in endpoint_ids:
            raise CapabilityAssessmentError(f"verification-unknown-endpoint:{endpoint_id}")

    rows: list[EndpointOperationSupport] = []
    all_keys = {
        (endpoint_id, operation, scope)
        for endpoint_id, operations in declared.items()
        for operation, scope in operations
    }
    all_keys.update(runtime_operations)
    all_keys.update(verification_operations)
    for endpoint_id, operation, scope in sorted(
            all_keys, key=lambda item: (item[0], item[1], item[2] or "")):
        level = _operation_level(operation)
        is_declared = (operation, scope) in declared.get(endpoint_id, set())
        endpoint = profile.endpoint(endpoint_id)
        required_mappings = observation_requirements.get(
            (endpoint_id, operation, scope), ())
        missing_mappings = tuple(
            mapping_id for mapping_id in required_mappings
            if mapping_id not in runtime_observation_mappings)
        protocol_supported = (
            endpoint.protocol is None
            or (runtime_support is not None and endpoint.protocol in runtime_protocols)
        )
        is_effective = (
            is_declared and (endpoint_id, operation, scope) in runtime_operations
            and protocol_supported and not missing_mappings
        )
        evidence_refs = verification_operations.get((endpoint_id, operation, scope), ())
        if evidence_refs and (not is_declared or not is_effective):
            raise CapabilityAssessmentError(
                f"verification-exceeds-effective-capability:{endpoint_id}:{operation}"
            )
        is_verified = bool(evidence_refs)
        row_gaps: set[str] = set()
        if not is_declared:
            row_gaps.add("operation-not-declared")
        elif runtime_support is None:
            row_gaps.add("runtime-preflight-not-supplied")
        elif endpoint_id in protocol_gaps:
            row_gaps.add(protocol_gaps[endpoint_id])
        elif (endpoint_id, operation, scope) not in runtime_operations:
            suffix = f":{scope}" if scope is not None else ""
            row_gaps.add(
                f"runtime-operation-unavailable:{endpoint_id}:{operation}{suffix}"
            )
        if runtime_support is not None:
            row_gaps.update(
                f"runtime-observation-mapping-unavailable:{mapping_id}"
                for mapping_id in missing_mappings)
        if is_effective and not is_verified:
            row_gaps.add("verification-evidence-not-supplied")
        rows.append(EndpointOperationSupport(
            endpoint_id=endpoint_id,
            operation=operation,
            level=level,
            declared=is_declared,
            effective=is_effective,
            verified=is_verified,
            scope=scope,
            gaps=tuple(sorted(row_gaps)),
            evidence_refs=evidence_refs,
        ))

    matrix = tuple(rows)
    gaps = set(initial_gaps)
    for row in matrix:
        gaps.update(row.gaps)
    declared_level = _highest_level(matrix, profile, attribute="declared")
    effective_level = _highest_level(matrix, profile, attribute="effective")
    verified_level = _highest_level(matrix, profile, attribute="verified")
    if runtime_support is None:
        gaps.add("runtime-preflight-not-supplied")
    else:
        gaps.update(protocol_gaps.values())
    if verification is None:
        gaps.add("verification-evidence-not-supplied")
    elif verified_level is None:
        if any(row.verified for row in matrix):
            gaps.add("verified-operations-insufficient-for-complete-level")
        else:
            gaps.add("no-effective-operations-verified")
    if requested_minimum_level is None:
        minimum_level_met = None
    else:
        minimum_level_met = (
            effective_level is not None
            and _LEVELS.index(effective_level) >= _LEVELS.index(requested_minimum_level)
        )
        if not minimum_level_met:
            gaps.add(f"requested-minimum-not-met:{requested_minimum_level}")

    return IPTestLevelAssessment(
        schema_version=IP_TEST_LEVEL_ASSESSMENT_SCHEMA,
        component_id=profile.component_id,
        profile_fingerprint=profile.profile_fingerprint,
        sidecar_fingerprint=sidecar.sidecar_fingerprint if sidecar is not None else None,
        declared_level=declared_level,
        effective_level=effective_level,
        verified_level=verified_level,
        requested_minimum_level=requested_minimum_level,
        minimum_level_met=minimum_level_met,
        support_matrix=matrix,
        gaps=tuple(sorted(gaps)),
    )

