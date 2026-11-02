"""Evidence contracts for the generic runtime.

Three layers stay separate: physical protocol samples, component semantic
effects, and cross-component source/consumption.  A status is never upgraded by
final-value equality, and ``unsupported`` means the needed proof capability was
not provided -- it never manufactures an executed fact.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ..contracts import (
    GenericRuntimeRefused,
    canonical_json_bytes,
    parse_closed_json,
    require_digest,
    require_identifier,
)
from myfuzz.scenario.ledger import TransactionKey

STATUSES = ("certified", "missing", "contradicted", "unsupported")
STATUS_RANK = {"certified": 0, "unsupported": 1, "missing": 2, "contradicted": 3}

SCOPES = (
    "physical_protocol_sample",
    "component_semantic_effect",
    "cross_component_source",
    "cross_component_consumption",
)

REFUSAL_CODES = frozenset({
    "generic-source-unverified",
    "generic-semantic-unsupported",
    "generic-template-mismatch",
    "generic-adapter-missing",
    "generic-adapter-ambiguous",
    "generic-binding-drift",
    "generic-plan-mismatch",
    "generic-route-refused",
    "generic-evidence-missing",
})


def _refuse(code: str, pointer: str, detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def combine_status(statuses) -> str:
    """Combine statuses with contradicted > missing > unsupported > certified."""
    if type(statuses) not in (tuple, list):
        _refuse("generic-contract-type", "/statuses", {"expected": "sequence"})
    worst = 0
    for status in statuses:
        if type(status) is not str or status not in STATUS_RANK:
            _refuse("generic-contract-type", "/statuses",
                    {"allowed": list(STATUSES)})
        worst = max(worst, STATUS_RANK[status])
    if not statuses:
        return "missing"
    for name in ("contradicted", "missing", "unsupported", "certified"):
        if STATUS_RANK[name] == worst:
            return name
    return "missing"


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """Reference into an existing raw event store; identity is rebuilt there."""

    component: str
    event_id: int
    kind: str

    def __post_init__(self) -> None:
        if type(self) is not EvidenceRef:
            _refuse("generic-contract-type", "/ref")
        if type(self.component) is not str or not self.component:
            _refuse("generic-contract-type", "/component")
        if type(self.event_id) is not int or self.event_id < 0:
            _refuse("generic-contract-type", "/event_id",
                    {"expected": "nonnegative int, bool rejected"})
        if type(self.kind) is not str or not self.kind:
            _refuse("generic-contract-type", "/kind")

    def document(self) -> dict:
        return {"component": self.component, "event_id": self.event_id,
                "kind": self.kind}

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.document())


def parse_evidence_ref(document, *, pointer: str = "") -> EvidenceRef:
    rows = parse_closed_json(document, ("component", "event_id", "kind"),
                             pointer=pointer)
    return EvidenceRef(rows["component"], rows["event_id"], rows["kind"])


@dataclass(frozen=True, slots=True)
class EffectEvidence:
    """Component-semantic effect evidence with explicit obligation results."""

    key: TransactionKey
    status: str
    scope: str
    binding_sha256: str
    semantic_contract_sha256: str
    source_refs: tuple[EvidenceRef, ...]
    native_refs: tuple[EvidenceRef, ...]
    destination_refs: tuple[EvidenceRef, ...]
    obligation_results: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if type(self) is not EffectEvidence:
            _refuse("generic-contract-type", "/effect")
        if type(self.key) is not TransactionKey:
            _refuse("generic-contract-type", "/key")
        if type(self.status) is not str or self.status not in STATUSES:
            _refuse("generic-contract-type", "/status",
                    {"allowed": list(STATUSES)})
        if type(self.scope) is not str or self.scope not in SCOPES:
            _refuse("generic-contract-type", "/scope",
                    {"allowed": list(SCOPES)})
        require_digest(self.binding_sha256, "/binding_sha256")
        require_digest(self.semantic_contract_sha256, "/semantic_contract_sha256")
        for name in ("source_refs", "native_refs", "destination_refs"):
            refs = getattr(self, name)
            if type(refs) is not tuple or any(
                    type(ref) is not EvidenceRef for ref in refs):
                _refuse("generic-contract-type", "/" + name,
                        {"expected": "tuple of EvidenceRef"})
            if len({ref.canonical_bytes() for ref in refs}) != len(refs):
                _refuse("generic-contract-duplicate", "/" + name)
        if type(self.obligation_results) is not tuple:
            _refuse("generic-contract-type", "/obligation_results",
                    {"expected": "tuple of (name, status)"})
        names = []
        for row in self.obligation_results:
            if type(row) is not tuple or len(row) != 2:
                _refuse("generic-contract-type", "/obligation_results",
                        {"expected": "(name, status)"})
            name, status = row
            if type(name) is not str or not name:
                _refuse("generic-contract-type", "/obligation_results",
                        {"expected": "nonempty obligation name"})
            if type(status) is not str or status not in STATUSES:
                _refuse("generic-contract-type", "/obligation_results",
                        {"allowed": list(STATUSES)})
            names.append(name)
        if len(set(names)) != len(names):
            _refuse("generic-contract-duplicate", "/obligation_results")
        if self.status == "certified" and any(
                status != "certified" for _, status in self.obligation_results):
            _refuse("generic-contract-shape", "/status",
                    {"expected": "certified only when every obligation is certified"})

    def document(self) -> dict:
        return {
            "key": {
                "execution_id": self.key.execution_id,
                "testcase_id": self.key.testcase_id,
                "source_component": self.key.source_component,
                "source_epoch": self.key.source_epoch,
                "channel_id": self.key.channel_id,
                "source_sequence": self.key.source_sequence,
            },
            "status": self.status,
            "scope": self.scope,
            "binding_sha256": self.binding_sha256,
            "semantic_contract_sha256": self.semantic_contract_sha256,
            "source_refs": [ref.document() for ref in self.source_refs],
            "native_refs": [ref.document() for ref in self.native_refs],
            "destination_refs": [ref.document() for ref in self.destination_refs],
            "obligation_results": [list(row) for row in self.obligation_results],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.document())

    def sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class EdgeClaim:
    """One edge claim with the same closed evidence shape as EffectEvidence."""

    key: TransactionKey
    status: str
    scope: str
    source_refs: tuple[EvidenceRef, ...]
    native_refs: tuple[EvidenceRef, ...]
    destination_refs: tuple[EvidenceRef, ...]
    obligation_results: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if type(self) is not EdgeClaim:
            _refuse("generic-contract-type", "/claim")
        EffectEvidence(self.key, self.status, self.scope,
                       "0" * 64, "0" * 64, self.source_refs, self.native_refs,
                       self.destination_refs, self.obligation_results)

    def document(self) -> dict:
        evidence = EffectEvidence(self.key, self.status, self.scope,
                                  "0" * 64, "0" * 64, self.source_refs,
                                  self.native_refs, self.destination_refs,
                                  self.obligation_results).document()
        evidence.pop("binding_sha256")
        evidence.pop("semantic_contract_sha256")
        return evidence


def merge_obligations(*groups) -> tuple[tuple[str, str], ...]:
    """Merge obligation results deterministically; conflicts become contradicted."""
    merged: dict[str, str] = {}
    for group in groups:
        if type(group) is not tuple:
            _refuse("generic-contract-type", "/obligation_results",
                    {"expected": "tuple of (name, status)"})
        for name, status in group:
            merged[name] = combine_status((merged.get(name, "certified"), status))
    return tuple(sorted(merged.items()))


def declared_refusal_codes() -> frozenset[str]:
    return REFUSAL_CODES
