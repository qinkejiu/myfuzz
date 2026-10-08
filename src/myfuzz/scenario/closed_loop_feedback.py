"""Closed-loop feedback consumed read-only from runtime chain certificates.

The certified end-to-end chains produced by
:mod:`myfuzz.scenario.chain_certificates` already carry, per hop, the exact
production/delivery/consumption event identity. This module turns that stream
into first-class feedback without ever re-deriving causality:

``closed_loop``
    one hit per ``certified`` certificate: the declared terminal hop was
    observed, so the whole declared propagation loop is proven for that
    ``source_admission_id``.
``partial_propagation``
    an ``incomplete`` certificate whose observed hops include a component other
    than the admitted source component: downstream consumption is proven, the
    terminal hop is not (``missing_hops`` names the first gap and every
    required hop after it).
``stage_reached``
    an ``incomplete`` certificate that only ever reached its own source-side
    stages: no downstream consumer is proven, so it is stage arrival and never
    propagation.

Every hit names its direction, ``source_admission_id``, ordered hop identities
(``hop_id`` plus the real ``event_id``), its terminal hop, whether the chain
crossed case boundaries and which downstream components served it. ``hit_id``
is the lowercase SHA-256 hex digest of the canonical JSON array
``[schema, kind, direction, source_admission_id, [[hop_id, event_id], ...]]``,
so the same journal and producer version always produce the same counts and the
same hit identities.

The consumer is fail-closed and read-only: a certificate whose schema,
identity or hop sequence does not match the frozen producer contract is refused
with :class:`ValueError` instead of being counted, a certificate that is
re-ingested is deduplicated by ``certificate_id``, and a ``certificate_id``
reused with different evidence is refused. Ingested documents are never
mutated.

``energy_weights`` converts this feedback (closed loops, new edges, new state
transitions, new coverage targets and failure evidence) into the source/path
weights consumed by :func:`myfuzz.scenario.mutation.choose_mutation`. Without
feedback it returns the caller's baseline weights unchanged, so existing
allocation stays reproducible. Evidence that names no weight key is never
silently attributed: hits default to their own ``source_id`` and every other
evidence kind requires an explicit ``attribution`` entry.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

from .chain_certificates import (
    CPU_IRQ_SERIAL_HOP,
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    SCHEMA_VERSION as CERTIFICATE_SCHEMA_VERSION,
    SERIAL_TOKEN_ABSENT,
    SERIAL_TOKEN_REFUSED,
    SERIAL_TOKEN_WITNESSED,
    declared_hop_sequence,
)


FEEDBACK_SCHEMA_VERSION = "closed_loop_feedback.v1"
CERTIFIED = "certified"
INCOMPLETE = "incomplete"
CLOSED_LOOP = "closed_loop"
PARTIAL_PROPAGATION = "partial_propagation"
STAGE_REACHED = "stage_reached"
HIT_KINDS = (CLOSED_LOOP, PARTIAL_PROPAGATION, STAGE_REACHED)

_DIRECTIONS = (IP_TO_CPU_TO_IP, CPU_TO_IP_TO_CPU)
_STATUSES = (CERTIFIED, INCOMPLETE)
_SERIAL_STATUSES = (SERIAL_TOKEN_ABSENT, SERIAL_TOKEN_WITNESSED,
                    SERIAL_TOKEN_REFUSED)
_PROOF_SCOPES = {IP_TO_CPU_TO_IP: "ip_to_cpu_to_ip_certified_hops",
                 CPU_TO_IP_TO_CPU: "cpu_to_ip_to_cpu_certified_hops"}
_HOP_FIELDS = frozenset(("hop_id", "event_id", "evidence"))
_KIND_RANK = {kind: rank for rank, kind in enumerate(HIT_KINDS)}
_KIND_LISTS = {CLOSED_LOOP: "closed_loops",
               PARTIAL_PROPAGATION: "partial_propagation",
               STAGE_REACHED: "stage_reached"}
# First declared hop that is proven by a component downstream of the admitted
# source's own stages: everything before it is the source-side stage prefix.
_STAGE_BOUNDARY_HOP = {IP_TO_CPU_TO_IP: "cpu_irq_input",
                       CPU_TO_IP_TO_CPU: "mmio_write_acceptance"}


def _nonempty_string(value: object) -> bool:
    return type(value) is str and bool(value)


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def _recomputed_certificate_id(direction: str, admission_id: str) -> str:
    """Independent copy of the frozen producer's certificate identity."""
    payload = json.dumps([direction, admission_id], separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _hit_id(kind: str, direction: str, admission_id: str,
            hops: list[dict]) -> str:
    payload = json.dumps(
        [FEEDBACK_SCHEMA_VERSION, kind, direction, admission_id,
         [[hop["hop_id"], hop["event_id"]] for hop in hops]],
        separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def producer_identity() -> dict:
    """Identify the certificate producer bytes that hit identities depend on."""
    module = sys.modules.get("myfuzz.scenario.chain_certificates")
    path = Path(getattr(module, "__file__", "") or "")
    identity = {"module": "myfuzz.scenario.chain_certificates",
                "path": str(path), "sha256": None}
    try:
        identity["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return identity


def certificate_hit(certificate: Mapping) -> dict:
    """Validate and classify one chain certificate into a feedback hit.

    Raises :class:`ValueError` for every deviation from the frozen
    ``runtime_chain_certificate.v1`` contract; a malformed certificate is never
    silently counted.
    """
    if not isinstance(certificate, Mapping):
        raise ValueError(
            "closed-loop feedback requires a chain certificate mapping, got "
            f"{type(certificate).__name__}")
    schema = certificate.get("schema_version")
    if schema != CERTIFICATE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported chain certificate schema_version {schema!r}")
    status = certificate.get("status")
    if status not in _STATUSES:
        raise ValueError(f"unsupported chain certificate status {status!r}")
    direction = certificate.get("direction")
    if direction not in _DIRECTIONS:
        raise ValueError(
            f"unsupported chain certificate direction {direction!r}")
    certificate_id = certificate.get("certificate_id")
    if not _nonempty_string(certificate_id):
        raise ValueError("chain certificate needs a nonempty certificate_id")
    admission_id = certificate.get("source_admission_id")
    if not _nonempty_string(admission_id):
        raise ValueError(
            "chain certificate needs a nonempty source_admission_id")
    if certificate_id != _recomputed_certificate_id(direction, admission_id):
        raise ValueError("chain certificate certificate_id disagrees with "
                         "direction and source_admission_id")
    source_action_id = certificate.get("source_action_id")
    if not _nonempty_string(source_action_id):
        raise ValueError("chain certificate needs a nonempty source_action_id")
    source_id = certificate.get("source_id")
    if not _nonempty_string(source_id):
        raise ValueError("chain certificate needs a nonempty source_id")
    source_component = certificate.get("source_component")
    if not _nonempty_string(source_component):
        raise ValueError(
            "chain certificate needs a nonempty source_component")
    source_case_id = certificate.get("source_case_id")
    source_case_index = certificate.get("source_case_index")
    if not _nonempty_string(source_case_id) or not _nonnegative_integer(
            source_case_index):
        raise ValueError("chain certificate source case identity is invalid")
    endpoint_case_id = certificate.get("endpoint_case_id")
    endpoint_case_index = certificate.get("endpoint_case_index")
    if (endpoint_case_id is None) != (endpoint_case_index is None):
        raise ValueError(
            "chain certificate endpoint case identity is incomplete")
    if endpoint_case_id is not None and (
            not _nonempty_string(endpoint_case_id)
            or not _nonnegative_integer(endpoint_case_index)):
        raise ValueError("chain certificate endpoint case identity is invalid")
    completed_event_id = certificate.get("completed_event_id")
    if not _positive_integer(completed_event_id):
        raise ValueError(
            "chain certificate completed_event_id must be a positive integer")
    proof_scope = certificate.get("proof_scope")
    if proof_scope != _PROOF_SCOPES[direction]:
        raise ValueError(
            f"chain certificate proof_scope {proof_scope!r} does not match "
            f"{direction}")
    serial_status = certificate.get("serial_token_status")
    if serial_status not in _SERIAL_STATUSES:
        raise ValueError(
            f"chain certificate serial_token_status {serial_status!r} is "
            "unknown")

    sequence = declared_hop_sequence(direction)
    positions = {name: index for index, name in enumerate(sequence)}
    document_hops = certificate.get("hops")
    if not isinstance(document_hops, list) or not document_hops:
        raise ValueError("chain certificate hops must be a nonempty list")
    hops: list[dict] = []
    observed: set[str] = set()
    components: list[str] = []
    witnessed = False
    last_position = -1
    last_event_id = 0
    for index, entry in enumerate(document_hops):
        if not isinstance(entry, Mapping):
            raise ValueError(f"chain certificate hop {index} must be a mapping")
        if set(entry) != _HOP_FIELDS:
            raise ValueError(f"chain certificate hop {index} must declare "
                             "exactly hop_id, event_id and evidence")
        hop_id = entry.get("hop_id")
        if not _nonempty_string(hop_id) or hop_id not in positions:
            raise ValueError(f"chain certificate hop_id {hop_id!r} is not "
                             f"declared for {direction}")
        if hop_id in observed:
            raise ValueError(
                f"chain certificate hop_id {hop_id!r} is duplicated")
        event_id = entry.get("event_id")
        if not _positive_integer(event_id):
            raise ValueError(f"chain certificate hop {hop_id!r} event_id must "
                             "be a positive integer")
        evidence = entry.get("evidence")
        if not isinstance(evidence, Mapping):
            raise ValueError(f"chain certificate hop_id {hop_id!r} evidence "
                             "must be a mapping")
        position = positions[hop_id]
        if position <= last_position:
            raise ValueError(f"chain certificate hop_id {hop_id!r} is out of "
                             "declared order")
        if event_id <= last_event_id:
            raise ValueError(f"chain certificate hop event_id {event_id!r} is "
                             "not strictly increasing")
        last_position, last_event_id = position, event_id
        observed.add(hop_id)
        component = evidence.get("component")
        if _nonempty_string(component):
            components.append(component)
        witnessed = witnessed or hop_id == CPU_IRQ_SERIAL_HOP
        hops.append({"hop_id": hop_id, "event_id": event_id})

    missing_hops = certificate.get("missing_hops")
    if not isinstance(missing_hops, list):
        raise ValueError("chain certificate missing_hops must be a list")
    missing: list[str] = []
    for hop_id in missing_hops:
        if not _nonempty_string(hop_id) or hop_id not in positions:
            raise ValueError("chain certificate missing_hops names undeclared "
                             f"hop_id {hop_id!r}")
        if hop_id in observed:
            raise ValueError("chain certificate missing_hops names observed "
                             f"hop_id {hop_id!r}")
        if hop_id in missing:
            raise ValueError(
                f"chain certificate missing_hops repeats hop_id {hop_id!r}")
        missing.append(hop_id)
    if status == CERTIFIED and missing:
        raise ValueError(
            "certified chain certificate must not declare missing_hops")
    if missing:
        first_missing = positions[missing[0]]
        for hop in hops:
            if positions[hop["hop_id"]] > first_missing:
                raise ValueError(f"chain certificate missing_hops {missing[0]!r}"
                                 " precedes an observed hop_id")

    if witnessed != (serial_status == SERIAL_TOKEN_WITNESSED):
        raise ValueError("chain certificate serial_token_status must be "
                         f"{SERIAL_TOKEN_WITNESSED!r} when the "
                         f"{CPU_IRQ_SERIAL_HOP} hop is present")

    downstream = sorted({component for component in components
                         if component != source_component})
    # A chain propagated only when a hop beyond the source's own stage prefix
    # was witnessed, either by another component's evidence or by position in
    # the declared sequence. Otherwise it is stage arrival, never propagation.
    boundary_hop = _STAGE_BOUNDARY_HOP[direction]
    stage_hops = frozenset(sequence[:sequence.index(boundary_hop)])
    propagated = bool(downstream) or any(hop["hop_id"] not in stage_hops
                                         for hop in hops)
    if status == CERTIFIED:
        kind = CLOSED_LOOP
    elif propagated:
        kind = PARTIAL_PROPAGATION
    else:
        kind = STAGE_REACHED
    terminal_hop = sequence[-1]
    if endpoint_case_id is None:
        cross_case: bool | None = None
    else:
        cross_case = (endpoint_case_id, endpoint_case_index) != (
            source_case_id, source_case_index)
    return {
        "schema_version": FEEDBACK_SCHEMA_VERSION,
        "hit_id": _hit_id(kind, direction, admission_id, hops),
        "kind": kind,
        "certificate_id": certificate_id,
        "status": status,
        "direction": direction,
        "source_admission_id": admission_id,
        "source_action_id": source_action_id,
        "source_id": source_id,
        "source_component": source_component,
        "source_case_id": source_case_id,
        "source_case_index": source_case_index,
        "endpoint_case_id": endpoint_case_id,
        "endpoint_case_index": endpoint_case_index,
        "cross_case": cross_case,
        "hops": hops,
        "hop_count": len(hops),
        "terminal_hop": dict(hops[-1]),
        "declared_terminal_hop": terminal_hop,
        "reached_terminal_hop": terminal_hop in observed,
        "missing_hops": missing,
        "first_missing_hop": missing[0] if missing else None,
        "downstream_components": downstream,
        "propagated": propagated,
        "stage_boundary_hop": boundary_hop,
        "serial_token_status": serial_status,
        "completed_event_id": completed_event_id,
        "proof_scope": proof_scope,
    }


def hit_feature(hit: Mapping) -> str:
    """Feature identity of one hit: ``<kind>:<direction>:<source_id>``."""
    if not isinstance(hit, Mapping):
        raise ValueError(f"feedback item is not a closed-loop hit: {hit!r}")
    kind = hit.get("kind")
    direction = hit.get("direction")
    source_id = hit.get("source_id")
    if (kind not in HIT_KINDS or direction not in _DIRECTIONS
            or not _nonempty_string(source_id)):
        raise ValueError(f"feedback item is not a closed-loop hit: {hit!r}")
    return f"{kind}:{direction}:{source_id}"


def edge_feature(edge: Mapping) -> str:
    """Feature identity of an interaction edge, as counted by the collector."""
    if not isinstance(edge, Mapping):
        raise ValueError(f"feedback item is not an interaction edge: {edge!r}")
    kind = edge.get("kind")
    source = edge.get("source")
    target = edge.get("target")
    if not (_nonempty_string(kind) and _nonempty_string(source)
            and _nonempty_string(target)):
        raise ValueError(f"feedback item is not an interaction edge: {edge!r}")
    return f"{kind}:{source}:{target}"


def transition_feature(transition: object) -> str:
    """Feature identity of a state transition (its counter key, verbatim)."""
    if isinstance(transition, Mapping):
        transition = transition.get("key")
    if not _nonempty_string(transition):
        raise ValueError(
            f"feedback item is not a state transition: {transition!r}")
    return transition


def target_feature(target_id: object) -> str:
    """Feature identity of one coverage target."""
    if not _nonempty_string(target_id):
        raise ValueError(f"feedback item is not a target id: {target_id!r}")
    return f"target:{target_id}"


def failure_feature(failure: object) -> str:
    """Feature identity of one failure family."""
    if isinstance(failure, Mapping):
        failure = failure.get("family")
    if not _nonempty_string(failure):
        raise ValueError(f"feedback item is not a failure family: {failure!r}")
    return f"failure:{failure}"


def _hit_order(hit: Mapping) -> tuple:
    return (_KIND_RANK[hit["kind"]], hit["direction"], hit["source_case_index"],
            hit["source_id"], hit["source_admission_id"], hit["hit_id"])


class ClosedLoopFeedback:
    """Accumulate certificate hits with recomputable counts and identities.

    Certificates arrive as a contiguous stream from
    :class:`myfuzz.scenario.chain_certificates.ChainCertificates`. A batch is
    validated in full before anything is recorded, re-ingesting an identical
    certificate is a no-op, and one settled admission is never counted twice.
    """

    def __init__(self) -> None:
        self._hits: dict[str, dict] = {}
        self._by_kind: dict[str, list[dict]] = {kind: [] for kind in HIT_KINDS}
        self._reported: dict[str, int] = {kind: 0 for kind in HIT_KINDS}
        self._producer = producer_identity()

    def ingest(self, certificates: Iterable[Mapping]) -> tuple[dict, ...]:
        """Record new certificates; return the hits they added, in order."""
        validated = tuple(certificate_hit(certificate)
                          for certificate in certificates)
        recorded = []
        for hit in validated:
            previous = self._hits.get(hit["certificate_id"])
            if previous is not None:
                if previous != hit:
                    raise ValueError("chain certificate certificate_id was "
                                     "reused with different evidence")
                continue
            self._hits[hit["certificate_id"]] = hit
            self._by_kind[hit["kind"]].append(hit)
            recorded.append(hit)
        return tuple(recorded)

    @property
    def certificate_count(self) -> int:
        return len(self._hits)

    @property
    def hit_count(self) -> int:
        return len(self._hits)

    @property
    def closed_loop_count(self) -> int:
        return len(self._by_kind[CLOSED_LOOP])

    @property
    def partial_propagation_count(self) -> int:
        return len(self._by_kind[PARTIAL_PROPAGATION])

    @property
    def stage_reached_count(self) -> int:
        return len(self._by_kind[STAGE_REACHED])

    def _sorted_hits(self, kind: str) -> list[dict]:
        return [deepcopy(hit)
                for hit in sorted(self._by_kind[kind], key=_hit_order)]

    def _counts(self) -> dict:
        return {"certificate_count": len(self._hits),
                "hit_count": len(self._hits),
                "closed_loop_count": self.closed_loop_count,
                "partial_propagation_count": self.partial_propagation_count,
                "stage_reached_count": self.stage_reached_count}

    def summary(self) -> dict:
        """Complete historical report, sorted independently of arrival order."""
        counts = Counter(hit_feature(hit) for kind in HIT_KINDS
                         for hit in self._by_kind[kind])
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "certificate_schema_version": CERTIFICATE_SCHEMA_VERSION,
            "producer": deepcopy(self._producer),
            **self._counts(),
            **{_KIND_LISTS[kind]: self._sorted_hits(kind)
               for kind in HIT_KINDS},
            "feature_counts": dict(sorted(counts.items())),
        }

    def incremental_summary(self) -> dict:
        """Report only the hits recorded since the previous call."""
        result = {"schema_version": FEEDBACK_SCHEMA_VERSION, **self._counts()}
        for kind in HIT_KINDS:
            pending = self._by_kind[kind][self._reported[kind]:]
            self._reported[kind] += len(pending)
            delta = [deepcopy(hit) for hit in sorted(pending, key=_hit_order)]
            name = _KIND_LISTS[kind]
            result[name] = delta
            result["delta_" + name] = delta
        return result


# --------------------------------------------------------------- energy


@dataclass(frozen=True)
class EnergyGains:
    """Explicit additive gains/penalties applied by :func:`energy_weights`."""

    closed_loop: int = 64
    partial_propagation: int = 8
    stage_reached: int = 2
    new_edge: int = 4
    new_state_transition: int = 2
    new_target: int = 16
    failure_penalty: int = 16
    floor: int = 0

    def __post_init__(self) -> None:
        for name in ("closed_loop", "partial_propagation", "stage_reached",
                     "new_edge", "new_state_transition", "new_target",
                     "failure_penalty", "floor"):
            value = getattr(self, name)
            if not _nonnegative_integer(value):
                raise ValueError(
                    f"energy gain {name} must be a nonnegative integer")


DEFAULT_GAINS = EnergyGains()


def _attributed_keys(identity: str, attribution: Mapping | None,
                     default: tuple[str, ...] | None) -> tuple[str, ...]:
    if attribution is not None and identity in attribution:
        keys = attribution[identity]
        if isinstance(keys, (str, bytes)) or not isinstance(keys, Iterable):
            raise ValueError(f"attribution for {identity!r} must be an "
                             "iterable of weight keys")
        materialised = tuple(keys)
        if not materialised or any(not _nonempty_string(key)
                                   for key in materialised):
            raise ValueError(f"attribution for {identity!r} must name "
                             "nonempty weight keys")
        return materialised
    if default is None:
        raise ValueError(f"feedback feature {identity!r} has no attribution "
                         "entry, so it names no source or path weight")
    return default


def energy_weights(base_weights: Mapping[str, int], *,
                   closed_loops: Iterable[Mapping] = (),
                   partial_propagation: Iterable[Mapping] = (),
                   stage_reached: Iterable[Mapping] = (),
                   new_edges: Iterable[Mapping] = (),
                   new_state_transitions: Iterable[object] = (),
                   new_targets: Iterable[object] = (),
                   failures: Iterable[object] = (),
                   attribution: Mapping[str, Iterable[str]] | None = None,
                   gains: EnergyGains = DEFAULT_GAINS) -> dict[str, int]:
    """Return mutation energy weights for the next selection round.

    ``base_weights`` maps a candidate key (a graph source ID for
    ``choose_mutation(source_weights=...)``, or a target/path ID for
    ``target_weights=...``) to its current nonnegative weight. Every supplied
    evidence item adds its gain once: closed-loop hits default to crediting
    their own ``source_id``, and every other evidence kind (new edge, new state
    transition, new target, failure) requires an ``attribution`` entry mapping
    its feature identity to the weight keys it belongs to, so no weight is ever
    invented from an unattributable observation. Identical evidence is
    deduplicated, the result is independent of evidence order, and without
    feedback the caller's baseline is returned unchanged.
    """
    if not isinstance(gains, EnergyGains):
        raise ValueError("energy gains must be an EnergyGains instance")
    if not isinstance(base_weights, Mapping):
        raise ValueError("energy base weights must be a mapping")
    if attribution is not None and not isinstance(attribution, Mapping):
        raise ValueError("energy attribution must be a mapping")
    base: dict[str, int] = {}
    for key, value in base_weights.items():
        if not _nonempty_string(key):
            raise ValueError("energy weight key must be a nonempty string")
        if not _nonnegative_integer(value):
            raise ValueError(
                f"energy weight {key!r} must be a nonnegative integer")
        base[key] = value

    features: dict[str, tuple[int, bool, tuple[str, ...] | None]] = {}

    def add(identity: str, gain: int, *, penalty: bool = False,
            default: tuple[str, ...] | None = None) -> None:
        if identity not in features:
            features[identity] = (gain, penalty, default)

    def add_hit(item: object, kind: str, gain: int) -> None:
        feature = hit_feature(item)
        if item.get("kind") != kind:
            raise ValueError(f"feedback item kind {item.get('kind')!r} does "
                             f"not match the {kind!r} slot")
        add(feature, gain, default=(item["source_id"],))

    for item in closed_loops:
        add_hit(item, CLOSED_LOOP, gains.closed_loop)
    for item in partial_propagation:
        add_hit(item, PARTIAL_PROPAGATION, gains.partial_propagation)
    for item in stage_reached:
        add_hit(item, STAGE_REACHED, gains.stage_reached)
    for edge in new_edges:
        add(edge_feature(edge), gains.new_edge)
    for transition in new_state_transitions:
        add(transition_feature(transition), gains.new_state_transition)
    for target_id in new_targets:
        add(target_feature(target_id), gains.new_target)
    for failure in failures:
        add(failure_feature(failure), gains.failure_penalty, penalty=True)

    credit: dict[str, int] = {}
    penalty: dict[str, int] = {}
    for identity in sorted(features):
        gain, is_penalty, default = features[identity]
        bucket = penalty if is_penalty else credit
        for key in _attributed_keys(identity, attribution, default):
            bucket[key] = bucket.get(key, 0) + gain
    return {key: max(gains.floor,
                     base.get(key, 0) + credit.get(key, 0)
                     - penalty.get(key, 0))
            for key in sorted(set(base) | set(credit) | set(penalty))}


__all__ = ["CERTIFIED", "CERTIFICATE_SCHEMA_VERSION", "CLOSED_LOOP",
           "ClosedLoopFeedback", "DEFAULT_GAINS", "EnergyGains",
           "FEEDBACK_SCHEMA_VERSION", "HIT_KINDS", "INCOMPLETE",
           "PARTIAL_PROPAGATION", "STAGE_REACHED", "certificate_hit",
           "edge_feature", "energy_weights", "failure_feature", "hit_feature",
           "producer_identity", "target_feature", "transition_feature"]
