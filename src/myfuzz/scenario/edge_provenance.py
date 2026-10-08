"""Generic per-declared-edge provenance from an observed event stream.

One :class:`RuntimeEdgeContract` edge is settled ``certified`` only when every
*required* hop of its relation is joined by an exact key of the observed events
themselves:

``direct_binding``
    ``producer`` is the source-side endpoint record (a sampled tick record
    naming the resolved source endpoint and bit range, or a source pulse record
    naming it with ``source_event_id``); ``delivery`` is the
    ``dataflow_delivery`` whose ``producer_event_id`` names that record and
    whose endpoints/bit range equal the resolved endpoints exactly;
    ``consumer`` is a *distinct* event of one of two observed shapes:

    ``interrupt``
        a ``cpu_irq_input``/``cpu_irq_taken``/``source_start``/``pulse_start``/
        ``source_end``/``pulse_expired``/``expired_masked`` record naming the
        resolved target endpoint and carrying the delivered value (or the
        delivery's ``target_value``).

    ``data``
        the target component's own recorded input observation
        (``gpio_tick_observation`` -- admitted only through the existing
        ``is_authenticated_gpio_tick`` authentication -- or a
        ``gpio_input_applied``/``gpio_input_segment_applied`` receipt).  Its
        per-bit rows must cite the delivered transport by the exact
        ``origin.delivery_event_id`` of a ``dataflow_delivery`` record that
        itself names this declared edge, the declared source endpoint and
        source bit offset; the rows must cover the declared target window
        exactly once and reconstruct a value equal to that delivery's ``value``
        *and* to the declared slice of the target's own measured input, and the
        cited delivery's ``producer_event_id`` must name a driver record whose
        declared source slice is that same value.  The certificate then names
        that one joined chain, so ``producer``/``delivery`` move onto the
        delivery the target actually cited.  Time adjacency is never a join: a
        target observation that does not cite a delivery leaves the hop
        missing.

``mmio_route``
    ``producer`` is the ``mmio_acceptance`` inside the declared aperture whose
    ``source_transaction`` is an exact transaction key and whose source
    component is the declared initiator; ``delivery`` is the ``mmio_delivery``
    with the *same* transaction key, address and device; ``consumer`` is a
    distinct event naming the same transaction key (a version/commit record).

``persistent_state``
    ``producer`` is the declared resource write record; ``delivery`` is that
    same record's version (``shared_event``, the writer carries the transport
    version); ``consumer`` is a later read of the declared resource that names
    *that exact version* field by field, in one of the two observed shapes:

    ``memory``
        the writer is a ``memory_write``/``memory_write_commit``/
        ``memory_initialization`` of the declared ``memory_id`` carrying an
        exact ``generation``, ``byte_offset``, ``byte_enable``, ``width_bytes``
        and ``version`` (plus ``commit_id`` for a commit record), and the
        consumer is a later ``memory_read`` of the same resource whose byte
        window is wholly covered by the write's enabled bytes, whose
        ``generation`` equals the writer's, and whose per-byte ``versions``
        equal the writer's version while ``writer_event_ids`` names that very
        write record.  A name is exact only when it is the writer's own integer
        event id, the writer's own canonical ``TransactionKey(...)`` identity
        (the id its host commit stored) or the writer's own declared
        ``writer_event_id`` string.  A placeholder such as ``initial-image`` or
        any other name that resolves to no write record of this stream is *not*
        a reference, so it can never certify.

    ``register``
        the writer is a ``gpio_register_commit`` of the declared component and
        register whose ``bit_resources[]`` carry an exact ``bit``, ``value``,
        integer ``version`` and integer ``observation_event_id``, and the
        consumer is a later ``gpio_register_read``/``gpio_target_receipt``
        carrying a reference row (``bit_resources[]``/``post_bit_resources[]``/
        ``dependencies[]``/``origin_refs[]``) with the same component, register,
        bit, version and observation event id.  A missing or non-integer
        version/observation event id on either side never certifies.

Every hop carries the exact join key that admitted it. An edge with only part
of its jumps keeps ``missing`` naming the first absent required hop and lists
the hops already seen. An edge whose *whole* relation has no observed shape is
``unknown`` -- explicitly ``unknown``, never zero and never ``incomplete``.

An edge whose physical endpoints were never resolved (no compiled session
document was supplied) can never certify anything, so it is reported
``unknown`` with ``unsupported_shape_reason`` naming the missing resolution --
that is a statement about this consumer's *observability*, never about the
declared path failing to exist or failing to happen.

Fail-closed journal rules (counted in ``rejections``, never silently skipped):
non-object rows, a non-integer or negative ``event_id``, a non-contiguous id
(including a repeated or regressed one), a repeat of one id with conflicting
content, a declared-edge candidate whose identity field has the wrong type, a
malformed transaction key, and a delivery whose ``producer_event_id`` names no
record of this stream. The consumer is bounded by ``max_pending`` and
``max_event_gap``; an evicted, gap-reset or already settled edge never recovers
credit from later events.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json

from .runtime_path_contract import RuntimeNode, RuntimePathContract, _canonical


EDGE_PROVENANCE_SCHEMA = "runtime_edge_provenance.v1"
EDGE_PROVENANCE_REPORT_SCHEMA = "runtime_edge_provenance_report.v1"

#: Per-edge hop identities; the order is the declared order of a certificate.
PRODUCER = "producer"
DELIVERY = "delivery"
CONSUMER = "consumer"
HOP_IDS = (PRODUCER, DELIVERY, CONSUMER)

CERTIFIED = "certified"
INCOMPLETE = "incomplete"
UNKNOWN = "unknown"

PROOF_SCOPE_CERTIFIED = "declared_edge_ids_only"
PROOF_SCOPE_PARTIAL = "partial_journal_observation"
PROOF_SCOPE_UNKNOWN = "no_observable_shape"

TRANSACTION_FIELDS = ("channel_id", "execution_id", "source_component",
                      "source_epoch", "source_sequence", "testcase_id")
TRANSACTION_INT_FIELDS = frozenset(("source_epoch", "source_sequence"))

_TRANSACTION_KEY_FIELDS = frozenset(TRANSACTION_FIELDS)

#: Consumer-side shapes of one binding delivery: interrupt/source records that
#: name the target endpoint, plus a direct consumption record of the transport.
_IRQ_CONSUMER_KINDS = frozenset((
    "cpu_irq_input", "cpu_irq_taken", "source_start", "pulse_start",
    "source_end", "pulse_expired", "expired_masked", "dataflow_consumption"))

#: Subset that may itself be the *transport* record of a declared binding: the
#: interrupt pulse events the runner emits for one driven source segment.
_PULSE_TRANSPORT_KINDS = frozenset((
    "source_start", "pulse_start", "source_end", "pulse_expired", "expired_masked"))

#: Port names whose transport is carried by those pulse records rather than by
#: a ``dataflow_delivery`` written for one sampled output segment.
_PULSE_SOURCE_PORTS = frozenset(("irq", "interrupt"))

#: Target-side observation shapes of one *data* binding: the target component's
#: own recorded input. Each carries per-bit rows whose ``origin`` cites the
#: exact ``delivery_event_id`` the bit came from, so the consumer hop of a wide
#: binding can be joined without ever relying on time adjacency.
_BINDING_OBSERVATION_KINDS = frozenset((
    "gpio_tick_observation", "gpio_input_applied", "gpio_input_segment_applied"))

#: Bounded per-event scan of those rows: a declared binding never has more
#: declared bits than this, and a malformed event may not grow the work. A row
#: list longer than the bound is only ever partially read, so a truncated scan
#: can never complete the declared window and certify.
_BINDING_ROW_LIMIT = 64

_SUPPORTED_RELATIONS = frozenset(("direct_binding", "mmio_route", "persistent_state"))

_REQUIRED_HOPS = {"direct_binding": (PRODUCER, DELIVERY, CONSUMER),
                  "mmio_route": (PRODUCER, DELIVERY),
                  "persistent_state": (PRODUCER, DELIVERY, CONSUMER)}

_SCOPE = {"direct_binding": "binding",
          "mmio_route": "route_window",
          "persistent_state": "resource_version"}

_RESOURCE_PRODUCER_KINDS = frozenset(("memory_write", "memory_write_commit",
                                      "memory_initialization"))

#: Register-file writer/reader shapes of a declared persistent resource: the
#: commit record carries the per-bit version, the read record references it.
_REGISTER_PRODUCER_KINDS = frozenset(("gpio_register_commit",))
_REGISTER_CONSUMER_KINDS = frozenset(("gpio_register_read", "gpio_target_receipt"))
#: Event fields that may cite one anchored register bit version: the read's own
#: per-bit rows, its post-read rows, and the rows nested inside them.
_REGISTER_REFERENCE_FIELDS = ("bit_resources", "post_bit_resources",
                              "dependencies", "origin_refs")
_REGISTER_NESTED_FIELDS = ("dependencies", "origin_refs")

#: Bounded, per declared persistent edge diagnostics: at most this many distinct
#: missing-field notes are retained, so one long journal cannot grow the report.
_MISSING_FIELD_LIMIT = 8

#: Bounded newest-last history of one declared persistent edge's write records.
#: A later read may reference any of them, so the history is what lets the
#: certificate name the write the read actually joined; beyond it the oldest
#: record is dropped and counted instead of being silently unavailable.
_ANCHOR_LIMIT = 256

_REJECTION_LIMIT = 64


def _nonempty_text(value) -> bool:
    return type(value) is str and bool(value) and value.strip() == value


def _count(value) -> bool:
    """Non-negative integer excluding Python booleans."""
    return type(value) is int and value >= 0


def _transaction_key(document) -> tuple | None:
    """Exact transaction key tuple; missing, extra or ill-typed fields fail."""
    if not isinstance(document, Mapping) or set(document) != _TRANSACTION_KEY_FIELDS:
        return None
    values = []
    for name in TRANSACTION_FIELDS:
        value = document[name]
        if name in TRANSACTION_INT_FIELDS:
            if not _count(value):
                return None
        elif not _nonempty_text(value):
            return None
        values.append(value)
    return tuple(values)


def _key_from_target(document) -> tuple | None:
    """Parse the exact ``repr`` a ``state_dependency`` target uses, or ``None``.

    The value must be the whole canonical ``TransactionKey(...)`` form with the
    six declared fields in order; anything else is not a key, never a guess.
    """
    if not _nonempty_text(document) or not document.startswith("TransactionKey(") \
            or not document.endswith(")"):
        return None
    body = document[len("TransactionKey("):-1]
    parsed = {}
    for item in body.split(", "):
        name, separator, raw = item.partition("=")
        if not separator or name in parsed:
            return None
        parsed[name] = raw
    if set(parsed) != set(TRANSACTION_FIELDS):
        return None
    values = []
    for name in TRANSACTION_FIELDS:
        raw = parsed[name]
        if name in TRANSACTION_INT_FIELDS:
            if not raw.isdigit():
                return None
            values.append(int(raw))
        else:
            if len(raw) < 2 or raw[0] != "'" or raw[-1] != "'" or "'" in raw[1:-1]:
                return None
            text = raw[1:-1]
            if not text or text.strip() != text:
                return None
            values.append(text)
    return tuple(values)


def _key_document(key: tuple | None):
    if key is None:
        return None
    return dict(zip(TRANSACTION_FIELDS, key))


def _version(document) -> list | None:
    if type(document) is not list or len(document) != 2 or not all(_count(v) for v in document):
        return None
    return list(document)


def _endpoint(value):
    """Normalised ``[component, port]`` endpoint or ``None``."""
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return None
    if not all(_nonempty_text(item) for item in value):
        return None
    return [value[0], value[1]]


def _binding_row_origins(event) -> list:
    """Bounded ``(row, origin)`` pairs of one target input observation.

    Only the two observed shapes are read: a tick observation keeps its input
    context under ``active_input_context.segments``, an applied-input receipt
    under ``segments``. A row without an ``origin`` mapping carries no citation
    and is not returned; nothing else in the event is inspected.
    """
    kind = event.get("kind")
    if kind == "gpio_tick_observation":
        context = event.get("active_input_context")
        segments = context.get("segments") if isinstance(context, Mapping) else None
    elif kind in _BINDING_OBSERVATION_KINDS:
        segments = event.get("segments")
    else:
        return []
    if not isinstance(segments, (list, tuple)):
        return []
    rows = []
    for row in segments[:_BINDING_ROW_LIMIT]:
        if not isinstance(row, Mapping):
            continue
        origin = row.get("origin")
        if not isinstance(origin, Mapping):
            continue
        rows.append((row, origin))
    return rows


def _binding_citations(event) -> tuple:
    """Exact delivery event ids this event's input rows cite, in row order.

    The value must be the row's own integer ``origin.delivery_event_id``; a
    missing, non-integer or duplicated id contributes nothing, and the scan is
    bounded, so one malformed event cannot grow the reference work.
    """
    citations = []
    for _row, origin in _binding_row_origins(event):
        record = origin.get("delivery_event_id")
        if _count(record) and record not in citations:
            citations.append(record)
    return tuple(citations)


def _authenticated_tick(event) -> bool:
    """The existing PULP GPIO tick authentication, imported on first use."""
    from .gpio_consumption import is_authenticated_gpio_tick
    return bool(is_authenticated_gpio_tick(event))


def _field_value(field: int, offset: int, width: int):
    if offset < 0 or width < 1 or field.bit_length() > offset + width:
        return None
    return (field >> offset) & ((1 << width) - 1)


def _output_slice(outputs, port: str, offset: int, width: int):
    """One declared bit range of a sampled output container, or ``None``.

    A container that names the declared port holds that field whole, so the
    declared bits are ``(value >> offset) & mask``; a container that yields no
    such exact integer is not evidence, and the caller keeps its hop missing.
    """
    if not isinstance(outputs, Mapping):
        return None
    if port in outputs and _count(outputs[port]):
        return _field_value(outputs[port], offset, width)
    if len(outputs) == 1:
        only = next(iter(outputs.values()))
        if _count(only):
            return _field_value(only, offset, width)
    return None


@dataclass(frozen=True)
class EdgeEndpoints:
    """Resolved physical endpoints of one declared edge.

    ``RuntimeEdgeContract`` deliberately declares relations without inventing
    endpoints for ``direct_binding``/``causal_order``; the resolved endpoints
    come from the same run's compiled topology. Both nodes must be physical, so
    a logical/state node can never masquerade as a sampled endpoint.
    """

    source: RuntimeNode
    target: RuntimeNode

    def __post_init__(self) -> None:
        for name, node in (("source", self.source), ("target", self.target)):
            if (not isinstance(node, RuntimeNode) or node.kind != "physical"
                    or node.port is None or node.width is None):
                raise ValueError(f"edge {name} endpoint must be a physical runtime node")


def edge_endpoints_from_compiled(contract: RuntimePathContract,
                                 compiled: Mapping) -> dict:
    """Resolve every declared edge endpoint from one compiled session document.

    Direct bindings are matched to their unique compiled ``Bindings`` row; MMIO
    routes take the declared initiator/router window device; persistent edges
    take the declared resource component. Missing, duplicated or inconsistent
    coordinates fail closed instead of inventing an endpoint.
    """
    if not isinstance(compiled, Mapping) or set(compiled) != {
            "schema_version", "graph_sha256", "contract_sha256", "topology_sha256",
            "topology", "paths", "proof_scope", "runtime_causality_verified",
            "resource_versions_verified", "declaration"}:
        raise ValueError("edge endpoints require a compiled session document")
    if (compiled["graph_sha256"] != contract.graph_sha256
            or compiled["contract_sha256"] != contract.identity_sha256):
        raise ValueError("compiled session document is not this contract")
    topology = compiled["topology"]
    selections = {row["path_id"]: row for row in compiled["declaration"]["selections"]}
    nodes = {}
    for row in compiled["paths"]:
        selection = selections.get(row["path_id"])
        if selection is None:
            raise ValueError("compiled path is absent from the prepared declaration")
        for edge in selection["edges"]:
            key = (edge["rule_index"], edge["prerequisite_index"])
            nodes.setdefault(key, (edge["prerequisite"], edge["target"]))
    components = {node.node_id: node.component for node in contract.nodes}
    endpoints = {}
    for declaration in contract.edges:
        key = declaration.key
        if key not in nodes:
            continue
        prerequisite, target = nodes[key]
        if declaration.relation == "direct_binding":
            source_component = components.get(prerequisite)
            target_component = components.get(target)
            rows = [row for row in topology["bindings"]
                    if row["source_component"] == source_component
                    and row["target_component"] == target_component]
            if len(rows) != 1:
                raise ValueError(f"direct edge {key} has {len(rows)} compiled bindings")
            row = rows[0]
            endpoints[key] = EdgeEndpoints(
                RuntimeNode(prerequisite, row["source_component"], "physical",
                            port=row["source_port"], bit_offset=row["source_bit_offset"],
                            width=row["width"]),
                RuntimeNode(target, row["target_component"], "physical",
                            port=row["target_port"], bit_offset=row["target_bit_offset"],
                            width=row["width"]))
        elif declaration.relation == "mmio_route":
            routers = [row for row in topology["routers"]
                       if row["initiator"] == declaration.initiator_component]
            windows = ([window for window in routers[0]["windows"]
                        if window["device_id"] == declaration.device_id]
                       if len(routers) == 1 else [])
            if len(windows) != 1 or windows[0]["base"] != declaration.base \
                    or windows[0]["size"] != declaration.size:
                raise ValueError(f"MMIO edge {key} has no unique declared window")
            endpoints[key] = EdgeEndpoints(
                RuntimeNode(prerequisite, declaration.initiator_component, "physical",
                            port="mmio", bit_offset=declaration.base,
                            width=declaration.size),
                RuntimeNode(target, declaration.device_id, "physical",
                            port="mmio", bit_offset=declaration.base,
                            width=declaration.size))
        elif declaration.relation == "persistent_state":
            component = declaration.resource_component
            if component not in (components.get(prerequisite), components.get(target)):
                raise ValueError(f"persistent edge {key} resource outside declared edge")
            endpoints[key] = EdgeEndpoints(
                RuntimeNode(prerequisite, component, "physical", port=declaration.resource_id,
                            bit_offset=0, width=1),
                RuntimeNode(target, component, "physical", port=declaration.resource_id,
                            bit_offset=0, width=1))
    return endpoints


class EdgeProvenanceConsumer:
    """Bounded, incremental, fail-closed per-edge provenance consumer.

    ``ingest`` returns certificates for the edges that settled while consuming
    the slice; ``report`` renders every declared edge of the contract.
    """

    def __init__(self, contract: RuntimePathContract, *,
                 endpoints: Mapping | None = None,
                 max_pending: int = 4096, max_event_gap: int = 65536,
                 candidate_resolver=None) -> None:
        if not isinstance(contract, RuntimePathContract):
            raise ValueError("edge provenance requires a RuntimePathContract")
        if not _count(max_pending) or max_pending < 1:
            raise ValueError("edge provenance max_pending must be a positive integer")
        if not _count(max_event_gap) or max_event_gap < 1:
            raise ValueError("edge provenance max_event_gap must be a positive integer")
        if candidate_resolver is not None and not callable(candidate_resolver):
            raise ValueError("edge provenance candidate resolver must be callable")
        self.contract = contract
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        #: Optional pure per-event callable returning extra declared-edge
        #: candidates. It only *adds* candidates to the ones the journal already
        #: carries (a journal written before an edge was declared cannot name
        #: it), and every candidate it returns goes through the same
        #: declaration/malformed-identity checks as a journal candidate.
        self._candidate_resolver = candidate_resolver
        self._declarations = {edge.key: edge for edge in contract.edges}
        self._hint_limit = max(1024, max_pending * 64)
        self._endpoints = {}
        if endpoints is not None:
            if not isinstance(endpoints, Mapping):
                raise ValueError("edge provenance endpoints must be a mapping")
            for key, value in endpoints.items():
                if key not in self._declarations:
                    raise ValueError(f"endpoints declare unknown edge {key}")
                if not isinstance(value, EdgeEndpoints):
                    raise ValueError("edge endpoints must be EdgeEndpoints records")
                self._endpoints[key] = value
        self._unsupported = {key: edge.relation for key, edge in self._declarations.items()
                             if edge.relation not in _SUPPORTED_RELATIONS}
        self._missing_endpoints = {key: edge.relation
                                   for key, edge in self._declarations.items()
                                   if edge.relation not in self._unsupported
                                   and key not in self._endpoints}
        self._reset_state()

    # ------------------------------------------------------------ state model
    def _reset_state(self) -> None:
        self._active: dict[tuple[int, int], dict] = {}
        self._order: list[tuple[int, int]] = []
        self._archived: dict[tuple[int, int], dict] = {}
        self._blocked: set[tuple[int, int]] = set()
        self._final: set[tuple[int, int]] = set()
        self._certificates: list[dict] = []
        self._reported_certificates = 0
        self._rejections: list[dict] = []
        self._records: dict[int, dict] = {}
        self._digests: dict[int, str] = {}
        self._last_event_id = 0
        self._events_rejected = 0
        self._evictions = 0
        self._resets = 0
        self._events_observed = 0
        self._dropped_late_hops = 0
        self._producer_hints: dict[int, list] = {}
        self._deferred_hints: set[int] = set()
        self._pending_hints = 0
        self._max_reference = 0
        self._latest_record_id = 0
        #: Bounded per declared persistent edge observation ledger: one record
        #: per *declared* edge, so a long journal cannot grow it.
        self._shape_ledger = {}

    def reset(self) -> None:
        """Drop every partial observation and restart id continuity at zero."""
        self._reset_state()

    # --------------------------------------------------------------- counters
    @property
    def pending_count(self) -> int:
        return len(self._active)

    @property
    def last_event_id(self) -> int:
        return self._last_event_id

    @property
    def events_observed(self) -> int:
        return self._events_observed

    @property
    def events_rejected(self) -> int:
        return self._events_rejected

    @property
    def evictions(self) -> int:
        return self._evictions

    @property
    def resets(self) -> int:
        return self._resets

    @property
    def dropped_late_hops(self) -> int:
        return self._dropped_late_hops

    @property
    def pending_hint_count(self) -> int:
        """Bound on record ids retained only to join candidate-less events."""
        return self._pending_hints

    @property
    def rejections(self) -> tuple[dict, ...]:
        return tuple(deepcopy(row) for row in self._rejections)

    @property
    def certificates(self) -> tuple[dict, ...]:
        return tuple(deepcopy(row) for row in self._certificates)

    def endpoints_for(self, key):
        return self._endpoints.get(key)

    # --------------------------------------------------------------- ingestion
    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        """Consume the next contiguous slice and return newly settled edges.

        The slice may be a lazily streamed journal: every event registers the
        declared edges it *names* (its own ``edge_candidates`` and the
        ``producer_event_id``/``source_event_id`` records it refers to), and any
        record whose edge identity becomes known later still has the hops it
        already carries attributed to that edge. A sampled tick record never
        carries ``edge_candidates`` of its own, so this exact reference chain is
        the only join that attributes it to a declared edge.
        """
        produced = []
        for event in events:
            self._events_observed += 1
            if isinstance(event, Mapping):
                self._register_hints((event,))
            certificate = self._consume(event)
            if certificate is not None:
                produced.append(certificate)
            else:
                # ``_observe`` settles edges whose referenced records it just
                # attributed; surface those certificates too.
                produced.extend(self._settled_certificates())
            produced.extend(self._drain_pending_hints())
        return tuple(produced)

    def _settled_certificates(self) -> list:
        """Certificates produced since the last call, newest last."""
        produced = self._certificates[self._reported_certificates:]
        self._reported_certificates = len(self._certificates)
        return produced

    def _register_hints(self, events) -> None:
        """Register the edges these events name and defer unknown references."""
        for event in events:
            if not isinstance(event, Mapping):
                continue
            event_id = event.get("event_id")
            keys = []
            for candidate in self._candidates_of(event):
                declaration = self._declared_quietly(candidate)
                if declaration is not None and declaration.key not in keys:
                    keys.append(declaration.key)
            if not keys:
                # A record with no candidates of its own inherits the edges of
                # whatever it references, once those references are known: the
                # records it names as producer/source, and the delivery its own
                # target input rows cite as their exact ``delivery_event_id``.
                for record in self._references_of(event):
                    for key in self._producer_hints.get(record, ()):
                        if key not in keys:
                            keys.append(key)
                if keys and _count(event_id):
                    self._remember_hint(event_id, keys)
                continue
            if not _count(event_id):
                continue
            self._remember_hint(event_id, keys)
            for name in ("producer_event_id", "source_event_id"):
                record = event.get(name)
                if not _count(record):
                    continue
                known = record in self._producer_hints
                self._remember_hint(record, keys)
                if record not in self._records:
                    # Its own record has not been seen yet: wait for it.
                    self._deferred_hints.add(record)
                elif not known:
                    # Its record was already consumed, but now an edge-bearing
                    # event names it: attach its hops retroactively.
                    self._deferred_hints.add(record)

    def _drain_pending_hints(self) -> list:
        """Attribute hops of records whose edge identity became known in time.

        Only records that were named by an edge-bearing event before they were
        consumed are reconsidered, so the work stays proportional to the number
        of deferred references instead of the whole journal.
        """
        if not self._deferred_hints:
            return []
        pending = sorted(self._deferred_hints)
        self._deferred_hints.clear()
        produced = []
        for record_id in pending:
            record = self._records.get(record_id)
            if record is None:
                # Its own record has not been consumed yet: keep waiting.
                self._deferred_hints.add(record_id)
                continue
            produced.extend(self._attach_hint_record(record_id, record))
        return produced

    def _attach_hint_record(self, record_id: int, record: Mapping) -> list:
        produced = []
        for key in self._producer_hints.get(record_id, ()):
            if key in self._final or key in self._blocked:
                continue
            if self._endpoints.get(key) is None:
                continue
            state = self._active.get(key)
            if state is None:
                declaration = self._declarations.get(key)
                if declaration is None:
                    continue
                state = self._open(key, declaration)
            if state["event_id"] is not None and record_id <= state["event_id"]:
                continue
            self._attach(state, record_id, record)
            produced.extend(self._settle_ready_all())
        return produced

    def _candidates_of(self, event: Mapping):
        """Declared edge candidates carried by one event, possibly empty.

        A caller-supplied resolver may *add* candidates for declarations the
        journal itself predates. Candidates the journal already carries keep
        their order and are never dropped; a resolver must be pure and cheap,
        because it is consulted once while registering hints and once while
        observing the same event.
        """
        provenance = event.get("provenance")
        candidates = provenance.get("edge_candidates") if isinstance(provenance, Mapping) else None
        if candidates is None:
            candidates = event.get("edge_candidates")
        if not isinstance(candidates, (list, tuple)):
            candidates = ()
        if self._candidate_resolver is None:
            return candidates
        extra = self._candidate_resolver(event)
        if not isinstance(extra, (list, tuple)) or not extra:
            return candidates
        merged = list(candidates)
        for candidate in extra:
            if candidate not in merged:
                merged.append(candidate)
        return tuple(merged)

    def _references_of(self, event: Mapping) -> tuple:
        """Every record id one event references, in declared order and bounded.

        The ``producer_event_id``/``source_event_id`` ids the journal has always
        carried come first, then the delivery ids the event's own target input
        rows cite. Only those ids are ever resolved against the hint map, so a
        citation that names no record of this stream -- or a citation beyond the
        bounded row scan -- contributes no edge identity instead of a guess.
        """
        references = []
        for name in ("producer_event_id", "source_event_id"):
            record = event.get(name)
            if _count(record) and record not in references:
                references.append(record)
        for record in _binding_citations(event):
            if record not in references:
                references.append(record)
        return tuple(references)

    def _remember_hint(self, record_id: int, keys) -> None:
        """Record ids one candidate-bearing event proves, never a guessed key.

        The map is bounded by ``max_pending * 64`` entries (at least 1024) and
        is trimmed oldest-first only under that pressure; a trimmed reference
        simply stops attaching hops instead of inventing an edge identity.
        """
        edges = self._producer_hints.setdefault(record_id, [])
        for key in keys:
            if key not in edges:
                edges.append(key)
        self._max_reference = max(self._max_reference, record_id)
        if record_id in self._records:
            self._deferred_hints.add(record_id)
        limit = self._hint_limit
        while len(self._producer_hints) > limit:
            del self._producer_hints[min(self._producer_hints)]
        self._pending_hints = len(self._producer_hints)

    def _reject(self, reason: str, *, event_id, kind=None) -> None:
        self._events_rejected += 1
        if len(self._rejections) < _REJECTION_LIMIT:
            self._rejections.append({"reason": reason, "event_id": event_id,
                                     "kind": kind})

    def _consume(self, event) -> dict | None:
        if not isinstance(event, Mapping):
            self._reject("non_object_event", event_id=None)
            return None
        event_id = event.get("event_id")
        if not _count(event_id):
            self._reject("non_integer_event_id", event_id=event_id, kind=event.get("kind"))
            return None
        if event_id <= self._last_event_id:
            self._reject("repeated_event_id", event_id=event_id, kind=event.get("kind"))
            return None
        if event_id != self._last_event_id + 1:
            # Fail closed, count it, and continue from this id so one gap does
            # not cascade into a rejection of every later record.
            self._reject("non_contiguous_event_id", event_id=event_id, kind=event.get("kind"))
            self._last_event_id = event_id
            self._observe(event_id, event)
            return None
        self._last_event_id = event_id
        digest = hashlib.sha256(_canonical(dict(event))).hexdigest()
        previous = self._digests.get(event_id)
        if previous is not None and previous != digest:
            self._reject("content_conflict", event_id=event_id, kind=event.get("kind"))
            return None
        self._digests[event_id] = digest
        self._observe(event_id, event)
        settled = self._settle_ready_all()
        return settled[-1] if settled else None

    def _observe(self, event_id: int, event: Mapping) -> None:
        self._records[event_id] = dict(event)
        self._latest_record_id = event_id
        self._expire(event_id)
        self._expire_records(event_id)
        # Direct candidates and the edges this event's own reference names: an
        # event that proves a declared edge may itself be the referenced record
        # of that edge (the delivery names its producer, the CPU interrupt
        # record names its source pulse), so both keys are attached in the
        # declared order before anything is settled.
        keys = []
        for candidate in self._candidates_of(event):
            declaration = self._declared(candidate, event_id, event.get("kind"))
            if declaration is not None and declaration.key not in keys:
                keys.append(declaration.key)
        for record in self._references_of(event):
            for key in self._producer_hints.get(record, ()):
                if key not in keys:
                    keys.append(key)
        for key in self._producer_hints.get(event_id, ()):
            if key not in keys:
                keys.append(key)
        if not keys:
            return
        # A record this event references may already be consumed while its own
        # edge identity was still unknown. Attaching it first gives the current
        # event the exact anchor it must join to (a delivery needs the producer
        # record of its ``producer_event_id``).
        for name in ("producer_event_id", "source_event_id"):
            record = event.get(name)
            if not _count(record) or record == event_id:
                continue
            referenced = self._records.get(record)
            if referenced is not None and record in self._deferred_hints:
                self._deferred_hints.discard(record)
                self._attach_hint_record(record, referenced)
        for key in sorted(keys):
            if key not in self._declarations:
                continue
            if self._declarations[key].relation == "persistent_state":
                # The ledger describes what this journal itself showed, so it is
                # counted even after the edge settled; it stays one row per
                # declared edge.
                self._observe_resource_shape(key, event)
            if key in self._final or key in self._blocked:
                self._dropped_late_hops += 1
                continue
            if self._endpoints.get(key) is None:
                # No resolved physical endpoints: never guess a hop join.
                self._dropped_late_hops += 1
                continue
            state = self._active.get(key)
            if state is None:
                state = self._open(key, self._declarations[key])
            last = state["event_id"]
            if last is not None and event_id <= last:
                self._dropped_late_hops += 1
                continue
            self._attach(state, event_id, event)
        self._settle_ready_all()

    def _declared(self, candidate, event_id=None, kind=None):
        """Resolve one edge identity, counting a malformed candidate once.

        Hint registration uses :meth:`_declared_quietly` so the same malformed
        candidate is never counted twice for one event id.
        """
        declaration, malformed = self._resolve_declared(candidate)
        if malformed:
            self._reject("invalid_identity_field", event_id=event_id, kind=kind)
        return declaration

    def _declared_quietly(self, candidate):
        return self._resolve_declared(candidate)[0]

    def _resolve_declared(self, candidate):
        """Return ``(declaration, malformed)`` for one candidate row."""
        if not isinstance(candidate, Mapping):
            return None, True
        rule_index = candidate.get("rule_index")
        prerequisite_index = candidate.get("prerequisite_index")
        if type(rule_index) is not int or type(prerequisite_index) is not int:
            return None, rule_index is not None or prerequisite_index is not None
        return self._declarations.get((rule_index, prerequisite_index)), False

    def _open(self, key, declaration) -> dict:
        state = {"key": key, "declaration": declaration,
                 "endpoints": self._endpoints.get(key),
                 "event_id": None, "hops": {}, "handled": set(),
                 "consumer_event_id": None,
                 "anchor_record_id": None, "driver_event_id": None,
                 "delivery_value": None,
                 "target_value": None, "transaction": None, "version": None,
                 "observation_event_id": None, "writer_event_id": None,
                 "source_reference": None, "delivery_event_id": None,
                 "resource_kind": None, "write_span": None,
                 "register_bits": None, "anchors": [], "anchor": None}
        self._active[key] = state
        self._order.append(key)
        self._evict_over_capacity()
        return state

    def _shape_for(self, key) -> dict:
        """This edge's ledger row; one row per declared persistent edge."""
        return self._shape_ledger.setdefault(key, self._new_shape())

    @staticmethod
    def _new_shape() -> dict:
        """Bounded observation shape of one declared persistent edge."""
        return {"writer_records": 0, "reader_records": 0, "dropped_anchors": 0,
                "reader_reference_forms": {"event_id": 0, "transaction_key": 0,
                                           "declared_writer_id": 0,
                                           "placeholder": 0},
                "missing_fields": []}

    def _evict_over_capacity(self) -> None:
        while len(self._active) > self.max_pending:
            key = self._order.pop(0)
            state = self._active.pop(key, None)
            if state is None:
                continue
            self._evictions += 1
            self._blocked.add(key)
            self._archived[key] = self._archive(state, INCOMPLETE, "pending_capacity",
                                                event_id=state["event_id"])

    def _archive(self, state: dict, decision: str, reason: str,
                 event_id=None) -> dict:
        """Freeze one edge's observed hops; later events never add to it."""
        return {"key": state["key"], "declaration": state["declaration"],
                "endpoints": state.get("endpoints"),
                "hops": deepcopy(state.get("hops", {})),
                "handled": set(state.get("handled", ())),
                "references": self._references(state),
                "transaction": state.get("transaction"),
                "version": state.get("version"),
                "observation_event_id": state.get("observation_event_id"),
                "writer_event_id": state.get("writer_event_id"),
                "resource_kind": state.get("resource_kind"),
                "decision": decision, "reason": reason,
                "event_id": state.get("event_id") if event_id is None else event_id}

    def _expire(self, event_id: int) -> None:
        limit = event_id - self.max_event_gap
        stale = [key for key in self._order
                 if self._active.get(key, {}).get("event_id") is not None
                 and self._active[key]["event_id"] < limit]
        for key in stale:
            state = self._active.pop(key, None)
            self._order.remove(key)
            if state is None:
                continue
            self._blocked.add(key)
            self._archived[key] = self._archive(state, INCOMPLETE, "event_gap_reset",
                                                event_id=state["event_id"])
        if stale:
            self._resets += 1

    def _expire_records(self, event_id: int) -> None:
        limit = event_id - self.max_event_gap
        for stored in [key for key in self._records if key < limit]:
            del self._records[stored]
        for stored in [key for key in self._digests if key < limit]:
            del self._digests[stored]

    # ------------------------------------------------------------------- hops
    def _attach(self, state: dict, event_id: int, event: Mapping) -> None:
        if event_id in state["handled"]:
            # One record is attached to an edge at most once, whatever path
            # admitted it (declared candidate or deferred reference).
            return
        state["handled"].add(event_id)
        relation = state["declaration"].relation
        if relation == "direct_binding":
            if PRODUCER not in state["hops"]:
                evidence = self._match_driver(state, event_id, event)
                if evidence is not None:
                    self._record_hop(state, PRODUCER, event_id, evidence)
            if DELIVERY not in state["hops"]:
                evidence = self._match_binding_delivery(state, event_id, event)
                if evidence is not None:
                    self._record_hop(state, DELIVERY, event_id, evidence)
            if CONSUMER not in state["hops"]:
                evidence = self._match_target(state, event_id, event)
                if evidence is not None:
                    self._record_hop(state, CONSUMER, event_id, evidence)
                else:
                    # A wide data binding has no interrupt record at the
                    # target: its consumer is the target's own input
                    # observation, admitted only when it cites the exact
                    # delivery it consumed.
                    joined = self._match_binding_consumer(state, event_id, event)
                    if joined is not None:
                        self._join_cited_binding(state, joined, event_id, event)
        elif relation == "mmio_route":
            if PRODUCER not in state["hops"]:
                evidence = self._match_route_acceptance(state, event_id, event)
                if evidence is not None:
                    self._record_hop(state, PRODUCER, event_id, evidence)
            if DELIVERY not in state["hops"]:
                evidence = self._match_route_delivery(state, event_id, event)
                if evidence is not None:
                    self._record_hop(state, DELIVERY, event_id, evidence)
            if CONSUMER not in state["hops"]:
                evidence = self._match_route_consumer(state, event_id, event)
                if evidence is not None:
                    self._record_hop(state, CONSUMER, event_id, evidence)
        elif relation == "persistent_state":
            record = self._match_resource_producer(state, event_id, event)
            if record is not None:
                self._retain_anchor(state, record)
                if PRODUCER not in state["hops"]:
                    # The first retained write is the edge's declared producer;
                    # a read that later joins a different retained write moves
                    # all three hops onto that write together.
                    self._anchor(state, record)
                    self._record_hop(state, PRODUCER, record["event_id"],
                                     record["producer_evidence"])
                    self._record_hop(state, DELIVERY, record["event_id"],
                                     self._resource_version_evidence(state))
            if CONSUMER not in state["hops"]:
                matched = self._match_resource_consumer(state, event_id, event)
                if matched is not None:
                    anchor, evidence = matched
                    if anchor is not state.get("anchor"):
                        # The read referenced a *different* retained write of the
                        # same resource: its own exact record becomes the
                        # certificate's producer and delivery hop, so the three
                        # hops always describe one joined version.
                        self._anchor(state, anchor)
                        self._record_hop(state, PRODUCER, anchor["event_id"],
                                         anchor["producer_evidence"])
                        self._record_hop(state, DELIVERY, anchor["event_id"],
                                         self._resource_version_evidence(state))
                    self._record_hop(state, CONSUMER, event_id, evidence)
                    state["observation_event_id"] = event_id

    def _retain_anchor(self, state: dict, record: dict) -> None:
        """Keep a bounded newest-last history of this edge's write records.

        A later read may reference any retained write of the resource, so the
        history is what makes the certificate name the write the read actually
        joined. The history is bounded; a dropped anchor is counted and noted as
        a missing field instead of being silently unavailable.
        """
        anchors = state["anchors"]
        anchors.append(record)
        if len(anchors) > _ANCHOR_LIMIT:
            anchors.pop(0)
            self._shape_for(state["key"])["dropped_anchors"] += 1
            self._note_missing(state,
                               "persistent_state retained writer records exceeded "
                               f"{_ANCHOR_LIMIT}")

    def _anchor(self, state: dict, record: dict) -> None:
        """Make one retained write record the edge's current version anchor."""
        state["anchor"] = record
        state["resource_kind"] = record["resource_kind"]
        state["anchor_record_id"] = record["event_id"]
        state["version"] = record.get("version")
        state["writer_event_id"] = record.get("declared_writer_id")
        state["write_span"] = record.get("write_span")
        state["transaction_key"] = record.get("transaction_key")
        state["register_bits"] = record.get("register_bits")

    def _record_hop(self, state: dict, hop_id: str, event_id: int, evidence: dict) -> None:
        state["hops"][hop_id] = {"hop_id": hop_id, "event_id": event_id,
                                 "evidence": dict(evidence)}
        state["event_id"] = event_id

    # -- direct_binding -------------------------------------------------------
    def _match_driver(self, state: dict, event_id: int, event: Mapping) -> dict | None:
        endpoints = state["endpoints"]
        node, target = endpoints.source, endpoints.target
        kind = event.get("kind")
        if event.get("component") != node.component and not (
                kind in _IRQ_CONSUMER_KINDS and event.get("source") is not None):
            return None
        producer = event.get("producer_event_id")
        if producer is not None and not _count(producer):
            self._reject("invalid_identity_field", event_id=event_id, kind=event.get("kind"))
            return None
        if _count(producer) and producer not in self._records:
            self._reject("unknown_producer_reference", event_id=event_id, kind=event.get("kind"))
            return None
        if event_id in (state["driver_event_id"], state["delivery_event_id"],
                        state["consumer_event_id"]):
            return None
        if kind in ("local_tick_sample", "gpio_tick_observation"):
            value = _output_slice(event.get("outputs"), node.port, node.bit_offset, node.width)
            if value is None:
                return None
            state["anchor_record_id"] = event_id
            state["driver_event_id"] = event_id
            return {"key": "endpoint_output", "component": node.component, "port": node.port,
                    "bit_offset": node.bit_offset, "width": node.width,
                    "producer_event_id": event_id, "value": value,
                    "local_tick": event.get("local_tick")}
        if kind in _IRQ_CONSUMER_KINDS and (event.get("source_event_id") is not None
                                           or event.get("target") is not None):
            link = event.get("source_event_id")
            if not _count(link):
                self._reject("invalid_identity_field", event_id=event_id, kind=kind)
                return None
            if link not in self._records:
                self._reject("unknown_producer_reference", event_id=event_id, kind=kind)
                return None
            source = _endpoint(event.get("source"))
            if source is None or source != [node.component, node.port]:
                return None
            if (event.get("source_bit_offset"), event.get("width")) != (node.bit_offset, node.width):
                return None
            state["anchor_record_id"] = link
            state["driver_event_id"] = event_id
            return {"key": "source_event_id", "component": node.component, "port": node.port,
                    "bit_offset": node.bit_offset, "width": node.width,
                    "producer_event_id": link, "event_id": event_id,
                    "value": event.get("value"), "local_tick": event.get("local_tick")}
        return None

    def _match_binding_delivery(self, state: dict, event_id: int, event: Mapping) -> dict | None:
        """The transport record between the declared endpoints.

        Either a ``dataflow_delivery`` whose ``producer_event_id`` names the
        observed driver record, or an interrupt/source pulse record naming that
        same ``source_event_id`` (the pulse is the declared transport, the
        sampled driver record the value's producer).
        """
        kind = event.get("kind")
        if state["anchor_record_id"] is None or event_id in (state["driver_event_id"],
                                                             state["delivery_event_id"]):
            return None
        if kind not in ("dataflow_delivery", *_PULSE_TRANSPORT_KINDS):
            return None
        endpoints = state["endpoints"]
        node, target = endpoints.source, endpoints.target
        if kind != "dataflow_delivery" and node.port not in _PULSE_SOURCE_PORTS:
            # A pulse record only transports an interrupt-style source line.
            return None
        source = _endpoint(event.get("source"))
        delivered = _endpoint(event.get("target"))
        if source is None or delivered is None:
            return None
        if source != [node.component, node.port] or delivered != [target.component, target.port]:
            return None
        if (event.get("source_bit_offset"), event.get("target_bit_offset"),
                event.get("width")) != (node.bit_offset, target.bit_offset, node.width):
            return None
        if kind == "dataflow_delivery":
            link_name = "producer_event_id"
            link = event.get("producer_event_id")
            value = event.get("value")
            if not _count(value):
                self._reject("invalid_identity_field", event_id=event_id, kind=kind)
                return None
        else:
            link_name = "source_event_id"
            link = event.get("source_event_id")
            value = event.get("value")
            if not _count(link):
                return None
            if link not in self._records:
                self._reject("unknown_producer_reference", event_id=event_id, kind=kind)
                return None
        if not _count(link):
            self._reject("invalid_identity_field", event_id=event_id, kind=kind)
            return None
        if link not in self._records:
            self._reject("unknown_producer_reference", event_id=event_id, kind=kind)
            return None
        if link not in (state["anchor_record_id"], state["driver_event_id"]):
            return None
        hop = state["hops"].get(PRODUCER)
        seen = hop["evidence"].get("value") if hop else None
        if _count(value) and _count(seen) and value != seen:
            return None
        target_value = event.get("target_value")
        if _count(value):
            state["delivery_value"] = value
        state["target_value"] = target_value if _count(target_value) else state["target_value"]
        state["delivery_event_id"] = event_id
        return {"key": link_name, "source": source, "target": delivered,
                "source_bit_offset": node.bit_offset, "target_bit_offset": target.bit_offset,
                "width": node.width, "value": value,
                "chain": {link_name: link}}

    def _match_target(self, state: dict, event_id: int, event: Mapping) -> dict | None:
        if event.get("kind") not in _IRQ_CONSUMER_KINDS:
            return None
        if event_id in (state["driver_event_id"], state["delivery_event_id"],
                        state["consumer_event_id"]):
            return None
        endpoints = state["endpoints"]
        node, target = endpoints.source, endpoints.target
        delivered = _endpoint(event.get("target"))
        if delivered is None or delivered != [target.component, target.port]:
            return None
        observed_source = _endpoint(event.get("source"))
        if observed_source is not None and observed_source != [node.component, node.port]:
            return None
        if (event.get("target_bit_offset"), event.get("width")) != (target.bit_offset, target.width):
            return None
        value = event.get("value")
        expected = state["delivery_value"]
        if expected is None:
            expected = state["target_value"]
        if not _count(value):
            return None
        if _count(expected) and value != expected:
            return None
        link = event.get("source_event_id")
        if link is not None and not _count(link):
            self._reject("invalid_identity_field", event_id=event_id, kind=event.get("kind"))
            return None
        if _count(link):
            if link not in (state["anchor_record_id"], state["driver_event_id"],
                            state["delivery_event_id"]):
                return None
            key = "source_event_id+endpoint+value"
        else:
            key = "endpoint+target_value"
        state["consumer_event_id"] = event_id
        return {"key": key, "source": observed_source,
                "target": delivered, "target_bit_offset": target.bit_offset,
                "width": event.get("width"), "value": value, "source_event_id": link,
                "local_tick": event.get("local_tick")}

    def _declares_key(self, record: Mapping, key) -> bool:
        """Whether one stored record itself names this declared edge.

        The record's *own* candidates are judged (the journal's, or the ones a
        caller-supplied resolver adds); an edge identity another event merely
        attached to it is not enough to make it this edge's transport.
        """
        for candidate in self._candidates_of(record):
            declaration = self._declared_quietly(candidate)
            if declaration is not None and declaration.key == key:
                return True
        return False

    def _observed_driver_value(self, state: dict, record: Mapping):
        """The declared source slice one stored driver record observed, or ``None``.

        The same exact-fit rule the driver hop itself uses: the record must be a
        sample of the declared source component whose container names the
        declared port (or is its sole field) without carrying bits above the
        declared window.
        """
        node = state["endpoints"].source
        if record.get("component") != node.component:
            return None
        if record.get("kind") not in ("local_tick_sample", "gpio_tick_observation"):
            return None
        return _output_slice(record.get("outputs"), node.port, node.bit_offset, node.width)

    def _consumed_window(self, state: dict, rows):
        """The declared target window the cited rows reconstruct, or ``None``.

        Every cited row must name the declared source endpoint with the same
        relative bit position as its target bit, and the rows must cover the
        declared window exactly once. A gap, an overlap, an out-of-window bit or
        a value wider than its own row is refused instead of being summed into a
        plausible value.
        """
        node, target = state["endpoints"].source, state["endpoints"].target
        covered = {}
        for row, origin in rows:
            if origin.get("kind") != "binding":
                return None
            if (origin.get("source_component"), origin.get("source_port")) != (
                    node.component, node.port):
                return None
            bit_lo, width, value = row.get("bit_lo"), row.get("width"), row.get("value")
            source_lo = origin.get("source_bit_lo")
            if (not _count(bit_lo) or not _count(width) or width < 1
                    or not _count(value) or value >> width
                    or not _count(source_lo)):
                return None
            offset = bit_lo - target.bit_offset
            if offset < 0 or offset + width > target.width:
                return None
            if source_lo - node.bit_offset != offset:
                return None
            for index in range(width):
                if offset + index in covered:
                    return None
                covered[offset + index] = (value >> index) & 1
        if len(covered) != target.width:
            return None
        return sum(covered[index] << index for index in range(target.width))

    def _measured_window(self, state: dict, measured, consumed) -> bool:
        """The target's own measured input window equals the joined value."""
        target = state["endpoints"].target
        if not isinstance(measured, Mapping):
            return False
        observed = measured.get("gpio_in")
        if not _count(observed):
            observed = measured.get("actual_input_value")
        if not _count(observed):
            return False
        return ((observed >> target.bit_offset)
                & ((1 << target.width) - 1)) == consumed

    def _match_binding_consumer(self, state: dict, event_id: int, event: Mapping):
        """The target's own input observation citing one delivery exactly.

        Only the *cited* transport is credited. The row's
        ``origin.delivery_event_id`` must name a ``dataflow_delivery`` record
        that itself declares this edge, carries the declared endpoints and bit
        range, and whose own ``producer_event_id`` names a driver record that
        observed the same declared source slice; the rows must cover the
        declared target window exactly once and reconstruct that value, and the
        target's own measured input window must equal it too. Time adjacency
        proves nothing here: without a citation the hop stays missing.
        """
        kind = event.get("kind")
        if kind not in _BINDING_OBSERVATION_KINDS:
            return None
        if event_id in (state["driver_event_id"], state["delivery_event_id"],
                        state["consumer_event_id"]):
            return None
        endpoints = state["endpoints"]
        node, target = endpoints.source, endpoints.target
        if event.get("component") != target.component:
            return None
        measured = event
        if kind == "gpio_tick_observation":
            # The existing authentication entry: an unauthenticated pre/post
            # probe pair is never evidence of what the target consumed.
            if not _authenticated_tick(event):
                return None
            measured = event.get("post")
        elif event.get("status") is not None and event.get("status") != "observed":
            return None
        port = event.get("port")
        if port is not None and port != target.port:
            return None
        cited = {}
        for row, origin in _binding_row_origins(event):
            record = origin.get("delivery_event_id")
            if not _count(record):
                continue
            cited.setdefault(record, []).append((row, origin))
        for delivery_id in sorted(cited):
            record = self._records.get(delivery_id)
            if not isinstance(record, Mapping) \
                    or record.get("kind") != "dataflow_delivery":
                continue
            if not self._declares_key(record, state["key"]):
                continue
            if (_endpoint(record.get("source")) != [node.component, node.port]
                    or _endpoint(record.get("target")) != [target.component, target.port]
                    or (record.get("source_bit_offset"), record.get("target_bit_offset"),
                        record.get("width"))
                    != (node.bit_offset, target.bit_offset, target.width)):
                continue
            value = record.get("value")
            if not _count(value):
                continue
            driver_id = record.get("producer_event_id")
            if not _count(driver_id) or driver_id == event_id:
                continue
            driver_record = self._records.get(driver_id)
            if not isinstance(driver_record, Mapping):
                continue
            driver_value = self._observed_driver_value(state, driver_record)
            if driver_value is None or driver_value != value:
                continue
            consumed = self._consumed_window(state, cited[delivery_id])
            if consumed is None or consumed != value:
                continue
            if not self._measured_window(state, measured, consumed):
                continue
            return {"delivery_event_id": delivery_id, "delivery": record,
                    "driver_event_id": driver_id, "driver": driver_record,
                    "value": consumed, "rows": len(cited[delivery_id])}
        return None

    def _join_cited_binding(self, state: dict, joined: dict, event_id: int,
                            event: Mapping) -> None:
        """Move all three hops onto the chain the target actually cited.

        The cited delivery's own ``producer_event_id`` names the driver record
        it transported, and that record's declared source slice equals the
        delivery's value, so ``producer``/``delivery`` move onto that one joined
        chain instead of the first chain the journal happened to observe. The
        consumer hop then carries the citation itself, which is what the
        certificate's exact join rests on.
        """
        node, target = state["endpoints"].source, state["endpoints"].target
        record = joined["delivery"]
        driver_id = joined["driver_event_id"]
        state["anchor_record_id"] = driver_id
        state["driver_event_id"] = driver_id
        state["delivery_event_id"] = joined["delivery_event_id"]
        state["delivery_value"] = record.get("value")
        target_value = record.get("target_value")
        if _count(target_value):
            state["target_value"] = target_value
        self._record_hop(state, PRODUCER, driver_id, {
            "key": "endpoint_output", "component": node.component, "port": node.port,
            "bit_offset": node.bit_offset, "width": node.width,
            "producer_event_id": driver_id, "value": joined["value"],
            "local_tick": joined["driver"].get("local_tick"),
            "joined_by": "target_input_observation"})
        self._record_hop(state, DELIVERY, joined["delivery_event_id"], {
            "key": "producer_event_id", "source": [node.component, node.port],
            "target": [target.component, target.port],
            "source_bit_offset": node.bit_offset, "target_bit_offset": target.bit_offset,
            "width": node.width, "value": record.get("value"),
            "chain": {"producer_event_id": driver_id},
            "joined_by": "target_input_observation"})
        self._record_hop(state, CONSUMER, event_id, {
            "key": "delivery_event_id+window_value",
            "observation": event.get("kind"), "component": event.get("component"),
            "source": [node.component, node.port],
            "target": [target.component, target.port],
            "source_bit_offset": node.bit_offset, "target_bit_offset": target.bit_offset,
            "width": target.width, "value": joined["value"],
            "delivery_event_id": joined["delivery_event_id"],
            "delivery_value": record.get("value"), "driver_event_id": driver_id,
            "segments": joined["rows"], "explicit_delivery_reference": True,
            "local_tick": event.get("local_tick")})
        state["consumer_event_id"] = event_id

    # -- mmio_route -----------------------------------------------------------
    def _match_route_acceptance(self, state: dict, event_id: int, event: Mapping) -> dict | None:
        if event.get("kind") != "mmio_acceptance":
            return None
        declaration = state["declaration"]
        if event.get("device_id") != declaration.device_id:
            return None
        transaction = _transaction_key(event.get("source_transaction"))
        if transaction is None:
            self._reject("invalid_identity_field", event_id=event_id, kind="mmio_acceptance")
            return None
        if transaction[2] != declaration.initiator_component:
            return None
        address = event.get("address")
        if not self._in_aperture(declaration, address):
            return None
        if event.get("write") is not True:
            return None
        producer = event.get("producer_event_id")
        if not _count(producer):
            self._reject("invalid_identity_field", event_id=event_id, kind="mmio_acceptance")
            return None
        if producer not in self._records:
            self._reject("unknown_producer_reference", event_id=event_id, kind="mmio_acceptance")
            return None
        state["transaction"] = transaction
        state["anchor_record_id"] = event_id
        return {"key": "transaction_key+aperture",
                "initiator_component": declaration.initiator_component,
                "device_id": declaration.device_id, "base": declaration.base,
                "size": declaration.size, "address": address,
                "transaction": _key_document(transaction), "producer_event_id": producer,
                "write_value": event.get("write_value")}

    def _in_aperture(self, declaration, address) -> bool:
        if not _count(address):
            return False
        return declaration.base <= address < declaration.base + declaration.size

    def _match_route_delivery(self, state: dict, event_id: int, event: Mapping) -> dict | None:
        if event.get("kind") != "mmio_delivery" or state["transaction"] is None:
            return None
        declaration = state["declaration"]
        transaction = _transaction_key(event.get("source_transaction"))
        if transaction is None:
            self._reject("invalid_identity_field", event_id=event_id, kind="mmio_delivery")
            return None
        if transaction != state["transaction"]:
            return None
        if event.get("device_id") != declaration.device_id:
            return None
        address = event.get("address")
        if not self._in_aperture(declaration, address):
            return None
        if event.get("write") is not True:
            return None
        producer = event.get("producer_event_id")
        if not _count(producer):
            self._reject("invalid_identity_field", event_id=event_id, kind="mmio_delivery")
            return None
        if producer not in self._records:
            self._reject("unknown_producer_reference", event_id=event_id, kind="mmio_delivery")
            return None
        state["delivery_value"] = event.get("write_value")
        state["delivery_event_id"] = event_id
        return {"key": "transaction_key+aperture",
                "initiator_component": declaration.initiator_component,
                "device_id": declaration.device_id, "address": address,
                "transaction": _key_document(transaction),
                "delivery_order": event.get("delivery_order"),
                "target_delivery_order": event.get("target_delivery_order"),
                "write_value": event.get("write_value")}

    def _match_route_consumer(self, state: dict, event_id: int, event: Mapping) -> dict | None:
        if state["transaction"] is None or event.get("kind") != "state_dependency":
            return None
        transaction = _transaction_key(event.get("source_transaction", event.get("transaction")))
        if transaction is None:
            transaction = _key_from_target(event.get("target"))
        if transaction is None or transaction != state["transaction"]:
            return None
        if event_id in (state["anchor_record_id"], state["delivery_event_id"]):
            return None
        if event.get("edge_kind") not in ("RAW", "PERSIST"):
            return None
        resource = event.get("memory_id")
        if resource is not None:
            if not _nonempty_text(resource) or not self._record_in_aperture(state, event):
                return None
        version = _version(event.get("version"))
        if version is None:
            return None
        state["version"] = version
        state["observation_event_id"] = event_id
        return {"key": "transaction_key+version", "transaction": _key_document(transaction),
                "version": version, "edge_kind": event.get("edge_kind"),
                "memory_id": event.get("memory_id"), "byte_offset": event.get("byte_offset"),
                "observation_event_id": event_id,
                "producer_event_id": event.get("producer_event_id")}

    def _record_in_aperture(self, state: dict, event: Mapping) -> bool:
        """The record's byte window must lie inside the declared aperture."""
        declaration = state["declaration"]
        offset = event.get("byte_offset")
        address = event.get("address")
        if not _count(offset):
            return False
        limit = declaration.base + declaration.size
        spans = [offset, offset + 1]
        if _count(address):
            spans.extend((address, address + 1))
        elif offset < declaration.base:
            spans.append(declaration.base + (offset - declaration.base) % declaration.size + 1)
        return all(declaration.base <= value <= limit for value in spans)

    # -- persistent_state -----------------------------------------------------
    def _observe_resource_shape(self, key, event: Mapping) -> None:
        """Count the bounded observed shape of one declared persistent edge."""
        kind = event.get("kind")
        shape = self._shape_for(key)
        if kind in _RESOURCE_PRODUCER_KINDS or kind in _REGISTER_PRODUCER_KINDS:
            shape["writer_records"] += 1
        if kind == "memory_read" or kind in _REGISTER_CONSUMER_KINDS:
            shape["reader_records"] += 1

    def _note_missing(self, state: dict, note: str) -> None:
        """Retain at most ``_MISSING_FIELD_LIMIT`` distinct missing-field notes."""
        notes = self._shape_for(state["key"])["missing_fields"]
        if note not in notes and len(notes) < _MISSING_FIELD_LIMIT:
            notes.append(note)

    def _match_resource_producer(self, state: dict, event_id: int, event: Mapping):
        """The declared resource's own write record, carrying an exact version.

        Two observed shapes are judged: a host-memory write record (exact
        ``generation``, ``byte_offset``, ``byte_enable``, ``width_bytes`` and
        ``version``, plus a matching ``commit_id``/``commit_document`` when the
        record is a commit) and a GPIO register commit record (exact per-bit
        ``version`` and ``observation_event_id`` naming an already observed
        event). A record missing any of those fields is not evidence, so the
        producer hop stays missing instead of being guessed.
        """
        declaration = state["declaration"]
        kind = event.get("kind")
        if kind in _REGISTER_PRODUCER_KINDS:
            return self._match_register_producer(state, event_id, event)
        if kind not in _RESOURCE_PRODUCER_KINDS:
            return None
        if (event.get("component"), event.get("memory_id")) != (
                declaration.resource_component, declaration.resource_id):
            return None
        generation = event.get("generation")
        version = _version(event.get("version"))
        byte_offset = event.get("byte_offset")
        width = event.get("width_bytes")
        byte_enable = event.get("byte_enable")
        if not _count(generation):
            self._note_missing(state, f"{kind}.generation")
            return None
        if version is None or version[1] == 0 or version[0] != generation:
            self._note_missing(state, f"{kind}.version[generation, commit_sequence]")
            return None
        if not _count(byte_offset) or not _count(width) or width < 1:
            self._note_missing(state, f"{kind}.byte_offset/width_bytes")
            return None
        if not _count(byte_enable) or byte_enable == 0 or byte_enable >> width:
            self._note_missing(state, f"{kind}.byte_enable")
            return None
        if kind == "memory_write_commit":
            document = event.get("commit_document")
            if (not _nonempty_text(event.get("commit_id"))
                    or not isinstance(document, Mapping)
                    or (document.get("memory_id"), document.get("generation"),
                        document.get("byte_offset"), document.get("width_bytes"),
                        document.get("byte_enable"),
                        _version(document.get("version"))) != (
                        declaration.resource_id, generation, byte_offset, width,
                        byte_enable, version)
                    or document.get("commit_status") != "complete"):
                self._note_missing(state, f"{kind}.commit_id/commit_document")
                return None
        producer = event.get("producer_event_id")
        if not _count(producer):
            self._reject("invalid_identity_field", event_id=event_id, kind=kind)
            return None
        if producer not in self._records:
            self._reject("unknown_producer_reference", event_id=event_id, kind=kind)
            return None
        writer = event.get("writer_event_id")
        if kind == "memory_initialization" and not _nonempty_text(writer):
            self._reject("invalid_identity_field", event_id=event_id, kind=kind)
            return None
        transaction = _transaction_key(event.get("transaction"))
        return {"resource_kind": "memory", "event_id": event_id, "version": version,
                "write_span": (byte_offset, width, byte_enable),
                "transaction_key": transaction,
                "declared_writer_id": writer if _nonempty_text(writer) else None,
                "producer_evidence": {
                    "key": "resource_write", "component": declaration.resource_component,
                    "resource_id": declaration.resource_id, "version": version,
                    "generation": generation, "byte_offset": byte_offset,
                    "width_bytes": width, "byte_enable": byte_enable,
                    "address": event.get("address"), "commit_id": event.get("commit_id"),
                    "writer_event_id": writer if _nonempty_text(writer) else None,
                    "declared_writer_id": writer if _nonempty_text(writer) else None,
                    "write_event_id": event_id,
                    "transaction": _key_document(transaction)}}

    def _match_register_producer(self, state: dict, event_id: int, event: Mapping):
        """A GPIO register commit record with per-bit exact versions.

        Every admitted bit row must name its own observed event id, so the
        version below is the register file's version as an *observed* event
        witnessed it, never a bare counter.
        """
        declaration = state["declaration"]
        if event.get("component") != declaration.resource_component:
            return None
        if event.get("register") != declaration.resource_id:
            return None
        if event.get("status") is not None and event.get("status") != "observed":
            return None
        resources = event.get("bit_resources")
        if not isinstance(resources, list) or not resources:
            self._note_missing(state, "gpio_register_commit.bit_resources")
            return None
        bits = {}
        for resource in resources:
            if not isinstance(resource, Mapping):
                continue
            bit, version = resource.get("bit"), resource.get("version")
            observation = resource.get("observation_event_id")
            if (not _count(bit) or not _count(version) or version == 0
                    or not _count(observation) or observation >= event_id
                    or observation not in self._records):
                continue
            if (resource.get("component"), resource.get("register")) != (
                    declaration.resource_component, declaration.resource_id):
                continue
            bits[bit] = {"bit": bit, "version": version,
                         "observation_event_id": observation,
                         "value": resource.get("value")
                         if _count(resource.get("value")) else None,
                         "local_tick": resource.get("local_tick")}
        if not bits:
            self._note_missing(state,
                               "gpio_register_commit.bit_resources[].version/observation_event_id")
            return None
        producer = event.get("producer_event_id")
        if not _count(producer):
            self._reject("invalid_identity_field", event_id=event_id, kind=event.get("kind"))
            return None
        if producer not in self._records:
            self._reject("unknown_producer_reference", event_id=event_id, kind=event.get("kind"))
            return None
        return {"resource_kind": "register", "event_id": event_id,
                "register_bits": bits, "version": None, "write_span": None,
                "declared_writer_id": None, "transaction_key": None,
                "producer_evidence": {
                    "key": "register_commit", "component": declaration.resource_component,
                    "resource_id": declaration.resource_id,
                    "register": declaration.resource_id,
                    "access_id": event.get("access_id"),
                    "operation": event.get("operation"), "write_event_id": event_id,
                    "writer_event_id": event_id,
                    "bits": [dict(bits[bit]) for bit in sorted(bits)]}}

    def _resource_version_evidence(self, state: dict) -> dict:
        record = state.get("anchor") or {}
        evidence = {"key": "resource_version",
                    "component": state["declaration"].resource_component,
                    "resource_id": state["declaration"].resource_id,
                    "writer_event_id": record.get("declared_writer_id"),
                    "write_event_id": record.get("event_id"),
                    "version": record.get("version"), "shared_event": True}
        if state.get("resource_kind") == "register":
            bits = record.get("register_bits") or {}
            evidence["key"] = "register_version"
            evidence["bits"] = [dict(bits[bit]) for bit in sorted(bits)]
        return evidence

    def _match_resource_consumer(self, state: dict, event_id: int, event: Mapping):
        """A later read that references one retained version field by field."""
        if state.get("resource_kind") == "register":
            return self._match_register_consumer(state, event_id, event)
        return self._match_memory_consumer(state, event_id, event)

    @staticmethod
    def _writer_reference_form(record: dict, reference, kind):
        """How one read lane names one retained write record, or ``None``.

        Exact forms only: the writer's own integer event id, the writer's own
        canonical ``TransactionKey(...)`` identity (the id its host commit
        stored as the byte's writer), or the writer's own declared
        ``writer_event_id`` string. ``"other_writer"`` means the lane names a
        resolvable identity that is not this record; ``None`` means the lane
        names nothing resolvable at all, such as the boot-image placeholder
        ``initial-image``.
        """
        if not _nonempty_text(kind) or kind == "INITIAL_IMAGE":
            return None
        if _count(reference):
            return "event_id" if reference == record["event_id"] else "other_writer"
        if not _nonempty_text(reference):
            return None
        parsed = _key_from_target(reference)
        if parsed is not None:
            return ("transaction_key"
                    if parsed == record.get("transaction_key") else "other_writer")
        declared = record.get("declared_writer_id")
        if _nonempty_text(declared):
            return "declared_writer_id" if reference == declared else "other_writer"
        return None

    def _match_memory_consumer(self, state: dict, event_id: int, event: Mapping):
        declaration = state["declaration"]
        if event.get("kind") != "memory_read":
            return None
        if (event.get("component"), event.get("memory_id")) != (
                declaration.resource_component, declaration.resource_id):
            return None
        offset, width = event.get("byte_offset"), event.get("width_bytes")
        versions, raw, kinds = (event.get("versions"), event.get("writer_event_ids"),
                                event.get("writer_kinds"))
        generation = event.get("generation")
        if not _count(offset) or not _count(width) or width < 1:
            self._note_missing(state, "memory_read.byte_offset/width_bytes")
            return None
        if (not isinstance(versions, list) or len(versions) != width
                or not isinstance(raw, (list, tuple)) or len(raw) != width
                or not isinstance(kinds, list) or len(kinds) != width):
            self._note_missing(state,
                               "memory_read.versions/writer_event_ids/writer_kinds")
            return None
        for record in reversed(state["anchors"]):
            if record.get("resource_kind") != "memory" or event_id <= record["event_id"]:
                continue
            if not _count(generation) or generation != record["version"][0]:
                self._note_missing(state, "memory_read.generation")
                continue
            write_offset, write_width, byte_enable = record["write_span"]
            forms, covered = set(), True
            for lane in range(width):
                observed = _version(versions[lane])
                if observed is None:
                    self._note_missing(state, "memory_read.versions")
                    covered = False
                    break
                delta = offset + lane - write_offset
                if not 0 <= delta < write_width or not byte_enable >> delta & 1:
                    self._note_missing(
                        state, "memory_read byte window exceeds memory_write.byte_enable")
                    covered = False
                    break
                if observed != record["version"]:
                    self._note_missing(state,
                                       "memory_read.versions != memory_write.version")
                    covered = False
                    break
                form = self._writer_reference_form(record, raw[lane], kinds[lane])
                self._shape_for(state["key"])["reader_reference_forms"][
                    form if form is not None else "placeholder"] += 1
                if form is None:
                    self._note_missing(
                        state,
                        "memory_read.writer_event_ids names no write record (placeholder)")
                    covered = False
                    break
                if form == "other_writer":
                    self._note_missing(
                        state,
                        "memory_read.writer_event_ids names a different write record")
                    covered = False
                    break
                forms.add(form)
            if not covered:
                continue
            return record, {
                "key": ("writer_event_id+version" if forms == {"event_id"}
                        else "writer_version+%s" % "+".join(sorted(forms))),
                "component": declaration.resource_component,
                "resource_id": declaration.resource_id,
                "version": record["version"], "generation": generation,
                "byte_offset": offset, "width_bytes": width,
                "write_event_id": record["event_id"], "writer_event_id": record["event_id"],
                "writer_reference_forms": sorted(forms),
                "writer_event_ids": list(raw), "writer_kinds": list(kinds),
                "explicit_writer_refs": True, "value": event.get("value")}
        return None

    @staticmethod
    def _register_reference_rows(event: Mapping):
        """``(field, row)`` pairs that may cite one anchored bit version.

        A read cites a version either in its own per-bit row (``bit_resources``/
        ``post_bit_resources``) or in a row nested inside one of those
        (``dependencies``/``origin_refs``); a flatter event may also carry those
        lists directly. Nothing else is inspected.
        """
        for field in _REGISTER_REFERENCE_FIELDS:
            rows = event.get(field)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                yield field, row
                for nested in _REGISTER_NESTED_FIELDS:
                    inner = row.get(nested)
                    if not isinstance(inner, list):
                        continue
                    for item in inner:
                        if isinstance(item, Mapping):
                            yield f"{field}[].{nested}", item

    def _match_register_consumer(self, state: dict, event_id: int, event: Mapping):
        """A later read carrying an exact reference to one retained bit version."""
        declaration = state["declaration"]
        if event.get("kind") not in _REGISTER_CONSUMER_KINDS:
            return None
        if event.get("component") != declaration.resource_component:
            return None
        if event.get("status") is not None and event.get("status") != "observed":
            return None
        register = event.get("register")
        if register is not None and register != declaration.resource_id:
            return None
        for record in reversed(state["anchors"]):
            bits = record.get("register_bits")
            if record.get("resource_kind") != "register" or not bits \
                    or event_id <= record["event_id"]:
                continue
            matched = []
            for field, row in self._register_reference_rows(event):
                bit = row.get("bit")
                anchored = bits.get(bit) if _count(bit) else None
                if anchored is None:
                    continue
                component = row.get("component")
                if component is not None and component != declaration.resource_component:
                    continue
                observed_register = row.get("register")
                if observed_register is not None \
                        and observed_register != declaration.resource_id:
                    continue
                if (row.get("version") != anchored["version"]
                        or row.get("observation_event_id")
                        != anchored["observation_event_id"]):
                    continue
                if (_count(row.get("value")) and anchored["value"] is not None
                        and row.get("value") != anchored["value"]):
                    continue
                matched.append({"field": field, "bit": anchored["bit"],
                                "version": anchored["version"],
                                "observation_event_id": anchored["observation_event_id"],
                                "value": anchored["value"],
                                "read_value": event.get("read_value")})
            if not matched:
                continue
            return record, {
                "key": "register_version_reference",
                "component": declaration.resource_component,
                "resource_id": declaration.resource_id,
                "register": declaration.resource_id,
                "write_event_id": record["event_id"],
                "writer_event_id": record["event_id"],
                "read_event_id": event_id, "access_id": event.get("access_id"),
                "read_access_id": event.get("access_id"),
                "references": matched, "explicit_version_refs": True}
        self._note_missing(state,
                           "gpio_register_read.bit_resources[].version+observation_event_id")
        return None


    # ---------------------------------------------------------------- settling
    def _settle_ready(self) -> dict | None:
        settled = self._settle_ready_all()
        return settled[-1] if settled else None

    def _settle_ready_all(self) -> list:
        """Settle every edge whose required hops are all witnessed."""
        settled = []
        for key in list(self._active):
            state = self._active[key]
            required = _REQUIRED_HOPS[state["declaration"].relation]
            if all(hop_id in state["hops"] for hop_id in required):
                settled.append(self._settle(key, CERTIFIED, state["event_id"], None))
        return settled

    def _settle(self, key, status: str, event_id, reason: str | None) -> dict:
        state = self._active.pop(key, None)
        if state is not None and key in self._order:
            self._order.remove(key)
        self._final.add(key)
        if state is not None:
            self._archived[key] = self._archive(state, status, reason, event_id)
            state = dict(self._archived[key])
        else:
            state = {"key": key, "declaration": self._declarations[key], "hops": {},
                     "handled": set(), "endpoints": self._endpoints.get(key)}
        certificate = self._certificate(state, status, event_id, reason)
        self._certificates.append(certificate)
        return certificate

    def _certificate(self, state, status: str, event_id, reason: str | None) -> dict:
        row = self._edge_row(state, status, end_event_id=event_id, reason=reason)
        return {"schema_version": EDGE_PROVENANCE_SCHEMA,
                "certificate_id": _certificate_id(state["key"]),
                "status": status, "reason": reason,
                "rule_index": state["key"][0], "prerequisite_index": state["key"][1],
                "relation": state["declaration"].relation, "scope": row["scope"],
                "proof_scope": row["proof_scope"], "components": row["components"],
                "hops": deepcopy(row["hops"]), "missing": list(row["missing"]),
                "references": deepcopy(row["references"]),
                "observed_shape": deepcopy(row["observed_shape"])}

    def flush(self) -> tuple[dict, ...]:
        """Settle every still-open edge as ``incomplete`` at end of journal."""
        produced = []
        for key in list(self._active):
            last = self._active[key]["event_id"]
            produced.append(self._settle(key, INCOMPLETE, last, "end_of_journal"))
        return tuple(produced)

    # ------------------------------------------------------------------ report
    def report(self, events: Iterable[Mapping] = ()) -> dict:
        """Render one bounded coverage document for every declared edge."""
        produced = list(self.flush())
        self._certificates.extend(produced)
        self._reported_certificates = len(self._certificates)
        if events:
            produced.extend(self.ingest(events))
        rows = [self._edge_row(self._state_for(key), None, end_event_id=None, reason=None)
                for key in sorted(self._declarations)]
        counts = {"total": len(rows), CERTIFIED: 0, INCOMPLETE: 0, UNKNOWN: 0,
                  "rejected": self._events_rejected, "evicted": self._evictions}
        for row in rows:
            counts[row["status"]] += 1
        return {"schema_version": EDGE_PROVENANCE_REPORT_SCHEMA,
                "edge_schema_version": EDGE_PROVENANCE_SCHEMA,
                "contract_identity": self.contract.identity_sha256,
                "graph_sha256": self.contract.graph_sha256,
                "bounds": {"max_pending": self.max_pending,
                           "max_event_gap": self.max_event_gap,
                           "max_record_references": self._hint_limit},
                "events_observed": self._events_observed,
                "events_rejected": self._events_rejected,
                "last_event_id": self._last_event_id,
                "resets": self._resets,
                "dropped_late_hops": self._dropped_late_hops,
                "counts": counts,
                "edges": rows,
                "rejections": [dict(row) for row in self._rejections],
                "evictions": [{"rule_index": key[0], "prerequisite_index": key[1],
                               "reason": state["reason"]}
                              for key, state in sorted(self._archived.items())
                              if state.get("reason") == "pending_capacity"],
                "certificates": [dict(row) for row in produced],
                "proof_scope": {CERTIFIED: PROOF_SCOPE_CERTIFIED,
                                INCOMPLETE: PROOF_SCOPE_PARTIAL,
                                UNKNOWN: PROOF_SCOPE_UNKNOWN}}

    def _state_for(self, key) -> dict:
        state = self._active.get(key)
        if state is not None:
            return state
        archived = self._archived.get(key)
        if archived is not None:
            return dict(archived)
        return {"key": key, "declaration": self._declarations[key], "hops": {},
                "handled": set(), "endpoints": self._endpoints.get(key)}

    def _edge_row(self, state, status: str | None, *, end_event_id, reason: str | None) -> dict:
        declaration = state["declaration"]
        relation = declaration.relation
        seen = [hop_id for hop_id in HOP_IDS if hop_id in state["hops"]]
        hops = [{"hop_id": hop_id, "event_id": state["hops"][hop_id]["event_id"],
                 **deepcopy(state["hops"][hop_id]["evidence"])} for hop_id in seen]
        declared_shape = relation in _SUPPORTED_RELATIONS
        supported = declared_shape and self._endpoints.get(state["key"]) is not None
        unsupported_reason = None
        if not declared_shape:
            unsupported_reason = f"{relation} has no runtime join shape in this consumer"
        elif not supported:
            unsupported_reason = "no resolved physical endpoints for this declared edge"
        required = _REQUIRED_HOPS.get(relation, ())
        missing = [hop_id for hop_id in required if hop_id not in state["hops"]]
        decision = state.get("decision")
        if not declared_shape:
            row_status, row_reason = UNKNOWN, "declared_shape_unsupported"
        elif not supported:
            row_status, row_reason = UNKNOWN, "no_observable_hop"
        elif status == CERTIFIED and not missing:
            row_status, row_reason = CERTIFIED, None
        elif status == CERTIFIED:
            row_status, row_reason = INCOMPLETE, "missing_required_hop"
        elif status == INCOMPLETE:
            row_status, row_reason = INCOMPLETE, reason or "missing_required_hop"
        elif decision == CERTIFIED:
            row_status, row_reason = CERTIFIED, None
        elif decision == INCOMPLETE:
            row_status, row_reason = INCOMPLETE, state.get("reason") or "missing_required_hop"
        elif hops:
            row_status, row_reason = INCOMPLETE, "missing_required_hop"
        else:
            row_status, row_reason = UNKNOWN, "no_observable_hop"
        if row_status != INCOMPLETE:
            missing = []
        return {"rule_index": state["key"][0], "prerequisite_index": state["key"][1],
                "relation": relation, "scope": _SCOPE.get(relation), "direction": "forward",
                "components": self._components(state),
                "resource": ({"component": declaration.resource_component,
                              "resource_id": declaration.resource_id}
                             if relation == "persistent_state" else None),
                "status": row_status, "reason": row_reason,
                "declared_shape": declared_shape,
                "unsupported_shape": not declared_shape,
                "unsupported_shape_reason": unsupported_reason,
                "observed_shape": (None if not supported else
                                   {hop_id: hop_id in state["hops"] for hop_id in HOP_IDS}),
                "hops": hops, "missing": missing,
                "persistent_state": (self._persistent_block(state, row_status)
                                     if relation == "persistent_state" else None),
                "references": self._references(state),
                "proof_scope": {CERTIFIED: PROOF_SCOPE_CERTIFIED,
                                INCOMPLETE: PROOF_SCOPE_PARTIAL,
                                UNKNOWN: PROOF_SCOPE_UNKNOWN}[row_status],
                "settled_event_id": end_event_id if status is not None else None,
                "ingested": state.get("decision") is not None or bool(
                    state.get("hops") or state.get("transaction") is not None
                    or state.get("version") is not None
                    or state.get("observation_event_id") is not None)}

    def _persistent_block(self, state, row_status: str) -> dict:
        """Bounded, factual shape of one declared persistent edge in this run.

        ``writer_records``/``reader_records``/``reader_reference_forms`` count
        every event of this journal that names the declared resource and the
        declared edge identity.  ``missing_fields`` names the exact event fields
        that kept a hop out of an ``incomplete``/``unknown`` certificate, while
        ``rejected_candidates`` carries the same notes for a ``certified`` edge
        -- the observed candidates that did *not* join, recorded instead of
        being silently ignored.  ``unsupported_shape_reason`` is
        filled only when this journal observed *no* writer and no reader record
        of the declared resource at all -- an explicit statement about
        observability, never a claim that the declared relation did not happen.
        """
        shape = self._shape_for(state["key"])
        declaration = state["declaration"]
        block = {"resource_kind": state.get("resource_kind"),
                 "resource": {"component": declaration.resource_component,
                              "resource_id": declaration.resource_id},
                 "writer_records": shape["writer_records"],
                 "reader_records": shape["reader_records"],
                 "dropped_anchors": shape["dropped_anchors"],
                 "reader_reference_forms": dict(shape["reader_reference_forms"]),
                 "missing_fields": ([] if row_status == CERTIFIED
                                    else list(shape["missing_fields"])),
                 "rejected_candidates": (list(shape["missing_fields"])
                                         if row_status == CERTIFIED else []),
                 "unsupported_shape_reason": None}
        if row_status == UNKNOWN and not (shape["writer_records"]
                                         or shape["reader_records"]):
            block["unsupported_shape_reason"] = (
                "no observed writer/reader record names resource "
                f"({declaration.resource_component}, {declaration.resource_id}) "
                "in this journal")
        return block

    def _components(self, state) -> list:
        endpoints = state.get("endpoints")
        if endpoints is None:
            declaration = state["declaration"]
            if declaration.relation == "persistent_state":
                return [declaration.resource_component]
            if declaration.relation == "mmio_route":
                return sorted({declaration.initiator_component, declaration.device_id})
            return []
        return sorted({endpoints.source.component, endpoints.target.component})

    def _references(self, state) -> dict:
        references = {}
        if state.get("transaction") is not None:
            references["transaction"] = _key_document(state["transaction"])
        delivery = state["hops"].get(DELIVERY)
        if delivery is not None:
            chain = delivery["evidence"].get("chain") or {}
            for name in ("producer_event_id", "source_event_id"):
                if _count(chain.get(name)):
                    references[name] = chain[name]
        consumer = state["hops"].get(CONSUMER)
        if consumer is not None:
            evidence = consumer["evidence"]
            if _count(evidence.get("source_event_id")):
                references["source_event_id"] = evidence["source_event_id"]
            if _count(evidence.get("delivery_event_id")):
                references["delivery_event_id"] = evidence["delivery_event_id"]
            if evidence.get("observation_event_id") is not None:
                references["observation_event_id"] = evidence["observation_event_id"]
        if state.get("observation_event_id") is not None:
            references["observation_event_id"] = state["observation_event_id"]
        if state.get("version") is not None:
            references["version"] = list(state["version"])
        writer = state.get("writer_event_id")
        if writer is None:
            producer = state["hops"].get(PRODUCER)
            if producer is not None:
                writer = producer["evidence"].get("writer_event_id")
        if writer is None:
            consumer_hop = state["hops"].get(CONSUMER)
            if consumer_hop is not None:
                writer = consumer_hop["evidence"].get("writer_event_id")
        if writer is not None:
            references["writer_event_id"] = writer
        return references


def _certificate_id(key) -> str:
    payload = json.dumps({"schema_version": EDGE_PROVENANCE_SCHEMA,
                          "rule_index": key[0], "prerequisite_index": key[1]},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def edge_provenance_session(run_dir) -> tuple:
    """Read one run's own declaration and resolve its declared edge endpoints.

    Returns ``(contract, endpoints)`` from ``online_session_manifest.json``:
    the contract document the run compiled and the physical endpoints of every
    declared edge from that same compiled topology. Passing both to
    :func:`edge_provenance_report` is what makes a verdict possible at all; the
    *report* still only claims the exact identity joins it observed.
    """
    from pathlib import Path
    manifest_path = Path(run_dir) / "online_session_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"run directory has no session manifest: {run_dir}")
    compiled = json.loads(manifest_path.read_text(encoding="utf-8"))["runtime_paths"]
    contract = RuntimePathContract.from_document(compiled["declaration"]["contract"])
    return contract, edge_endpoints_from_compiled(contract, compiled)


def edge_provenance_report(contract: RuntimePathContract, events: Iterable[Mapping], *,
                           endpoints: Mapping | None = None,
                           max_pending: int = 4096, max_event_gap: int = 65536,
                           candidate_resolver=None) -> dict:
    """Consume one journal and render the per-declared-edge coverage report.

    ``events`` may be a lazily streamed journal; ``endpoints`` must be the
    resolved map from :func:`edge_endpoints_from_compiled` (or
    :func:`edge_provenance_session`), otherwise every edge stays ``unknown``
    with ``unsupported_shape_reason`` naming the missing resolution.
    ``candidate_resolver`` may add declared edge identities to events of a
    journal written before those edges were declared; it never removes or
    rewrites a candidate the journal already carries.
    """
    consumer = EdgeProvenanceConsumer(contract, endpoints=endpoints,
                                      max_pending=max_pending, max_event_gap=max_event_gap,
                                      candidate_resolver=candidate_resolver)
    consumer.ingest(events)
    return consumer.report()


__all__ = ["EDGE_PROVENANCE_SCHEMA", "EDGE_PROVENANCE_REPORT_SCHEMA",
           "PRODUCER", "DELIVERY", "CONSUMER", "HOP_IDS",
           "CERTIFIED", "INCOMPLETE", "UNKNOWN",
           "EdgeEndpoints", "edge_endpoints_from_compiled",
           "EdgeProvenanceConsumer", "edge_provenance_report",
           "edge_provenance_session"]
