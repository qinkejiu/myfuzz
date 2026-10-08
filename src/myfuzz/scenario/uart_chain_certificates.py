"""Read-only UART chain certificates for one saved online trace.

The shipped GPIO producer (:mod:`myfuzz.scenario.chain_certificates`) only
understands ``gpio_b.external_pin8`` and ``cpu.online_instruction`` sources, so a
heterogeneous OpenTitan UART run certifies nothing and does not even track a
candidate. This module closes that gap for the UART path: it streams
``online_final_trace.meta.json`` + ``online_events.jsonl`` / ``online_events.zlib``
or the monolithic ``online_final_trace.json`` through
:class:`myfuzz.scenario.acceptance_metrics.TraceEventStream`, joins the UART hops
by literal identities only, and emits ``runtime_uart_chain_certificate.v1``
certificates plus an honest per-candidate incomplete histogram whose first
missing hop is always named.

Declared hop sequence (``UART_HOPS``, one certificate per source admission)::

    uart_source_admission -> uart_source_injection -> uart_frame_admission ->
    uart_source_frame_begin -> uart_rx_receiver_start ->
    uart_rx_receiver_complete -> uart_fifo_push -> uart_irq_update ->
    uart_source_frame_end -> uart_frame_validation ->
    uart_irq_binding_delivery -> uart_cpu_irq_sample -> uart_cpu_irq_taken ->
    uart_fifo_pop -> uart_rdata_access -> uart_retired_read_match

Every hop is witnessed by exactly one event and by literal identity joins
(admission id, action id, frame id, FIFO entry id, receiver id, watermark
``source_output_key``, access id, six-field source transaction, retirement
witness ids). Event adjacency, equal counts and architectural expectation are
never used as a join, and no hop is ever inferred from another.

Ordering is the declared DAG ``UART_HOP_ORDER``, not arrival order: the CPU IRQ
acknowledgement hops are only *identifiable* once ``cpu_external_irq_taken``
names its ``source_output_key``, while their witness events precede the same
frame's ``uart_source_frame_end`` record, and in the saved artifact the watermark
IRQ leg of one frame precedes that frame's end record while the next frame's leg
follows it. A hop is attached at its declared position as long as its event id
respects every enforced edge against the hops already witnessed; a violated edge
is refused and counted, never reordered.

Fail-closed behaviour mirrors the GPIO producer: a join key that is present but
contradicts an already-recorded hop is refused (never silently accepted), the
candidate settles ``incomplete`` at that event with ``contradiction_reason``, and
no later event restores credit. Unknown quantities are ``null`` plus a
``*_reason``, never ``0``. Every certificate states its ``proof_scope`` and
``not_proof_of``: it proves the witness chain *inside the saved artifact*, not
that the DUT has no other behaviour, and it claims a cross-case link only when
the source and endpoint case ids genuinely differ.

The IRQ leg is evidence, never causality: a take is attributed to a candidate
only when the take's own ``input_context.source_output_key`` names a
``uart_irq_output_definition`` whose ``pre_entry_ids`` head is that candidate's
FIFO entry. Each certificate records ``irq_mode`` (``irq_taken`` /
``irq_asserted_no_take`` / ``no_irq_witness``) and ``polling_consistent``, so a
CPU read that happened without a joined interrupt is reported as polling
evidence instead of an unprovable IRQ-to-CPU claim.

``certificate_id`` is the lowercase SHA-256 hex digest of the canonical UTF-8
JSON array ``[direction, source_admission_id, frame_id]`` encoded with
``separators=(",", ":")``; ``frame_id`` is ``null`` for an admission that never
named a frame.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping
import hashlib
import json

from .acceptance_metrics import TraceEventStream
from .pin8_consumption_certificates import _case
from .source_provenance import SourceAdmission


SCHEMA_VERSION = "runtime_uart_chain_certificate.v1"
DIRECTION = "IP_TO_CPU"
CERTIFIED = "certified"
INCOMPLETE = "incomplete"
UART_COMPONENT = "uart"
CPU_COMPONENT = "cpu"
UART_SOURCE_ID = "uart.external_rx_byte"
UART_PORT = "uart_rx_byte"
RXFIFO_OFFSET = 24
FIFO_BYTE_ENABLE = 15
IRQ_CLASS = "rx_watermark"
IRQ_SOURCE_PORT = "uart_rx_watermark"
IRQ_TARGET_PORT = "irq"
IRQ_INPUT_CONTEXT_SCHEMA = "native_irq_input_context.v1"
IRQ_TAKEN = "irq_taken"
IRQ_ASSERTED_NO_TAKE = "irq_asserted_no_take"
NO_IRQ_WITNESS = "no_irq_witness"
READ_CHAIN_WITNESSED = "witnessed"
READ_CHAIN_INCOMPLETE = "incomplete"
PROOF_SCOPE = "saved_artifact_uart_witness_chain"

UART_HOPS = (
    "uart_source_admission",
    "uart_source_injection",
    "uart_frame_admission",
    "uart_source_frame_begin",
    "uart_rx_receiver_start",
    "uart_rx_receiver_complete",
    "uart_fifo_push",
    "uart_irq_update",
    "uart_source_frame_end",
    "uart_frame_validation",
    "uart_irq_binding_delivery",
    "uart_cpu_irq_sample",
    "uart_cpu_irq_taken",
    "uart_fifo_pop",
    "uart_rdata_access",
    "uart_retired_read_match",
)

# Enforced precedence edges. Anything not implied here (the IRQ leg against the
# frame end/validation records) is deliberately unordered: the saved artifact
# shows both interleavings for different frames.
UART_HOP_ORDER = (
    ("uart_source_admission", "uart_source_injection"),
    ("uart_source_injection", "uart_frame_admission"),
    ("uart_frame_admission", "uart_source_frame_begin"),
    ("uart_source_frame_begin", "uart_rx_receiver_start"),
    ("uart_rx_receiver_start", "uart_rx_receiver_complete"),
    ("uart_rx_receiver_complete", "uart_fifo_push"),
    ("uart_fifo_push", "uart_irq_update"),
    ("uart_fifo_push", "uart_source_frame_end"),
    ("uart_irq_update", "uart_irq_binding_delivery"),
    ("uart_irq_update", "uart_source_frame_end"),
    ("uart_irq_binding_delivery", "uart_cpu_irq_sample"),
    ("uart_cpu_irq_sample", "uart_cpu_irq_taken"),
    ("uart_source_frame_end", "uart_frame_validation"),
    ("uart_frame_validation", "uart_fifo_pop"),
    ("uart_cpu_irq_taken", "uart_fifo_pop"),
    ("uart_fifo_pop", "uart_rdata_access"),
    ("uart_rdata_access", "uart_retired_read_match"),
)

IRQ_HOPS = ("uart_irq_update", "uart_irq_binding_delivery", "uart_cpu_irq_sample",
            "uart_cpu_irq_taken")
READ_HOPS = ("uart_fifo_pop", "uart_rdata_access", "uart_retired_read_match")

KIND_HOP = {
    "source_admission": "uart_source_admission",
    "source_injection": "uart_source_injection",
    "uart_source_frame_admission": "uart_frame_admission",
    "uart_source_frame_begin": "uart_source_frame_begin",
    "uart_rx_receiver_start": "uart_rx_receiver_start",
    "uart_rx_receiver_complete": "uart_rx_receiver_complete",
    "uart_fifo_push": "uart_fifo_push",
    "uart_irq_update": "uart_irq_update",
    "uart_source_frame_end": "uart_source_frame_end",
    "uart_frame_validation": "uart_frame_validation",
    "native_irq_binding_delivery": "uart_irq_binding_delivery",
    "cpu_external_irq_sample": "uart_cpu_irq_sample",
    "cpu_external_irq_taken": "uart_cpu_irq_taken",
    "uart_fifo_pop": "uart_fifo_pop",
    "uart_rdata_access": "uart_rdata_access",
    "uart_retired_read_match": "uart_retired_read_match",
}

_NOT_PROOF_OF = (
    "proves only the witness chain inside the saved artifact; it does not prove "
    "the DUT has no other behaviour",
    "does not prove anything about ticks, bytes or cases the saved artifact does "
    "not contain",
    "does not prove a cross-case link unless source_case_id and endpoint_case_id "
    "genuinely differ",
    "does not prove the UART watermark interrupt was caused by this frame's byte "
    "alone; the joined queue state listed this entry as head among the "
    "watermark-qualified entries",
    "does not prove the CPU took an interrupt unless the uart_cpu_irq_taken hop "
    "is witnessed with its exact source_output_key join, and never proves the "
    "CPU took an interrupt for a certificate without that hop",
    "does not prove ISR, operand or store semantics beyond the retired load named "
    "by uart_retired_read_match",
    "does not contain events that were refused: refused joins are counted in the "
    "run-level refusal histogram and are never amended into a certificate",
)

_TRANSACTION_FIELDS = ("channel_id", "execution_id", "source_component",
                       "source_epoch", "source_sequence", "testcase_id")
_TRANSACTION_INT_FIELDS = frozenset(("source_epoch", "source_sequence"))

_UART_ADMISSION_ROLES = frozenset(("fuzz_source", "bootstrap"))


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _byte(value: object) -> bool:
    return type(value) is int and 0 <= value < 256


def _same(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False)


def _transaction_key(document: object) -> tuple | None:
    """Exact six-field source transaction key; anything else fails closed."""
    if not isinstance(document, Mapping) or set(document) != set(_TRANSACTION_FIELDS):
        return None
    values = []
    for name in _TRANSACTION_FIELDS:
        value = document[name]
        if name in _TRANSACTION_INT_FIELDS:
            if not _integer(value):
                return None
        elif type(value) is not str or not value:
            return None
        values.append(value)
    return tuple(values)


def _entry_id(value: object, component: str, epoch: int) -> tuple | None:
    """Exact ``[component, epoch, generation, sequence]`` FIFO entry identity."""
    if (type(value) is not list or len(value) != 4 or value[0] != component
            or type(value[1]) is not int or value[1] != epoch
            or not all(_integer(item) for item in value[2:])):
        return None
    return tuple(value)


def _receiver_key(value: object) -> tuple | None:
    if (type(value) is not list or len(value) != 3 or value[0] != UART_COMPONENT
            or not all(_integer(item) for item in value[1:])):
        return None
    return tuple(value)


def _source_output_key(value: object) -> tuple | None:
    """Exact ``[uart, epoch, rx_watermark, version]`` watermark identity."""
    if (type(value) is not list or len(value) != 4
            or value[0] != UART_COMPONENT
            or not _integer(value[1]) or value[2] != IRQ_CLASS
            or not _integer(value[3]) or value[3] < 1):
        return None
    return tuple(value)


def _certificate_id(admission_id: str, frame_id: str | None) -> str:
    payload = json.dumps([DIRECTION, admission_id, frame_id],
                         separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _closed_edges() -> frozenset:
    """Transitive closure of the declared precedence edges."""
    closure = {(before, after) for before, after in UART_HOP_ORDER}
    changed = True
    while changed:
        changed = False
        for first, second in tuple(closure):
            for third, fourth in tuple(closure):
                if second == third and (first, fourth) not in closure:
                    closure.add((first, fourth))
                    changed = True
    return frozenset(closure)


_ENFORCED_ORDER = _closed_edges()


class UartChainCertificates:
    """Fuse per-hop UART evidence into at most one chain per source admission.

    The consumer is fed one contiguous journal slice at a time (or a whole
    streamed trace) and returns the certificates settled by that slice. Memory is
    bounded by ``max_pending`` candidates, ``max_identities`` entries per identity
    index and ``max_event_gap``: a candidate settles ``incomplete`` as soon as it
    stops making progress, is evicted by capacity, contradicts a recorded join, or
    is still open at :meth:`flush`.
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 65536,
                 max_identities: int = 4096, max_certificates: int = 2048,
                 max_refusal_samples: int = 64,
                 require_irq_leg: bool = True) -> None:
        for name, value in (("max_pending", max_pending),
                            ("max_event_gap", max_event_gap),
                            ("max_identities", max_identities),
                            ("max_certificates", max_certificates),
                            ("max_refusal_samples", max_refusal_samples)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(require_irq_leg) is not bool:
            raise ValueError("require_irq_leg must be boolean")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self.max_identities = max_identities
        self.max_certificates = max_certificates
        self.max_refusal_samples = max_refusal_samples
        self.require_irq_leg = require_irq_leg

        self._last_event_id = 0
        self._emitted: list = []
        self._candidates: OrderedDict[str, dict] = OrderedDict()
        self._settled: OrderedDict[str, dict] = OrderedDict()
        self._settled_frames: OrderedDict[str, dict] = OrderedDict()
        self._settled_entries: OrderedDict[tuple, dict] = OrderedDict()
        self._entries: OrderedDict[tuple, dict] = OrderedDict()
        self._frames: OrderedDict[str, dict] = OrderedDict()
        self._receivers: OrderedDict[tuple, dict] = OrderedDict()
        self._pops: OrderedDict[int, dict] = OrderedDict()
        self._updates: OrderedDict[int, dict] = OrderedDict()
        self._assertions: OrderedDict[tuple, dict] = OrderedDict()
        self._deliveries: OrderedDict[int, dict] = OrderedDict()
        self._samples: OrderedDict[int, dict] = OrderedDict()
        self._certificates: list = []
        self._hop_event_counts: dict[str, int] = {}
        self._witness_counts: dict[str, int] = {hop: 0 for hop in UART_HOPS}
        self._first_missing: dict[str, int] = {}
        self._irq_modes: dict[str, int] = {}
        self._refusals: dict[str, int] = {}
        self._refusal_samples: list = []
        self._refused_hops: set = set()
        self._duplicates: dict[str, int] = {}
        self._unresolved: dict[str, int] = {}
        self._skipped: dict[str, int] = {}
        self._candidates_total = 0
        self._certificates_total = 0
        self._certified_total = 0
        self._incomplete_total = 0
        self._evicted_total = 0
        self._expired_total = 0
        self._contradicted_total = 0
        self._late_events = 0

    # ------------------------------------------------------------------ API

    @property
    def pending_count(self) -> int:
        """Unsettled candidates; never above ``max_pending``."""
        return len(self._candidates)

    @property
    def cache_size(self) -> int:
        """Total retained entries across every bounded identity index."""
        return sum(self.cache_sizes().values())

    def cache_sizes(self) -> dict:
        """Retained entries per bounded identity index (never above capacity)."""
        return {
            "entries": len(self._entries), "frames": len(self._frames),
            "receivers": len(self._receivers), "pops": len(self._pops),
            "updates": len(self._updates), "assertions": len(self._assertions),
            "deliveries": len(self._deliveries), "samples": len(self._samples),
            "settled": len(self._settled),
            "settled_frames": len(self._settled_frames),
            "settled_entries": len(self._settled_entries),
        }

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        """Consume one contiguous journal slice; return newly settled certificates."""
        result = []
        for event in events:
            if (not isinstance(event, Mapping)
                    or type(event.get("event_id")) is not int
                    or event["event_id"] != self._last_event_id + 1):
                raise ValueError("uart certificate journal must be contiguous")
            self._last_event_id = event["event_id"]
            self._expire(event["event_id"])
            state = self._dispatch(event)
            if state is not None:
                self._maybe_complete(state)
            result.extend(self._drain())
        return tuple(result)

    def flush(self) -> tuple[dict, ...]:
        """Settle every candidate still open at the end of the journal."""
        for admission_id in tuple(self._candidates):
            self._settle(admission_id, INCOMPLETE, self._last_event_id,
                         "journal_end")
        return self._drain()

    def document(self, *, trace_evidence: Mapping | None = None) -> dict:
        """The deterministic run-level document: certificates plus every count."""
        certificates = [dict(row) for row in self._certificates]
        histogram = {name: count for name, count in sorted(self._first_missing.items())}
        irq_modes = {name: count for name, count in sorted(self._irq_modes.items())}
        checks = self._self_consistency(certificates)
        return {
            "schema_version": SCHEMA_VERSION,
            "direction": DIRECTION,
            "certificate_schema_version": SCHEMA_VERSION,
            "hop_sequence": list(UART_HOPS),
            "enforced_hop_order": [list(edge) for edge in UART_HOP_ORDER],
            "required_hops": list(self._required()),
            "require_irq_leg": self.require_irq_leg,
            "limits": self._limits(),
            "trace": self._trace(trace_evidence),
            "candidates_total": self._candidates_total,
            "certificates_total": self._certificates_total,
            "retained_certificate_count": len(certificates),
            "certificates_truncated": self._certificates_total > len(certificates),
            "certified_total": self._certified_total,
            "incomplete_total": self._incomplete_total,
            "by_status": {CERTIFIED: self._certified_total,
                          INCOMPLETE: self._incomplete_total},
            "witness_counts": {hop: self._witness_counts[hop] for hop in UART_HOPS},
            "hop_event_counts": {kind: self._hop_event_counts.get(kind, 0)
                                 for kind in sorted(KIND_HOP)},
            "first_missing_hop_histogram": histogram,
            "first_missing_hop_histogram_reason": (
                None if histogram else "no_incomplete_candidate_was_tracked"),
            "irq_mode_histogram": irq_modes,
            "irq_mode_histogram_reason": (
                None if irq_modes else "no_candidate_was_tracked"),
            "refusals_total": sum(self._refusals.values()),
            "refusals_by_reason": {reason: count for reason, count
                                   in sorted(self._refusals.items())},
            "refused_hops": sorted(self._refused_hops),
            "refusals": [dict(row) for row in self._refusal_samples],
            "refusals_sampled": (sum(self._refusals.values())
                                 > len(self._refusal_samples)),
            "duplicates_total": sum(self._duplicates.values()),
            "duplicates_by_reason": {reason: count for reason, count
                                     in sorted(self._duplicates.items())},
            "unresolved_total": sum(self._unresolved.values()),
            "unresolved_by_reason": {reason: count for reason, count
                                     in sorted(self._unresolved.items())},
            "skipped_total": sum(self._skipped.values()),
            "skipped_by_reason": {reason: count for reason, count
                                  in sorted(self._skipped.items())},
            "evicted_total": self._evicted_total,
            "expired_total": self._expired_total,
            "contradicted_total": self._contradicted_total,
            "late_events_after_settlement": self._late_events,
            "certificates": certificates,
            "self_consistent": all(check["ok"] for check in checks),
            "self_consistency_checks": checks,
            "proof_scope": PROOF_SCOPE,
            "not_proof_of": list(_NOT_PROOF_OF),
        }

    # ------------------------------------------------------------- internals

    def _required(self) -> tuple:
        if self.require_irq_leg:
            return UART_HOPS
        return tuple(hop for hop in UART_HOPS if hop not in IRQ_HOPS)

    def _limits(self) -> list:
        return [
            {"name": "max_pending", "value": self.max_pending,
             "semantics": "unsettled candidates; the oldest is settled incomplete "
                          "with settled_reason=evicted_by_max_pending"},
            {"name": "max_event_gap", "value": self.max_event_gap,
             "semantics": "events a candidate may go without witnessing a new hop "
                          "before it settles incomplete with "
                          "settled_reason=event_gap_exceeded (progress window, "
                          "not an identity-index bound)"},
            {"name": "max_identities", "value": self.max_identities,
             "semantics": "retained entries per identity index (entries, frames, "
                          "receivers, pops, updates, assertions, deliveries, "
                          "samples, settled identities)"},
            {"name": "max_certificates", "value": self.max_certificates,
             "semantics": "certificate documents retained in the output; every "
                          "count still covers every emitted certificate"},
            {"name": "max_refusal_samples", "value": self.max_refusal_samples,
             "semantics": "refusal rows retained in the output; the histogram "
                          "always covers every refused join"},
        ]

    def _trace(self, trace_evidence: Mapping | None) -> dict:
        if trace_evidence is None:
            return {
                "attached": False, "path": None, "events_file": None,
                "format": None, "bytes": None,
                "events_ingested": self._last_event_id,
                "declared_event_count": None, "declared_status": None,
                "declared_semantic_sha256": None,
                "semantic_sha256_recomputed": None,
                "semantic_sha256_verified": None,
                "semantic_sha256_reason": "trace_not_attached_to_this_producer",
            }
        return dict(trace_evidence)

    def _cache_list(self) -> tuple:
        return (self._entries, self._frames, self._receivers, self._pops,
                self._updates, self._assertions, self._deliveries, self._samples,
                self._settled, self._settled_frames, self._settled_entries)

    def _store(self, cache: OrderedDict, key: object, entry: dict) -> None:
        cache[key] = entry
        while len(cache) > self.max_identities:
            cache.popitem(last=False)

    def _drain(self) -> list:
        drained, self._emitted = self._emitted, []
        return drained

    def _expire(self, event_id: int) -> None:
        """Progress-based candidate expiry; identity indexes are capacity-bounded.

        An identity index keeps the frame/entry/watermark identities it was told
        about until ``max_identities`` evicts the oldest, so a settled candidate
        can still be recognised (and refused) when a later event names it.
        """
        for admission_id, state in tuple(self._candidates.items()):
            if event_id - state["last_hop_event_id"] > self.max_event_gap:
                self._expired_total += 1
                self._settle(admission_id, INCOMPLETE, event_id,
                             "event_gap_exceeded")

    def _ensure_candidate(self, admission_id: object, event: Mapping) -> dict | None:
        """Create the candidate of one UART admission, or ``None`` when settled."""
        if not (type(admission_id) is str and admission_id):
            return None
        state = self._candidates.get(admission_id)
        if state is not None:
            return state
        if admission_id in self._settled:
            self._late_events += 1
            return None
        if len(self._candidates) >= self.max_pending:
            self._evicted_total += 1
            oldest = next(iter(self._candidates))
            self._settle(oldest, INCOMPLETE, event["event_id"],
                         "evicted_by_max_pending")
        state = {
            "admission_id": admission_id,
            "sequence": UART_HOPS,
            "required": self._required(),
            "hops": {},
            "last_hop_event_id": event["event_id"],
            "frame_id": None,
            "entry_id": None,
            "receiver_id": None,
            "byte": None,
            "case": None,
            "action_id": None,
            "role": None,
            "path_id": None,
            "input_sha256": None,
            "irq_keys": [],
            "irq_key_count": 0,
            "contradiction": None,
        }
        self._candidates[admission_id] = state
        self._candidates_total += 1
        return state

    def _attach(self, state: dict, hop_id: str, event_id: object, kind: str,
                evidence: Mapping) -> str | None:
        """Attach one hop at its declared position; ``None`` means attached."""
        if not _integer(event_id) or event_id <= 0 or event_id > self._last_event_id:
            return "hop_event_out_of_range"
        if hop_id in state["hops"]:
            return "duplicate_hop_witness"
        for other, entry in state["hops"].items():
            if (other, hop_id) in _ENFORCED_ORDER and entry["event_id"] >= event_id:
                return "hop_out_of_order"
            if (hop_id, other) in _ENFORCED_ORDER and event_id >= entry["event_id"]:
                return "hop_out_of_order"
        state["hops"][hop_id] = {"kind": kind, "event_id": event_id,
                                 "evidence": dict(evidence)}
        state["last_hop_event_id"] = max(state["last_hop_event_id"], event_id)
        return None

    def _duplicate(self, reason: str) -> None:
        self._duplicates[reason] = self._duplicates.get(reason, 0) + 1

    def _unresolved_count(self, reason: str) -> None:
        self._unresolved[reason] = self._unresolved.get(reason, 0) + 1

    def _skip(self, reason: str) -> None:
        self._skipped[reason] = self._skipped.get(reason, 0) + 1

    def _sample_refusal(self, reason: str, hop_id: str | None, event_id: int,
                        admission_id: str, frame_id: object,
                        certificate_id: object) -> None:
        if len(self._refusal_samples) >= self.max_refusal_samples:
            return
        self._refusal_samples.append({
            "reason": reason, "hop_id": hop_id, "event_id": event_id,
            "admission_id": admission_id, "frame_id": frame_id,
            "certificate_id": certificate_id,
        })

    def _refuse(self, state: dict, reason: str, hop_id: str | None,
                event_id: int) -> None:
        """Fail closed: count the refused join and settle the candidate now."""
        self._refusals[reason] = self._refusals.get(reason, 0) + 1
        if hop_id is not None:
            self._refused_hops.add(hop_id)
        admission_id = state["admission_id"]
        certificate_id = None
        if admission_id in self._candidates:
            state["contradiction"] = reason
            self._contradicted_total += 1
            settled = self._settle(admission_id, INCOMPLETE, event_id,
                                   "contradicted_join")
            if settled is not None:
                certificate_id = settled["certificate_id"]
        self._sample_refusal(reason, hop_id, event_id, admission_id,
                             state["frame_id"], certificate_id)

    def _refuse_settled(self, admission_id: str, reason: str,
                        hop_id: str | None, event_id: int) -> None:
        """A contradicting event that names an already settled candidate."""
        self._refusals[reason] = self._refusals.get(reason, 0) + 1
        if hop_id is not None:
            self._refused_hops.add(hop_id)
        record = self._settled.get(admission_id) or {}
        self._sample_refusal(reason, hop_id, event_id, admission_id, None,
                            record.get("certificate_id"))

    def _late_named(self, admission_id: str, event: Mapping,
                    hop_id: str | None = None, field: str | None = None,
                    value: object = None) -> bool:
        """Count an event naming a settled identity; refuse a contradicted join.

        Detection is bounded by the retained settled evidence index
        (``max_identities`` entries), exactly like every other identity index.
        """
        self._late_events += 1
        record = self._settled.get(admission_id)
        if record is None or hop_id is None or field is None:
            return False
        evidence = record["evidence"].get(hop_id)
        if evidence is None or field not in evidence:
            return False
        if not _same(evidence[field], value):
            self._refuse_settled(admission_id,
                                 "contradicts_settled_certificate", hop_id,
                                 event["event_id"])
            return True
        return False

    def _settle(self, admission_id: str, status: str, event_id: int,
                reason: str | None) -> dict | None:
        state = self._candidates.pop(admission_id, None)
        if state is None:
            return None
        certificate = self._render(state, status, event_id, reason)
        self._remember(state, certificate)
        self._emitted.append(certificate)
        return certificate

    def _remember(self, state: dict, certificate: dict) -> None:
        event_id = certificate["completed_event_id"]
        certificate_id = certificate["certificate_id"]
        evidence = {hop["hop_id"]: hop["evidence"] for hop in certificate["hops"]}
        self._store(self._settled, state["admission_id"],
                    {"event_id": event_id, "certificate_id": certificate_id,
                     "evidence": evidence})
        if state["frame_id"] is not None:
            self._store(self._settled_frames, state["frame_id"],
                        {"event_id": event_id, "certificate_id": certificate_id})
        if state["entry_id"] is not None:
            self._store(self._settled_entries, state["entry_id"],
                        {"event_id": event_id, "certificate_id": certificate_id})
        self._certificates_total += 1
        if certificate["status"] == CERTIFIED:
            self._certified_total += 1
        else:
            self._incomplete_total += 1
            first = certificate["first_missing_hop"]
            if first is not None:
                self._first_missing[first] = self._first_missing.get(first, 0) + 1
        self._irq_modes[certificate["irq_mode"]] = (
            self._irq_modes.get(certificate["irq_mode"], 0) + 1)
        for hop in certificate["witnessed_hop_ids"]:
            self._witness_counts[hop] += 1
        if len(self._certificates) < self.max_certificates:
            self._certificates.append(certificate)

    def _maybe_complete(self, state: dict) -> None:
        if state["admission_id"] not in self._candidates:
            return
        if all(hop in state["hops"] for hop in state["required"]):
            self._settle(state["admission_id"], CERTIFIED, self._last_event_id,
                         "required_hops_completed")

    # ---------------------------------------------------------- rendering

    def _irq_mode(self, state: dict) -> str:
        hops = state["hops"]
        if all(hop in hops for hop in IRQ_HOPS):
            return IRQ_TAKEN
        if "uart_irq_update" in hops or state["irq_key_count"]:
            return IRQ_ASSERTED_NO_TAKE
        return NO_IRQ_WITNESS

    @staticmethod
    def _irq_mode_reason(mode: str) -> str:
        return {
            IRQ_TAKEN: "cpu_external_irq_taken_joined_to_queue_head_entry",
            IRQ_ASSERTED_NO_TAKE:
                "watermark_asserted_while_entry_was_queue_head_without_a_"
                "joined_take",
            NO_IRQ_WITNESS:
                "no_watermark_assertion_named_this_entry_as_queue_head",
        }[mode]

    @staticmethod
    def _endpoint_case(state: dict) -> tuple:
        """First observed consumer case, in declared read-chain priority order."""
        for hop_id in ("uart_retired_read_match", "uart_rdata_access",
                       "uart_fifo_pop"):
            entry = state["hops"].get(hop_id)
            if entry is None:
                continue
            case = entry["evidence"].get("observed_case")
            if (isinstance(case, Mapping) and type(case.get("case_id")) is str
                    and _integer(case.get("case_index"))):
                return dict(case), hop_id
        return None, None

    def _render(self, state: dict, status: str, event_id: int,
                settled_reason: str | None) -> dict:
        sequence = state["sequence"]
        required = state["required"]
        hops = []
        missing = []
        # Frozen truncation rule (identical to the GPIO producer): ``hops`` is
        # the declared prefix up to the first absent required hop, and
        # ``missing_hops`` names every required hop absent from that prefix. A
        # hop witnessed *after* the first gap is therefore absent from ``hops``
        # and listed here too; ``witnessed_hop_ids`` says which have a witness.
        truncated = False
        for name in sequence:
            entry = state["hops"].get(name)
            if entry is not None and not truncated:
                hops.append({"hop_id": name, "kind": entry["kind"],
                             "event_id": entry["event_id"],
                             "evidence": dict(entry["evidence"])})
                continue
            if name not in required:
                continue
            if entry is None:
                truncated = True
            if truncated:
                missing.append(name)
        witnessed = [name for name in sequence if name in state["hops"]]
        ticks = {}
        for name in witnessed:
            evidence = state["hops"][name]["evidence"]
            component = evidence.get("component")
            tick = evidence.get("local_tick")
            if type(component) is str and _integer(tick):
                ticks[component] = tick
        endpoint, endpoint_source = self._endpoint_case(state)
        source_case = state["case"]
        if endpoint is None:
            cross_case, cross_case_reason = None, "endpoint_case_unknown"
        elif source_case is None:
            cross_case, cross_case_reason = None, "source_case_unknown"
        else:
            cross_case = (source_case["case_id"], source_case["case_index"]) != (
                endpoint["case_id"], endpoint["case_index"])
            cross_case_reason = (None if cross_case
                                 else "source_and_endpoint_case_ids_match")
        read_chain = (READ_CHAIN_WITNESSED
                      if all(hop in state["hops"] for hop in READ_HOPS)
                      else READ_CHAIN_INCOMPLETE)
        mode = self._irq_mode(state)
        if mode == IRQ_TAKEN:
            polling, polling_reason = False, "cpu_irq_take_joined_to_this_entry"
        elif read_chain == READ_CHAIN_WITNESSED:
            polling = True
            polling_reason = (
                "irq_asserted_without_a_joined_take_while_the_read_chain_completed"
                if mode == IRQ_ASSERTED_NO_TAKE else
                "read_chain_witnessed_without_any_irq_witness_for_this_entry")
        else:
            polling, polling_reason = None, "read_chain_not_witnessed"
        retirement = state["hops"].get("uart_retired_read_match")
        if retirement is None:
            insn = pc = register = None
            insn_reason = pc_reason = register_reason = (
                "uart_retired_read_match_absent")
        else:
            insn = retirement["evidence"].get("insn")
            insn_reason = None if _integer(insn) else "insn_not_recorded"
            pc = retirement["evidence"].get("pc")
            pc_reason = None if _integer(pc) else "pc_not_recorded"
            register = retirement["evidence"].get("destination_register")
            register_reason = (None if _integer(register)
                               else "destination_register_not_recorded")
        irq_hop = state["hops"].get("uart_cpu_irq_taken")
        irq_key = (irq_hop["evidence"].get("source_output_key")
                   if irq_hop is not None else None)
        first = missing[0] if missing else None
        return {
            "schema_version": SCHEMA_VERSION,
            "certificate_id": _certificate_id(state["admission_id"],
                                              state["frame_id"]),
            "status": status,
            "direction": DIRECTION,
            "source_admission_id": state["admission_id"],
            "source_action_id": state["action_id"],
            "source_component": UART_COMPONENT,
            "source_id": UART_SOURCE_ID,
            "source_role": state["role"],
            "source_case_id": source_case["case_id"] if source_case else None,
            "source_case_index": (source_case["case_index"]
                                  if source_case else None),
            "source_case_reason": (None if source_case
                                   else "source_admission_not_witnessed"),
            "source_path_id": state["path_id"],
            "source_input_sha256": state["input_sha256"],
            "source_admission_reason": (
                None if "uart_source_admission" in state["hops"]
                else "source_admission_not_witnessed"),
            "frame_id": state["frame_id"],
            "frame_id_reason": (None if state["frame_id"]
                                else "frame_admission_not_witnessed"),
            "entry_id": list(state["entry_id"]) if state["entry_id"] else None,
            "entry_id_reason": (None if state["entry_id"]
                                else "uart_fifo_push_not_witnessed"),
            "receiver_id": (list(state["receiver_id"])
                            if state["receiver_id"] else None),
            "receiver_id_reason": (None if state["receiver_id"]
                                   else "uart_rx_receiver_start_not_witnessed"),
            "byte": state["byte"],
            "byte_reason": (None if state["byte"] is not None
                            else "uart_fifo_push_not_witnessed"),
            "endpoint_case_id": endpoint["case_id"] if endpoint else None,
            "endpoint_case_index": endpoint["case_index"] if endpoint else None,
            "endpoint_case_source": endpoint_source,
            "endpoint_case_reason": (None if endpoint
                                     else "endpoint_case_not_witnessed"),
            "cross_case": cross_case,
            "cross_case_reason": cross_case_reason,
            "irq_mode": mode,
            "irq_mode_reason": self._irq_mode_reason(mode),
            "irq_source_output_key": (list(irq_key) if irq_key else None),
            "irq_source_output_key_reason": (
                None if irq_key else "cpu_irq_take_not_witnessed"),
            "irq_assertion_keys": [list(key) for key in state["irq_keys"]],
            "irq_assertion_key_count": state["irq_key_count"],
            "read_chain_state": read_chain,
            "read_chain_reason": (None if read_chain == READ_CHAIN_WITNESSED
                                  else "uart_fifo_pop_or_rdata_access_or_"
                                       "retired_read_match_absent"),
            "polling_consistent": polling,
            "polling_consistent_reason": polling_reason,
            "retirement_insn": insn,
            "retirement_insn_reason": insn_reason,
            "retirement_pc": pc,
            "retirement_pc_reason": pc_reason,
            "destination_register": register,
            "destination_register_reason": register_reason,
            "first_missing_hop": first,
            "first_missing_hop_reason": (None if first is not None
                                         else "all_required_hops_witnessed"),
            "missing_hops": [] if status == CERTIFIED else missing,
            "hops": hops,
            "witnessed_hop_ids": witnessed,
            "completed_event_id": event_id,
            "completed_local_ticks": ticks,
            "settled_reason": settled_reason,
            "contradiction_reason": state["contradiction"],
            "proof_scope": PROOF_SCOPE,
            "not_proof_of": list(_NOT_PROOF_OF),
        }

    def _self_consistency(self, certificates: list) -> list:
        checks = []

        def check(name: str, ok: bool, detail: str) -> None:
            checks.append({"check": name, "ok": bool(ok), "detail": detail})

        check("candidate_accounting",
              self._candidates_total
              == self._certified_total + self._incomplete_total,
              f"candidates={self._candidates_total} "
              f"certified={self._certified_total} "
              f"incomplete={self._incomplete_total}")
        bad_status = [row["certificate_id"] for row in certificates
                      if row["status"] not in (CERTIFIED, INCOMPLETE)]
        check("status_domain", not bad_status, f"invalid={bad_status}")
        complete = [row for row in certificates if row["status"] == CERTIFIED]
        check("certified_hops_complete",
              all(not row["missing_hops"]
                  and all(hop in row["witnessed_hop_ids"]
                          for hop in self._required())
                  for row in complete),
              f"certified={len(complete)}")
        check("incomplete_has_missing_hops",
              all(row["missing_hops"] for row in certificates
                  if row["status"] == INCOMPLETE),
              f"incomplete={self._incomplete_total}")
        check("first_missing_hop_agrees",
              all(row["first_missing_hop"] == row["missing_hops"][0]
                  for row in certificates if row["missing_hops"]),
              "first_missing_hop == missing_hops[0]")
        order_ok = True
        detail = "enforced hop edges strictly increase"
        for row in certificates:
            ids = {hop["hop_id"]: hop["event_id"] for hop in row["hops"]}
            for before, after in _ENFORCED_ORDER:
                if before in ids and after in ids and not ids[before] < ids[after]:
                    order_ok = False
                    detail = (f"{row['certificate_id']}: {before}="
                              f"{ids[before]} !< {after}={ids[after]}")
        check("hop_event_order", order_ok, detail)
        expected_histogram = {}
        for row in certificates:
            if row["status"] == INCOMPLETE and row["first_missing_hop"]:
                key = row["first_missing_hop"]
                expected_histogram[key] = expected_histogram.get(key, 0) + 1
        if self._certificates_total == len(certificates):
            check("first_missing_hop_histogram_agrees",
                  expected_histogram == self._first_missing,
                  f"{expected_histogram}")
        else:
            check("first_missing_hop_histogram_agrees", True,
                  "skipped: certificate documents truncated")
        total = sum(self._refusals.values())
        check("refusals_accounted",
              len(self._refusal_samples) == min(total, self.max_refusal_samples),
              f"refusals={total} sampled={len(self._refusal_samples)}")
        return checks

    # ----------------------------------------------------------- dispatch

    def _count_kind(self, event: Mapping) -> None:
        kind = event.get("kind")
        if kind not in KIND_HOP:
            return
        if kind == "source_admission":
            admission = event.get("admission")
            component = (admission.get("component")
                         if isinstance(admission, Mapping) else None)
            if component != UART_COMPONENT:
                return
        if kind == "source_injection" and (event.get("component") != UART_COMPONENT
                                           or event.get("port") != UART_PORT):
            return
        if kind == "uart_irq_update" and (event.get("component") != UART_COMPONENT
                                          or event.get("irq_class") != IRQ_CLASS):
            return
        self._hop_event_counts[kind] = self._hop_event_counts.get(kind, 0) + 1

    def _dispatch(self, event: Mapping) -> dict | None:
        kind = event.get("kind")
        self._count_kind(event)
        if kind == "source_admission":
            return self._admission(event)
        if kind == "source_injection":
            return self._injection(event)
        if kind == "uart_source_frame_admission":
            return self._frame_admission(event)
        if kind in ("uart_source_frame_begin", "uart_source_frame_end",
                    "uart_frame_validation"):
            return self._frame_record(event)
        if kind == "uart_rx_receiver_start":
            return self._receiver_start(event)
        if kind == "uart_rx_receiver_complete":
            return self._receiver_complete(event)
        if kind == "uart_fifo_push":
            return self._fifo_push(event)
        if kind == "uart_fifo_pop":
            return self._fifo_pop(event)
        if kind == "uart_irq_update":
            return self._irq_update(event)
        if kind == "uart_irq_output_definition":
            return self._irq_definition(event)
        if kind == "native_irq_binding_delivery":
            return self._irq_delivery(event)
        if kind == "cpu_external_irq_sample":
            return self._irq_sample(event)
        if kind == "cpu_external_irq_taken":
            return self._irq_take(event)
        if kind == "uart_rdata_access":
            return self._rdata_access(event)
        if kind == "uart_retired_read_match":
            return self._retired_read_match(event)
        return None

    # -------------------------------------------------------------- hops

    @staticmethod
    def _observed(event: Mapping) -> dict:
        evidence = {}
        if type(event.get("component")) is str:
            evidence["component"] = event["component"]
        if _integer(event.get("local_tick")):
            evidence["local_tick"] = event["local_tick"]
        case = _case(event)
        if case is not None:
            evidence["observed_case"] = case
        return evidence

    def _admission(self, event: Mapping) -> dict | None:
        try:
            admission = SourceAdmission.from_document(event.get("admission"))
        except (TypeError, ValueError):
            self._skip("malformed_source_admission")
            return None
        if (admission.component != UART_COMPONENT
                or admission.source_id != UART_SOURCE_ID
                or admission.direction != DIRECTION):
            return None
        if admission.role not in _UART_ADMISSION_ROLES:
            self._skip("unsupported_uart_admission_role")
            return None
        if admission.input_kind != "source_event":
            self._skip("unsupported_uart_admission_input_kind")
            return None
        if _case(event) != {"case_id": admission.case_id,
                            "case_index": admission.case_index}:
            self._skip("uart_admission_case_mismatch")
            return None
        provenance = event.get("provenance")
        if (not isinstance(provenance, Mapping)
                or provenance.get("origin_status") != "known"
                or provenance.get("origin_admission_ids")
                != [admission.admission_id]):
            self._skip("unproven_uart_admission_origin")
            return None
        state = self._ensure_candidate(admission.admission_id, event)
        if state is None:
            return None
        if state["action_id"] is not None and state["action_id"] != admission.action_id:
            self._refuse(state, "conflicting_source_admission",
                         "uart_source_admission", event["event_id"])
            return None
        state.update(
            action_id=admission.action_id,
            case={"case_id": admission.case_id,
                  "case_index": admission.case_index},
            role=admission.role, path_id=admission.path_id,
            input_sha256=admission.input_sha256)
        if "uart_source_admission" in state["hops"]:
            self._duplicate("duplicate_source_admission")
            return None
        evidence = dict(self._observed(event))
        evidence.update(admission_id=admission.admission_id,
                        action_id=admission.action_id, role=admission.role,
                        direction=admission.direction, source_id=admission.source_id,
                        path_id=admission.path_id, input_kind=admission.input_kind,
                        input_sha256=admission.input_sha256)
        self._attach(state, "uart_source_admission", event["event_id"],
                     "source_admission", evidence)
        return state

    def _injection(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        if event.get("port") != UART_PORT or event.get("direction") != DIRECTION:
            self._skip("unsupported_uart_injection_port")
            return None
        provenance = event.get("provenance")
        origins = (provenance.get("origin_admission_ids")
                   if isinstance(provenance, Mapping) else None)
        if (not isinstance(provenance, Mapping)
                or provenance.get("origin_status") != "known"
                or not isinstance(origins, list) or len(origins) != 1
                or not isinstance(origins[0], str)):
            self._skip("unproven_uart_injection_origin")
            return None
        if not _byte(event.get("value")) or event.get("bit_offset") != 0:
            self._skip("malformed_uart_injection")
            return None
        state = self._ensure_candidate(origins[0], event)
        if state is None:
            return None
        if state["action_id"] is None:
            state["action_id"] = event.get("action_id")
        elif state["action_id"] != event.get("action_id"):
            self._refuse(state, "conflicting_source_injection",
                         "uart_source_injection", event["event_id"])
            return None
        if "uart_source_injection" in state["hops"]:
            recorded = state["hops"]["uart_source_injection"]["evidence"]
            if recorded.get("value") != event["value"]:
                self._refuse(state, "conflicting_source_injection",
                             "uart_source_injection", event["event_id"])
                return None
            self._duplicate("duplicate_source_injection")
            return None
        evidence = dict(self._observed(event))
        evidence.update(action_id=event.get("action_id"), port=UART_PORT,
                        value=event["value"], bit_offset=0,
                        width=event.get("width"), source_ref=event.get("source_ref"))
        self._attach(state, "uart_source_injection", event["event_id"],
                     "source_injection", evidence)
        return state

    def _frame_admission(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        frame_id = event.get("frame_id")
        provenance = event.get("provenance")
        origins = (provenance.get("origin_admission_ids")
                   if isinstance(provenance, Mapping) else None)
        if (type(frame_id) is not str or not frame_id
                or not isinstance(provenance, Mapping)
                or provenance.get("origin_status") != "known"
                or not isinstance(origins, list) or len(origins) != 1
                or not isinstance(origins[0], str)
                or event.get("port") != UART_PORT
                or not _byte(event.get("byte"))):
            self._skip("malformed_uart_frame_admission")
            return None
        state = self._ensure_candidate(origins[0], event)
        if state is None:
            return None
        if state["action_id"] is None:
            state["action_id"] = event.get("action_id")
        elif state["action_id"] != event.get("action_id"):
            self._refuse(state, "conflicting_frame_admission",
                         "uart_frame_admission", event["event_id"])
            return None
        if state["frame_id"] is not None and state["frame_id"] != frame_id:
            self._refuse(state, "conflicting_frame_admission",
                         "uart_frame_admission", event["event_id"])
            return None
        state["frame_id"] = frame_id
        self._store(self._frames, frame_id,
                    {"event_id": event["event_id"],
                     "admission_id": state["admission_id"]})
        if "uart_frame_admission" in state["hops"]:
            recorded = state["hops"]["uart_frame_admission"]["evidence"]
            if recorded.get("byte") != event["byte"]:
                self._refuse(state, "uart_frame_byte_mismatch",
                             "uart_frame_admission", event["event_id"])
                return None
            self._duplicate("duplicate_frame_admission")
            return None
        if state["byte"] is not None and state["byte"] != event["byte"]:
            self._refuse(state, "uart_frame_byte_mismatch",
                         "uart_frame_admission", event["event_id"])
            return None
        evidence = dict(self._observed(event))
        evidence.update(frame_id=frame_id, action_id=event.get("action_id"),
                        byte=event["byte"], port=UART_PORT, bit_offset=0,
                        width=event.get("width"),
                        start_tick=event.get("start_tick"),
                        end_tick=event.get("end_tick"),
                        frame_semantics=event.get("frame_semantics"),
                        session_case_id=event.get("session_case_id"),
                        admission_id=state["admission_id"])
        self._attach(state, "uart_frame_admission", event["event_id"],
                     "uart_source_frame_admission", evidence)
        if state["byte"] is None:
            state["byte"] = event["byte"]
        return state

    def _frame_record(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        frame_id = event.get("frame_id")
        kind = event.get("kind")
        hop_id = KIND_HOP[kind]
        if type(frame_id) is not str or not frame_id \
                or event.get("port") != UART_PORT:
            self._skip("malformed_uart_frame_record")
            return None
        state = self._candidate_for_frame(frame_id, event, hop_id=hop_id,
                                          field="byte",
                                          value=event.get("byte"))
        if state is None:
            return None
        if kind in ("uart_source_frame_end", "uart_frame_validation"):
            if event.get("waveform_matched") is not True:
                self._refuse(state, "uart_waveform_not_matched", hop_id,
                             event["event_id"])
                return None
            if not _byte(event.get("byte")):
                self._refuse(state, "uart_frame_byte_mismatch", hop_id,
                             event["event_id"])
                return None
            if state["byte"] is not None and state["byte"] != event["byte"]:
                self._refuse(state, "uart_frame_byte_mismatch", hop_id,
                             event["event_id"])
                return None
            if state["byte"] is None:
                state["byte"] = event["byte"]
        if kind == "uart_frame_validation":
            admission_id = event.get("admission_id")
            if (not isinstance(admission_id, str)
                    or admission_id != state["admission_id"]
                    or event.get("action_id") != state["action_id"]):
                self._refuse(state, "frame_identity_mismatch", hop_id,
                             event["event_id"])
                return None
        if hop_id in state["hops"]:
            self._duplicate(f"duplicate_{kind}")
            return None
        evidence = dict(self._observed(event))
        evidence.update(frame_id=frame_id, action_id=event.get("action_id"),
                        byte=event.get("byte"), port=UART_PORT,
                        waveform_matched=event.get("waveform_matched"),
                        mismatch_count=event.get("mismatch_count"),
                        sample_count=event.get("sample_count"),
                        start_tick=event.get("start_tick"),
                        end_tick=event.get("end_tick"),
                        source_drive_ref_count=(
                            len(event["source_drive_refs"])
                            if isinstance(event.get("source_drive_refs"), list)
                            else None))
        if kind == "uart_frame_validation":
            evidence["admission_id"] = event.get("admission_id")
        self._attach(state, hop_id, event["event_id"], kind, evidence)
        return state

    def _receiver_start(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        receiver = _receiver_key(event.get("receiver_id"))
        ref = event.get("input_ref")
        if (receiver is None or not isinstance(ref, Mapping)
                or type(ref.get("frame_id")) is not str
                or not isinstance(ref.get("admission_id"), str)):
            self._skip("malformed_uart_receiver_start")
            return None
        state = self._candidate_for_frame(ref["frame_id"], event)
        if state is None:
            return None
        if ref["admission_id"] != state["admission_id"]:
            self._refuse(state, "receiver_admission_mismatch",
                         "uart_rx_receiver_start", event["event_id"])
            return None
        if state["action_id"] is not None \
                and ref.get("action_id") != state["action_id"]:
            self._refuse(state, "receiver_action_mismatch",
                         "uart_rx_receiver_start", event["event_id"])
            return None
        if state["receiver_id"] is not None and state["receiver_id"] != receiver:
            self._refuse(state, "receiver_identity_mismatch",
                         "uart_rx_receiver_start", event["event_id"])
            return None
        state["receiver_id"] = receiver
        self._store(self._receivers, receiver, {
            "event_id": event["event_id"],
            "admission_id": state["admission_id"], "frame_id": ref["frame_id"],
            "receiver_id": list(receiver), "config": event.get("config"),
            "observation_event_id": event.get("observation_event_id")})
        if "uart_rx_receiver_start" in state["hops"]:
            self._duplicate("duplicate_uart_rx_receiver_start")
            return None
        evidence = dict(self._observed(event))
        evidence.update(receiver_id=list(receiver), input_ref=dict(ref),
                        config=event.get("config"),
                        observation_event_id=event.get("observation_event_id"))
        self._attach(state, "uart_rx_receiver_start", event["event_id"],
                     "uart_rx_receiver_start", evidence)
        return state

    def _receiver_complete(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        receiver = _receiver_key(event.get("receiver_id"))
        start = self._receivers.get(receiver) if receiver is not None else None
        if start is None or start.get("completion_event") is not None:
            self._unresolved_count("receiver_complete_without_a_witnessed_start")
            return None
        state = self._candidates.get(start["admission_id"])
        if state is None:
            self._late_named(start["admission_id"], event,
                             "uart_rx_receiver_complete", "value",
                             event.get("value"))
            return None
        if event.get("frame_error") != 0 or event.get("parity_error") != 0:
            self._refuse(state, "receiver_error_flags",
                         "uart_rx_receiver_complete", event["event_id"])
            return None
        if not _byte(event.get("value")):
            self._refuse(state, "receiver_byte_mismatch",
                         "uart_rx_receiver_complete", event["event_id"])
            return None
        if state["byte"] is not None and state["byte"] != event["value"]:
            self._refuse(state, "receiver_byte_mismatch",
                         "uart_rx_receiver_complete", event["event_id"])
            return None
        if state["byte"] is None:
            state["byte"] = event["value"]
        self._store(self._receivers, receiver, dict(
            start, completed_event_id=event["event_id"],
            completion_event=event.get("observation_event_id"),
            completion_value=event["value"]))
        if "uart_rx_receiver_complete" in state["hops"]:
            self._duplicate("duplicate_uart_rx_receiver_complete")
            return None
        evidence = dict(self._observed(event))
        evidence.update(receiver_id=list(receiver), value=event["value"],
                        frame_error=0, parity_error=0,
                        sample_ref_count=(len(event["sample_refs"])
                                          if isinstance(event.get("sample_refs"),
                                                        list) else None),
                        observation_event_id=event.get("observation_event_id"))
        self._attach(state, "uart_rx_receiver_complete", event["event_id"],
                     "uart_rx_receiver_complete", evidence)
        return state

    def _fifo_push(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        frame_id = event.get("frame_id")
        if type(frame_id) is not str or not frame_id:
            self._skip("unrouted_uart_fifo_push")
            return None
        state = self._candidate_for_frame(frame_id, event,
                                          hop_id="uart_fifo_push",
                                          field="entry_id",
                                          value=event.get("entry_id"))
        if state is None:
            return None
        entry = _entry_id(event.get("entry_id"), UART_COMPONENT,
                          event.get("reset_epoch") if _integer(
                              event.get("reset_epoch")) else 0)
        receiver = _receiver_key(event.get("receiver_id"))
        if entry is None or receiver is None or not _byte(event.get("value")):
            self._refuse(state, "malformed_uart_fifo_push", "uart_fifo_push",
                         event["event_id"])
            return None
        start = self._receivers.get(receiver)
        if start is None or start.get("completion_event") is None:
            self._unresolved_count(
                "uart_fifo_push_without_a_witnessed_receiver_complete")
            return None
        if (start["admission_id"] != state["admission_id"]
                or start["frame_id"] != frame_id):
            self._refuse(state, "receiver_identity_mismatch", "uart_fifo_push",
                         event["event_id"])
            return None
        if state["byte"] is not None and state["byte"] != event["value"]:
            self._refuse(state, "receiver_byte_mismatch", "uart_fifo_push",
                         event["event_id"])
            return None
        if event.get("completion_event") != start.get("completion_event"):
            self._refuse(state, "receiver_completion_mismatch", "uart_fifo_push",
                         event["event_id"])
            return None
        if start.get("completion_value") != event["value"]:
            self._refuse(state, "receiver_byte_mismatch", "uart_fifo_push",
                         event["event_id"])
            return None
        if event.get("retained") is not True:
            self._unresolved_count("unretained_uart_fifo_push")
            return None
        if state["entry_id"] is not None and state["entry_id"] != entry:
            self._refuse(state, "conflicting_uart_fifo_push", "uart_fifo_push",
                         event["event_id"])
            return None
        if "uart_fifo_push" in state["hops"]:
            recorded = state["hops"]["uart_fifo_push"]["evidence"]
            if recorded.get("entry_id") != list(entry):
                self._refuse(state, "conflicting_uart_fifo_push",
                             "uart_fifo_push", event["event_id"])
                return None
            self._duplicate("duplicate_uart_fifo_push")
            return None
        state["entry_id"] = entry
        state["receiver_id"] = receiver
        if state["byte"] is None:
            state["byte"] = event["value"]
        self._store(self._entries, entry, {
            "event_id": event["event_id"], "admission_id": state["admission_id"],
            "frame_id": frame_id, "entry_id": list(entry),
            "value": event["value"], "receiver_id": list(receiver)})
        evidence = dict(self._observed(event))
        evidence.update(entry_id=list(entry), value=event["value"],
                        frame_id=frame_id, receiver_id=list(receiver),
                        completion_event=event.get("completion_event"),
                        retained=True,
                        observation_event_id=event.get("observation_event_id"))
        self._attach(state, "uart_fifo_push", event["event_id"],
                     "uart_fifo_push", evidence)
        return state

    def _fifo_pop(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        entry = _entry_id(event.get("entry_id"), UART_COMPONENT,
                          event.get("reset_epoch") if _integer(
                              event.get("reset_epoch")) else 0)
        record = self._entries.get(entry) if entry is not None else None
        if record is None:
            self._unresolved_count("uart_fifo_pop_without_a_witnessed_push")
            return None
        state = self._candidates.get(record["admission_id"])
        if state is None:
            self._late_named(record["admission_id"], event, "uart_fifo_pop",
                             "value", event.get("value"))
            return None
        access = event.get("access")
        if (not isinstance(access, Mapping)
                or access.get("raw_offset") != RXFIFO_OFFSET
                or access.get("write") is not False
                or access.get("byte_enable") != FIFO_BYTE_ENABLE
                or not isinstance(access.get("access_id"), str)
                or _transaction_key(access.get("source_transaction")) is None):
            self._refuse(state, "unproven_uart_routed_access", "uart_fifo_pop",
                         event["event_id"])
            return None
        if event.get("value") != record["value"]:
            self._refuse(state, "uart_fifo_value_mismatch", "uart_fifo_pop",
                         event["event_id"])
            return None
        if "uart_fifo_pop" in state["hops"]:
            self._refuse(state, "duplicate_uart_fifo_pop", "uart_fifo_pop",
                         event["event_id"])
            return None
        evidence = dict(self._observed(event))
        evidence.update(entry_id=list(entry), value=event["value"],
                        access_id=access.get("access_id"),
                        source_transaction=access.get("source_transaction"),
                        address=access.get("address"),
                        raw_offset=RXFIFO_OFFSET, byte_enable=FIFO_BYTE_ENABLE,
                        window_base=access.get("window_base"),
                        window_size=access.get("window_size"),
                        route_context_mode=access.get("route_context_mode"),
                        clear=event.get("clear"),
                        observation_event_id=event.get("observation_event_id"))
        self._attach(state, "uart_fifo_pop", event["event_id"], "uart_fifo_pop",
                     evidence)
        observation = event.get("observation_event_id")
        if _integer(observation):
            self._store(self._pops, observation, {
                "event_id": event["event_id"],
                "admission_id": state["admission_id"], "entry_id": list(entry),
                "value": event["value"], "access": dict(access)})
        return state

    def _rdata_access(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        request_event = event.get("actual_request_event_id")
        pop = self._pops.get(request_event) if _integer(request_event) else None
        if pop is None:
            self._unresolved_count("uart_rdata_access_without_a_witnessed_pop")
            return None
        state = self._candidates.get(pop["admission_id"])
        if state is None:
            self._late_named(pop["admission_id"], event, "uart_rdata_access",
                             "read_value", event.get("read_value"))
            return None
        access = pop["access"]
        key = _transaction_key(event.get("source_transaction"))
        window_base = event.get("window_base")
        if (event.get("raw_offset") != RXFIFO_OFFSET
                or event.get("write") is not False
                or event.get("byte_enable") != FIFO_BYTE_ENABLE
                or not _integer(window_base)
                or not _integer(event.get("address")) or key is None
                or not isinstance(event.get("access_id"), str)
                or not event["access_id"]):
            self._refuse(state, "unproven_uart_routed_access",
                         "uart_rdata_access", event["event_id"])
            return None
        if (event.get("access_id") != access.get("access_id")
                or _transaction_key(access.get("source_transaction")) != key
                or event.get("address") != access.get("address")
                or event.get("address") != window_base + RXFIFO_OFFSET
                or event.get("read_value") != pop["value"]):
            self._refuse(state, "uart_rdata_access_mismatch",
                         "uart_rdata_access", event["event_id"])
            return None
        if "uart_rdata_access" in state["hops"]:
            self._refuse(state, "duplicate_uart_rdata_access",
                         "uart_rdata_access", event["event_id"])
            return None
        command_scope = event.get("command_scope")
        evidence = dict(self._observed(event))
        evidence.update(access_id=event["access_id"],
                        source_transaction=list(key), address=event["address"],
                        raw_offset=RXFIFO_OFFSET,
                        byte_enable=FIFO_BYTE_ENABLE,
                        read_value=event["read_value"], error=0,
                        window_base=window_base,
                        window_size=event.get("window_size"),
                        route_context_mode=event.get("route_context_mode"),
                        request_tick=event.get("request_tick"),
                        response_tick=event.get("response_tick"),
                        command_sequence=(command_scope.get("command_sequence")
                                          if isinstance(command_scope, Mapping)
                                          else None),
                        actual_request_event_id=request_event,
                        actual_response_event_id=event.get(
                            "actual_response_event_id"))
        self._attach(state, "uart_rdata_access", event["event_id"],
                     "uart_rdata_access", evidence)
        return state

    def _retired_read_match(self, event: Mapping) -> dict | None:
        if (event.get("status") != "accepted"
                or event.get("proof_scope") != "cpu_retired_uart_rdata_read"):
            self._skip("unproven_uart_retired_read_match")
            return None
        entry = _entry_id(event.get("entry_id"), UART_COMPONENT,
                          event.get("reset_epoch") if _integer(
                              event.get("reset_epoch")) else 0)
        if entry is None:
            self._skip("malformed_uart_retired_read_match")
            return None
        record = self._entries.get(entry)
        if record is None:
            self._unresolved_count("uart_retired_read_match_without_a_push")
            return None
        state = self._candidates.get(record["admission_id"])
        if state is None:
            self._late_named(record["admission_id"], event,
                             "uart_retired_read_match", "read_value",
                             event.get("read_value"))
            return None
        access = state["hops"].get("uart_rdata_access")
        if access is None:
            self._unresolved_count("uart_retired_read_match_without_a_read")
            return None
        evidence = access["evidence"]
        if (event.get("frame_id") != state["frame_id"]
                or event.get("uart_access_event_id") != access["event_id"]
                or event.get("uart_request_event_id")
                != evidence.get("actual_request_event_id")
                or event.get("uart_response_event_id")
                != evidence.get("actual_response_event_id")
                or event.get("read_value") != evidence.get("read_value")):
            self._refuse(state, "retired_read_value_mismatch",
                         "uart_retired_read_match", event["event_id"])
            return None
        key = _transaction_key(event.get("fullkey"))
        if key is None or list(key) != list(evidence.get("source_transaction") or ()):
            self._refuse(state, "retired_read_transaction_mismatch",
                         "uart_retired_read_match", event["event_id"])
            return None
        admission = event.get("source_admission")
        if (not isinstance(admission, Mapping)
                or admission.get("admission_id") != state["admission_id"]):
            self._refuse(state, "retired_read_admission_mismatch",
                         "uart_retired_read_match", event["event_id"])
            return None
        take = state["hops"].get("uart_cpu_irq_taken")
        scope = event.get("cpu_scope")
        if take is not None and isinstance(scope, Mapping):
            if (scope.get("source_component") != take["evidence"].get("component")
                    or scope.get("source_epoch")
                    != take["evidence"].get("reset_epoch")):
                self._refuse(state, "cpu_irq_take_scope_mismatch",
                             "uart_cpu_irq_taken", event["event_id"])
                return None
        if "uart_retired_read_match" in state["hops"]:
            self._duplicate("duplicate_uart_retired_read_match")
            return None
        reading = dict(self._observed(event))
        reading.update(entry_id=list(entry), frame_id=event.get("frame_id"),
                       read_value=event.get("read_value"),
                       destination_register=event.get("destination_register"),
                       insn=event.get("insn"), pc=event.get("pc"),
                       order=event.get("order"),
                       retirement_event_id=event.get("retirement_event_id"),
                       retirement_match_event_id=event.get(
                           "retirement_match_event_id"),
                       uart_read_proof_event_id=event.get(
                           "uart_read_proof_event_id"),
                       uart_access_event_id=event.get("uart_access_event_id"),
                       uart_request_event_id=event.get("uart_request_event_id"),
                       uart_response_event_id=event.get(
                           "uart_response_event_id"),
                       cpu_scope=dict(scope) if isinstance(scope, Mapping) else None,
                       execution_id=(scope.get("execution_id")
                                     if isinstance(scope, Mapping) else None),
                       graph_path_certified=event.get("graph_path_certified"),
                       path_id=event.get("path_id"), fullkey=list(key))
        self._attach(state, "uart_retired_read_match", event["event_id"],
                     "uart_retired_read_match", reading)
        return state

    # ------------------------------------------------------------ IRQ leg

    def _irq_update(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        if event.get("irq_class") != IRQ_CLASS:
            self._skip("non_watermark_uart_irq_update")
            return None
        self._store(self._updates, event["event_id"], {
            "event_id": event["event_id"], "component": UART_COMPONENT,
            "reset_epoch": event.get("reset_epoch"),
            "local_tick": event.get("local_tick"), "irq_class": IRQ_CLASS,
            "pre_output": event.get("pre_output"),
            "post_output": event.get("post_output"),
            "pre_event": event.get("pre_event"),
            "pre_state": event.get("pre_state"),
            "pre_enable": event.get("pre_enable"),
            "pre_watermark_test": event.get("pre_watermark_test"),
            "watermark_threshold": event.get("watermark_threshold"),
            "pre_depth": event.get("pre_depth"),
            "pre_entry_ids": event.get("pre_entry_ids")})
        return None

    def _irq_definition(self, event: Mapping) -> dict | None:
        if event.get("component") != UART_COMPONENT:
            return None
        key = _source_output_key(event.get("source_output_key"))
        entries = event.get("pre_entry_ids")
        version = event.get("value")
        update_id = event.get("irq_update_event_id")
        if (key is None or type(entries) is not list
                or not _integer(version) or version not in (0, 1)
                or not _integer(update_id)
                or not all(_entry_id(entry, UART_COMPONENT, key[1]) is not None
                           for entry in entries)
                or event.get("trusted_definition") is not True):
            self._skip("malformed_uart_irq_definition")
            return None
        update = self._updates.get(update_id)
        if update is None:
            self._unresolved_count("uart_irq_definition_without_its_update")
            return None
        if (update["reset_epoch"] != key[1] or update["post_output"] != version
                or update["pre_entry_ids"] != entries
                or update["irq_class"] != IRQ_CLASS):
            self._unresolved_count("uart_irq_definition_update_mismatch")
            return None
        record = {"event_id": event["event_id"], "source_output_key": list(key),
                  "version": key[3], "value": version,
                  "pre_entry_ids": [list(entry) for entry in entries],
                  "update_event_id": update_id,
                  "definition_observation_event_id": event.get(
                      "definition_observation_event_id"),
                  "pre_depth": update.get("pre_depth"),
                  "local_tick": event.get("local_tick")}
        self._store(self._assertions, key, record)
        if version != 1 or not entries:
            return None
        touched = None
        for position, entry in enumerate(entries):
            candidate = self._entries.get(tuple(entry))
            if candidate is None:
                continue
            state = self._candidates.get(candidate["admission_id"])
            if state is None:
                continue
            if position != 0:
                self._unresolved_count("uart_irq_definition_entry_not_at_head")
                continue
            touched = self._assert_watermark(state, record, update_id) or touched
        return touched

    def _assert_watermark(self, state: dict, record: Mapping,
                          update_id: int) -> dict | None:
        self._note_irq_key(state, record["source_output_key"])
        if "uart_irq_update" in state["hops"]:
            self._duplicate("duplicate_uart_irq_assertion")
            return None
        evidence = {"component": UART_COMPONENT,
                    "source_output_key": list(record["source_output_key"]),
                    "version": record["version"],
                    "post_output": record["value"],
                    "pre_depth": record.get("pre_depth"),
                    "pre_entry_ids": [list(entry)
                                      for entry in record["pre_entry_ids"]],
                    "definition_event_id": record["event_id"],
                    "definition_observation_event_id":
                        record.get("definition_observation_event_id"),
                    "local_tick": record.get("local_tick"),
                    "attribution": "queue_head_entry"}
        reason = self._attach(state, "uart_irq_update", update_id,
                              "uart_irq_update", evidence)
        if reason is not None and reason != "duplicate_hop_witness":
            self._refuse(state, reason, "uart_irq_update", update_id)
            return None
        return state

    @staticmethod
    def _note_irq_key(state: dict, key: object) -> None:
        if not isinstance(key, list):
            return
        state["irq_key_count"] += 1
        if len(state["irq_keys"]) < 4 and key not in state["irq_keys"]:
            state["irq_keys"].append(list(key))

    def _irq_delivery(self, event: Mapping) -> dict | None:
        if (event.get("source_component") != UART_COMPONENT
                or event.get("irq_class") != IRQ_CLASS):
            return None
        self._store(self._deliveries, event["event_id"], {
            "event_id": event["event_id"],
            "source_component": event.get("source_component"),
            "source_epoch": event.get("source_epoch"),
            "source_local_tick": event.get("source_local_tick"),
            "source_phase": event.get("source_phase"),
            "source_port": event.get("source_port"),
            "source_observation_event_id": event.get("source_observation_event_id"),
            "source_output_key": event.get("source_output_key"),
            "target_component": event.get("target_component"),
            "target_epoch": event.get("target_epoch"),
            "target_port": event.get("target_port"),
            "width": event.get("width"),
            "source_bit_offset": event.get("source_bit_offset"),
            "target_bit_offset": event.get("target_bit_offset"),
            "value": event.get("value"),
            "dataflow_delivery_event_id": event.get("dataflow_delivery_event_id")})
        return None

    def _irq_sample(self, event: Mapping) -> dict | None:
        if event.get("component") != CPU_COMPONENT:
            return None
        self._store(self._samples, event["event_id"], {
            "event_id": event["event_id"], "component": event.get("component"),
            "reset_epoch": event.get("reset_epoch"),
            "local_tick": event.get("local_tick"),
            "command_scope": event.get("command_scope"),
            "receipt_id": event.get("receipt_id"),
            "expected_input": event.get("expected_input"),
            "actual_pre_input": event.get("actual_pre_input"),
            "actual_post_input": event.get("actual_post_input"),
            "irq_masked_pre": event.get("irq_masked_pre"),
            "irq_taken_pre": event.get("irq_taken_pre"),
            "binding_delivery_event_id": event.get("binding_delivery_event_id"),
            "source_output_key": event.get("source_output_key")})
        return None

    def _irq_take(self, event: Mapping) -> dict | None:
        if event.get("component") != CPU_COMPONENT:
            return None
        context = event.get("input_context")
        key = _source_output_key(event.get("source_output_key"))
        if (not isinstance(context, Mapping)
                or context.get("schema_version") != IRQ_INPUT_CONTEXT_SCHEMA
                or context.get("source_output_key") != event.get("source_output_key")
                or context.get("target_component") != event.get("component")
                or context.get("target_epoch") != event.get("reset_epoch")
                or context.get("binding_delivery_event_id")
                != event.get("binding_delivery_event_id")
                or context.get("expected_input") != 1 or key is None):
            self._skip("malformed_cpu_irq_take")
            return None
        sample = self._samples.get(event.get("sample_event_id"))
        delivery = self._deliveries.get(event.get("binding_delivery_event_id"))
        assertion = self._assertions.get(key)
        if sample is None or delivery is None:
            self._unresolved_count("cpu_irq_take_without_its_sample_or_delivery")
            return None
        entries = assertion["pre_entry_ids"] if assertion is not None else []
        record = self._entries.get(tuple(entries[0])) if entries else None
        state = (self._candidates.get(record["admission_id"])
                 if record is not None else None)
        if state is None:
            if record is not None:
                self._late_named(record["admission_id"], event,
                                 "uart_cpu_irq_taken", "source_output_key",
                                 event.get("source_output_key"))
            else:
                self._unresolved_count("cpu_irq_take_without_a_queue_head_entry")
            return None
        self._note_irq_key(state, list(key))
        if (not _same(event.get("command_scope"), sample.get("command_scope"))
                or not _same(event.get("receipt_id"), sample.get("receipt_id"))
                or event.get("local_tick") != sample.get("local_tick")
                or event.get("reset_epoch") != sample.get("reset_epoch")
                or sample.get("binding_delivery_event_id") != delivery["event_id"]
                or not _same(sample.get("source_output_key"), list(key))
                or not _same(delivery.get("source_output_key"), list(key))):
            self._refuse(state, "uart_irq_sample_mismatch", "uart_cpu_irq_sample",
                         event["event_id"])
            return None
        if (sample.get("expected_input") != 1 or sample.get("actual_pre_input") != 1
                or sample.get("actual_post_input") != 1
                or sample.get("irq_masked_pre") != 0
                or sample.get("irq_taken_pre") != 1):
            self._refuse(state, "cpu_irq_sample_not_taken", "uart_cpu_irq_sample",
                         event["event_id"])
            return None
        if (delivery.get("value") != 1 or delivery.get("source_epoch") != key[1]
                or delivery.get("target_component") != event.get("component")
                or delivery.get("target_epoch") != event.get("reset_epoch")
                or delivery.get("source_port") != IRQ_SOURCE_PORT
                or delivery.get("target_port") != IRQ_TARGET_PORT
                or delivery.get("width") != 1
                or delivery.get("source_bit_offset") != 0
                or delivery.get("target_bit_offset") != 0):
            self._refuse(state, "uart_irq_delivery_mismatch",
                         "uart_irq_binding_delivery", event["event_id"])
            return None
        if assertion is None:
            self._unresolved_count("cpu_irq_take_without_its_definition")
            return None
        if assertion["value"] != 1:
            self._refuse(state, "uart_irq_definition_not_asserted",
                         "uart_irq_update", event["event_id"])
            return None
        delivery_evidence = {
            "component": UART_COMPONENT, "source_output_key": list(key),
            "value": 1, "width": 1, "source_port": IRQ_SOURCE_PORT,
            "target_port": IRQ_TARGET_PORT,
            "target_component": event.get("component"),
            "target_epoch": event.get("reset_epoch"),
            "source_local_tick": delivery.get("source_local_tick"),
            "source_phase": delivery.get("source_phase"),
            "source_observation_event_id": delivery.get(
                "source_observation_event_id"),
            "dataflow_delivery_event_id": delivery.get(
                "dataflow_delivery_event_id")}
        sample_evidence = {
            "component": CPU_COMPONENT, "reset_epoch": sample.get("reset_epoch"),
            "local_tick": sample.get("local_tick"),
            "command_scope": sample.get("command_scope"),
            "receipt_id": sample.get("receipt_id"), "expected_input": 1,
            "actual_pre_input": 1, "actual_post_input": 1, "irq_masked_pre": 0,
            "irq_taken_pre": 1, "binding_delivery_event_id": delivery["event_id"],
            "source_output_key": list(key)}
        observation = event.get("irq_serial_observation")
        decision = (observation.get("decision")
                    if isinstance(observation, Mapping) else None)
        retirement = (observation.get("retirement")
                      if isinstance(observation, Mapping) else None)
        take_evidence = {
            "component": CPU_COMPONENT, "reset_epoch": event.get("reset_epoch"),
            "local_tick": event.get("local_tick"),
            "command_scope": event.get("command_scope"),
            "take_key": event.get("take_key"),
            "sample_event_id": sample["event_id"],
            "binding_delivery_event_id": delivery["event_id"],
            "source_output_key": list(key),
            "decision_serial": decision.get("value") if isinstance(
                decision, Mapping) else None,
            "retirement_serial": retirement.get("value") if isinstance(
                retirement, Mapping) else None,
            "irq_serial_observation_schema": (
                observation.get("schema_version")
                if isinstance(observation, Mapping) else None),
            "zero_semantics": (observation.get("zero_semantics")
                               if isinstance(observation, Mapping) else None)}
        for hop_id, hop_event, kind, evidence in (
                ("uart_irq_binding_delivery", delivery["event_id"],
                 "native_irq_binding_delivery", delivery_evidence),
                ("uart_cpu_irq_sample", sample["event_id"],
                 "cpu_external_irq_sample", sample_evidence),
                ("uart_cpu_irq_taken", event["event_id"],
                 "cpu_external_irq_taken", take_evidence)):
            reason = self._attach(state, hop_id, hop_event, kind, evidence)
            if reason is not None and reason != "duplicate_hop_witness":
                self._refuse(state, reason, hop_id, event["event_id"])
                return None
        return state

    # ------------------------------------------------------------ helpers

    def _candidate_for_frame(self, frame_id: str, event: Mapping, *,
                             hop_id: str | None = None,
                             field: str | None = None,
                             value: object = None) -> dict | None:
        record = self._frames.get(frame_id)
        if record is None:
            self._unresolved_count("event_without_a_witnessed_frame_admission")
            return None
        state = self._candidates.get(record["admission_id"])
        if state is None:
            self._late_named(record["admission_id"], event, hop_id, field, value)
            return None
        return state


# --------------------------------------------------------------------------
# read-only run scan
# --------------------------------------------------------------------------


def _trace_evidence(stream: TraceEventStream) -> dict:
    """Canonical trace block: observed counts plus honest nulls with reasons."""
    declared = stream.declared_semantic_sha256()
    recomputed = stream.semantic_sha256()
    if declared is None:
        verified, reason = None, "artifact_declares_no_semantic_sha256"
    elif recomputed is None:
        verified, reason = None, "artifact_declares_no_local_ticks_or_status"
    else:
        verified, reason = declared == recomputed, None
    return {
        "attached": True,
        "path": str(stream.path),
        "events_file": stream.descriptor["events_file"],
        "format": stream.descriptor["format"],
        "bytes": stream.descriptor["bytes"],
        "events_ingested": stream.event_count,
        "declared_event_count": stream.descriptor["declared_event_count"],
        "declared_status": stream.declared_status(),
        "declared_semantic_sha256": declared,
        "semantic_sha256_recomputed": recomputed,
        "semantic_sha256_verified": verified,
        "semantic_sha256_reason": reason,
    }


def uart_chain_certificates(run_dir, *, max_pending: int = 128,
                            max_event_gap: int = 65536, max_identities: int = 4096,
                            max_certificates: int = 2048,
                            require_irq_leg: bool = True,
                            chunk_chars: int | None = None,
                            verify_semantic: bool = True) -> dict:
    """Stream one saved run directory once and return the UART chain document."""
    options = {} if chunk_chars is None else {"chunk_chars": chunk_chars}
    stream = TraceEventStream(run_dir, verify_semantic=verify_semantic, **options)
    producer = UartChainCertificates(
        max_pending=max_pending, max_event_gap=max_event_gap,
        max_identities=max_identities, max_certificates=max_certificates,
        require_irq_leg=require_irq_leg)
    producer.ingest(stream.events())
    producer.flush()
    return producer.document(trace_evidence=_trace_evidence(stream))


__all__ = [
    "CERTIFIED", "DIRECTION", "INCOMPLETE", "IRQ_ASSERTED_NO_TAKE", "IRQ_HOPS",
    "IRQ_TAKEN", "KIND_HOP", "NO_IRQ_WITNESS", "PROOF_SCOPE",
    "READ_CHAIN_INCOMPLETE", "READ_CHAIN_WITNESSED", "SCHEMA_VERSION",
    "UART_HOPS", "UART_HOP_ORDER", "UartChainCertificates",
    "uart_chain_certificates",
]
