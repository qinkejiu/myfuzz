"""Exact-identity ISR GPIO A writeback endpoint certificates (additive, read-only).

Boundary this module closes
---------------------------

The shipped P5 chain producer (:mod:`myfuzz.scenario.chain_certificates`) ends
``CPU_TO_IP_TO_CPU`` at the admitted instruction's ``retired_target_delivery``
and ``IP_TO_CPU_TO_IP`` at ``isr_padin_retirement``. Both terminal hops are read
by the CPU *inside the handler*, yet neither certificate contains the handler's
own write back to GPIO A (``PADOUT``) nor the A->B reflow that write drives.
The P5 report states that boundary explicitly.

What is certifiable today, and what is not
------------------------------------------

A real run journals the handler write as a complete local record set. Every hop
of the *downstream* consequence is joinable by an exact field identity:

``handler_mmio_acceptance``
    ``mmio_acceptance`` (cpu, ``gpio_a``, offset 12, ``write`` true), joined to
    the target side by the six-field transaction key
    ``(channel_id, execution_id, source_component, source_epoch,
    source_sequence, testcase_id)``.
``handler_register_commit``
    ``gpio_a`` ``out`` register commit, joined by the same access id, by
    ``observation_event_id == gpio_apb_access.event_id`` and by the transaction
    key repeated on every committed bit resource.
``binding_segment``
    ``gpio_input_applied`` on ``gpio_b`` whose segment origin repeats the
    committed bit identity ``(component, register, bit, version,
    observation_event_id)`` in ``producer_resource_refs``.
``binding_input_resource``
    ``gpio_input_applied_resource`` on ``gpio_b`` whose bit resource names the
    same committed bit identity in ``origin_refs`` with ``origin_status``
    ``known`` and yields the bound input bit version.
``bound_irq_trigger``
    ``gpio_irq_trigger`` on ``gpio_b`` whose cause ``current_sample.origin_refs``
    names the same committed bit identity; the trigger id is the identity.
``handler_retirement`` / ``handler_retirement_match`` / ``handler_target_delivery``
    ``cpu_retire``, ``cpu_retirement_match`` and
    ``cpu_retired_transaction_target_delivery`` joined by the transaction key,
    by ``producer_event_id`` / ``retirement_event_id`` and by the target access
    id, with ``mem_addr``/``mem_wmask``/``mem_wdata`` equal to the acceptance
    ``address``/``byte_enable``/``write_value``.
``bound_irq_observation`` / ``bound_cpu_irq_input``
    ``gpio_irq_observation`` and ``cpu_irq_input`` joined by the exact trigger id
    and by ``source_trigger.trigger_event_id``.

That fragment is what the artifacts genuinely support, and it is what this
module certifies.

The *upstream* join into a P5 chain does **not** exist today and is never
invented here. The handler write's retirement delivery reports
``registered_origin_status == "unknown"`` with empty ``registered_origins`` and
``source_refs``, handler execution has no ``source_admission`` record, and no
field anywhere on the handler path names the interrupt take
(``cpu_irq_taken.cpu_step_event_id`` / ``source_trigger.trigger_id``) or the
handler instance. ``cpu_irq_taken``, the handler retirements, the MMIO records
and the register commits are therefore related only by event adjacency/ordering
and by the program-counter image span, and neither is accepted as a join.
:func:`audit_chain_extension` states that per chain with the exact attempt keys,
and its positive branch is exercised by a synthetic journal that journals the
missing identity, so the audit is not rigged to refuse.

Bounded and fail-closed
-----------------------

At most ``max_pending`` open candidates, at most ``max_writebacks`` retained
writeback identities and one bounded cache per evidence kind. A candidate that
ages out beyond ``max_event_gap``, is evicted by ``max_pending``, crosses a
reset barrier or is still open at :meth:`IsrWritebackCertificates.flush` settles
as ``incomplete`` and names the first missing hop and every required hop after
it. A hop is never overwritten, never reordered and never restored. The handler
image span only *classifies* the writer (``writer.classification.basis`` says
so); it is never a join, and ``adjacency_fallbacks_used`` stays zero.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
import hashlib
import json


SCHEMA_VERSION = "isr_writeback_certificate.v1"
AUDIT_SCHEMA_VERSION = "isr_writeback_chain_extension_audit.v1"
PROOF_SCOPE = "exact_handler_gpio_a_padout_commit_to_bound_second_irq_input"
NOT_PROOF_OF = (
    "p5_chain_extension",
    "chain_completion",
    "handler_execution_attribution_to_the_certified_irq_take",
    "isr_entry_or_trap_identity",
    "event_adjacency_or_ordering",
    "operand_taint_beyond_committed_register_versions",
)
HANDLER_HOP_SEQUENCE = (
    "handler_mmio_acceptance", "handler_register_commit", "binding_segment",
    "binding_input_resource", "bound_irq_trigger", "handler_retirement",
    "handler_retirement_match", "handler_target_delivery",
    "bound_cpu_irq_input", "bound_irq_observation")
# The declared order is *journal* order, not physical order: for one trigger the
# harness emits the CPU input notification before the GPIO IRQ observation (90 of
# 90 observed triggers across the two saved runs). Physical causality still
# holds inside the declared order: the write commits before the binding, the
# binding before the trigger, and the trigger before both consumers.
_EXTENSION_HOP = "handler_padout_writeback"
_MISSING_IDENTITY_REQUIRED = (
    "known + exactly one origin document equal to the certified chain admission "
    "document, plus source_refs naming its action id")
_CLASSIFICATION_BASIS = "declared_initial_image_span_observation_not_identity"
_NO_SPAN_BASIS = "no_declared_handler_span_all_padout_writes_in_scope"

_CPU_DEVICE = "cpu"
_GPIO_A_DEVICE = "gpio_a"
_GPIO_B_DEVICE = "gpio_b"
_PADOUT_OFFSET = 12
_PADOUT_REGISTER = "out"
_TRANSACTION_FIELDS = ("channel_id", "execution_id", "source_component",
                       "source_epoch", "source_sequence", "testcase_id")
_TRANSACTION_INT_FIELDS = frozenset(("source_epoch", "source_sequence"))
_RESET_KINDS = frozenset(("reset_barrier", "gpio_reset_resource", "cpu_reset"))
_CPU_IRQ_SOURCE = ("gpio_b", "irq")
_CPU_IRQ_TARGET = ("cpu", "irq")

_HOP_ATTEMPT_KEYS = {
    "handler_mmio_acceptance": "acceptance_transaction_identity",
    "handler_register_commit": "access_and_observation_identity",
    "binding_segment": "binding_version_identity",
    "binding_input_resource": "binding_input_version_identity",
    "bound_irq_trigger": "irq_trigger_sample_identity",
    "handler_retirement": "retirement_transaction_and_mem_identity",
    "handler_retirement_match": "retirement_match_identity",
    "handler_target_delivery": "target_delivery_identity",
    "bound_irq_observation": "trigger_observation_identity",
    "bound_cpu_irq_input": "cpu_irq_input_trigger_identity",
}
_HOP_ATTEMPT_REQUIRED = {
    "handler_mmio_acceptance": "six-field transaction key on a cpu gpio_a "
                               "offset-12 write acceptance",
    "handler_register_commit": "same transaction key plus access id and "
                               "observation_event_id == gpio_apb_access.event_id",
    "binding_segment": "committed bit identity (component, register, bit, "
                       "version, observation_event_id) repeated in "
                       "gpio_input_applied segment producer_resource_refs",
    "binding_input_resource": "same committed bit identity in "
                              "gpio_input_applied_resource origin_refs with "
                              "origin_status known",
    "bound_irq_trigger": "same committed bit identity in a gpio_irq_trigger "
                         "cause current_sample origin_refs",
    "handler_retirement": "cpu_retire whose mem_addr/mem_wmask/mem_wdata equal "
                          "the acceptance address/byte_enable/write_value",
    "handler_retirement_match": "cpu_retirement_match listing exactly the same "
                                "transaction key and produced by that retire",
    "handler_target_delivery": "cpu_retired_transaction_target_delivery naming "
                               "that match, the target access id and the "
                               "delivery",
    "bound_irq_observation": "gpio_irq_observation carrying the exact trigger id",
    "bound_cpu_irq_input": "cpu_irq_input whose source_trigger names that "
                           "trigger id and trigger event id",
}
_EXTRA_ATTEMPTS = (
    ("binding_event_adjacency", "adjacency_only",
     "the binding events are adjacent to the commit in the journal; ordering is "
     "never accepted as a join"),
    ("retirement_event_adjacency", "adjacency_only",
     "the retirement follows the commit in the journal; ordering is never "
     "accepted as a join"),
    ("writer_pc_classification", "classification_only",
     "the declared handler image span classifies the writer; it is not a "
     "per-invocation identity"),
)

_ANCHOR_HOP = {"CPU_TO_IP_TO_CPU": "retired_target_delivery",
               "IP_TO_CPU_TO_IP": "isr_padin_retirement"}
# Only these keys can carry handler attribution. The endpoint-echo keys below
# them can only ever repeat a chain's own terminal identity, so an exact value
# there is a self-echo (the record is the chain endpoint), never an extension.
_DECISIVE_KEYS = frozenset(("admission_origin_identity", "irq_take_identity",
                            "handler_read_link_identity"))


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _flag(value: object) -> bool | int | None:
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return value
    return None


def _transaction_key(document: object) -> tuple | None:
    """Exact transaction key tuple; missing, extra or ill-typed fields fail."""
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


def _key_document(key: Sequence) -> dict:
    return {name: key[index] for index, name in enumerate(_TRANSACTION_FIELDS)}


def _key_tuple(document: object) -> tuple | None:
    """Accept the six-field key as an object or as the canonical field list."""
    if isinstance(document, Mapping):
        return _transaction_key(document)
    if (isinstance(document, (list, tuple))
            and len(document) == len(_TRANSACTION_FIELDS)):
        return _transaction_key(dict(zip(_TRANSACTION_FIELDS, document)))
    return None


def _bit_identity(document: object) -> tuple | None:
    """Exact committed-register bit identity, or None when unidentifiable."""
    if not isinstance(document, Mapping):
        return None
    component = document.get("component")
    register = document.get("register")
    bit = document.get("bit")
    version = document.get("version")
    observation = document.get("observation_event_id")
    if (type(component) is not str or not component
            or type(register) is not str or not register
            or not _integer(bit) or not _integer(version)
            or not _integer(observation) or observation < 1):
        return None
    return (component, register, bit, version, observation)


def _identities(document: object) -> tuple:
    """Every exact bit identity reachable in one origin_refs-style list."""
    if not isinstance(document, list):
        return ()
    found = []
    for item in document:
        identity = _bit_identity(item)
        if identity is not None:
            found.append(identity)
    return tuple(found)


def _certificate_id(key: Sequence, access_id: str | None) -> str:
    payload = json.dumps([SCHEMA_VERSION, list(key), access_id],
                         separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def declared_handler_hop_sequence() -> tuple[str, ...]:
    """The frozen hop sequence every certificate is truncated to."""
    return HANDLER_HOP_SEQUENCE


def missing_chain_extension_identity(observed: str = "unknown") -> dict:
    """The single identity whose absence blocks the P5 chain extension."""
    return {
        "record": "cpu_retired_transaction_target_delivery",
        "field": "registered_origins/registered_origin_status",
        "artifact_path": "online_final_trace.json | online_events.zlib",
        "observed": observed,
        "required": _MISSING_IDENTITY_REQUIRED,
        "why": (
            "the handler write is not a source_admission, so its retirement "
            "delivery carries no registered origin: no chain candidate can claim "
            "it, and no field on the handler path names the interrupt take or "
            "the handler instance"),
    }


class IsrWritebackCertificates:
    """One certificate per handler GPIO A ``PADOUT`` write, exactly joined.

    The consumer is fed one contiguous journal slice at a time. Every hop is
    joined by an exact identity field; the declared handler image span is used
    only to classify the writer and to scope which writes produce certificates
    (writes outside it are counted, never certified).
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096,
                 handler_span: Sequence[int] | None = None,
                 handler_image_id: str | None = None,
                 max_writebacks: int = 256,
                 max_identities: int | None = None) -> None:
        if max_identities is None:
            max_identities = max(1024, max_pending * 32)
        for name, value in (("max_pending", max_pending),
                            ("max_event_gap", max_event_gap),
                            ("max_writebacks", max_writebacks),
                            ("max_identities", max_identities)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if handler_span is not None:
            if (not isinstance(handler_span, (tuple, list))
                    or len(handler_span) != 2
                    or not all(_integer(item) for item in handler_span)
                    or handler_span[1] < 1):
                raise ValueError("handler_span must be (address, length)")
            handler_span = (handler_span[0], handler_span[1])
        if handler_image_id is not None and (type(handler_image_id) is not str
                                             or not handler_image_id):
            raise ValueError("handler_image_id must be a nonempty string")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self.max_writebacks = max_writebacks
        self.max_identities = max_identities
        self.handler_image_id = handler_image_id
        self._handler_span = handler_span
        self._last_event_id = 0
        self._candidates: OrderedDict[tuple, dict] = OrderedDict()
        self._settled: OrderedDict[tuple, None] = OrderedDict()
        self._acceptances: OrderedDict[tuple, dict] = OrderedDict()
        self._accesses: OrderedDict[str, dict] = OrderedDict()
        self._accesses_by_key: OrderedDict[tuple, dict] = OrderedDict()
        self._commits: OrderedDict[tuple, dict] = OrderedDict()
        self._commit_identities: OrderedDict[tuple, dict] = OrderedDict()
        self._bound_inputs: OrderedDict[tuple, dict] = OrderedDict()
        self._triggers: OrderedDict[str, dict] = OrderedDict()
        self._observations: OrderedDict[str, dict] = OrderedDict()
        self._inputs: OrderedDict[str, dict] = OrderedDict()
        self._retires: OrderedDict[int, dict] = OrderedDict()
        self._matches: OrderedDict[int, dict] = OrderedDict()
        self._writebacks: OrderedDict[str, dict] = OrderedDict()
        self._counters = {
            "handler_writes_observed": 0,
            "out_of_scope_writes": 0,
            "certificates_certified": 0,
            "certificates_incomplete": 0,
            "candidates_reset": 0,
            "evicted_or_expired": 0,
            "adjacency_fallbacks_used": 0,
            "padout_writes_seen": 0,
            "identity_cache_evictions": 0,
            "writeback_records_dropped": 0,
            "first_missing_hop_counts": {},
        }

    # ------------------------------------------------------------------ API

    @property
    def pending_count(self) -> int:
        return len(self._candidates)

    @property
    def handler_span(self) -> tuple[int, int] | None:
        return self._handler_span

    def counters(self) -> dict:
        """Bounded run counters; no unbounded key set ever grows here."""
        return {**self._counters,
                "first_missing_hop_counts": dict(
                    self._counters["first_missing_hop_counts"]),
                "retained_writeback_identities": len(self._writebacks),
                "writeback_retention_truncated": (
                    self._counters["writeback_records_dropped"] > 0),
                "pending_candidates": len(self._candidates),
                "max_pending": self.max_pending,
                "max_event_gap": self.max_event_gap,
                "max_writebacks": self.max_writebacks,
                "max_identities": self.max_identities,
                "handler_span": list(self._handler_span)
                if self._handler_span is not None else None,
                "handler_image_id": self.handler_image_id}

    def writeback_records(self) -> tuple[dict, ...]:
        """Bounded handler writeback identities for the chain-extension audit."""
        return tuple(dict(record) for record in self._writebacks.values())

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        """Consume the next contiguous journal slice; return new certificates."""
        result = []
        for event in events:
            if (not isinstance(event, Mapping)
                    or type(event.get("event_id")) is not int
                    or event["event_id"] != self._last_event_id + 1):
                raise ValueError("writeback journal must be contiguous")
            event_id = event["event_id"]
            self._last_event_id = event_id
            result.extend(self._expire(event_id))
            kind = event.get("kind")
            if kind in _RESET_KINDS:
                result.extend(self._settle_all(event_id, "reset_barrier"))
                self._caches_clear()
            elif kind == "initial_image":
                self._initial_image(event)
            elif kind == "mmio_acceptance":
                self._acceptance(event)
            elif kind == "gpio_apb_access":
                self._apb_access(event)
            elif kind == "gpio_register_commit":
                self._commit(event)
            elif kind == "gpio_input_applied":
                self._binding(event)
            elif kind == "gpio_input_applied_resource":
                self._binding_resource(event)
            elif kind == "gpio_irq_trigger":
                self._trigger(event)
            elif kind == "cpu_retire":
                self._retire(event)
            elif kind == "cpu_retirement_match":
                self._retirement_match(event)
            elif kind == "cpu_retired_transaction_target_delivery":
                self._retired_delivery(event)
            elif kind == "gpio_irq_observation":
                self._irq_observation(event)
            elif kind == "cpu_irq_input":
                self._cpu_irq_input(event)
            result.extend(self._settle_complete(event_id))
        return tuple(result)

    def flush(self) -> tuple[dict, ...]:
        """Settle every candidate still open at the end of the journal."""
        return tuple(self._settle_all(self._last_event_id, "journal_end"))

    # ------------------------------------------------------------- internals

    def _limit(self, cache: OrderedDict) -> None:
        while len(cache) > self.max_pending:
            cache.popitem(last=False)

    def _store(self, cache: OrderedDict, key: object, entry: dict) -> None:
        cache[key] = entry
        self._limit(cache)

    def _store_identity(self, cache: OrderedDict, key: object,
                        entry: dict) -> None:
        """Bound the per-bit identity caches separately from pending candidates.

        One PADOUT commit publishes one identity per committed bit, so the
        ``max_pending`` entry bound would hold only a handful of commits and
        could evict an identity still needed by the next binding event. The
        identity bound stays explicit and reported.
        """
        cache[key] = entry
        while len(cache) > self.max_identities:
            cache.popitem(last=False)
            self._counters["identity_cache_evictions"] += 1

    def _cache_list(self) -> tuple[OrderedDict, ...]:
        return (self._acceptances, self._accesses, self._accesses_by_key,
                self._commits, self._commit_identities, self._bound_inputs,
                self._triggers, self._observations, self._inputs, self._retires,
                self._matches)

    def _caches_clear(self) -> None:
        for cache in self._cache_list():
            cache.clear()

    def _expire(self, event_id: int) -> list:
        result = []
        for key, state in tuple(self._candidates.items()):
            if event_id - state["born"] > self.max_event_gap:
                self._counters["evicted_or_expired"] += 1
                result.append(self._settle(key, "incomplete", event_id,
                                           "max_event_gap"))
        for cache in self._cache_list():
            while cache:
                entry = next(iter(cache.values()))
                if event_id - entry["event_id"] <= self.max_event_gap:
                    break
                cache.popitem(last=False)
        return result

    def _settle_all(self, event_id: int, reason: str) -> list:
        result = []
        for key in tuple(self._candidates):
            result.append(self._settle(key, "incomplete", event_id, reason))
        return result

    def _settle_complete(self, event_id: int) -> list:
        result = []
        for key, state in tuple(self._candidates.items()):
            if all(name in state["hops"] for name in HANDLER_HOP_SEQUENCE):
                result.append(self._settle(key, "certified", event_id, "complete"))
        return result

    def _settle(self, key: tuple, status: str, event_id: int,
                reason: str) -> dict:
        state = self._candidates.pop(key)
        self._settled[key] = None
        document = self._document(state, status, event_id, reason)
        if status == "certified":
            self._counters["certificates_certified"] += 1
            self._remember_writeback(document)
        else:
            self._counters["certificates_incomplete"] += 1
            missing = document["missing_hops"]
            if missing:
                counts = self._counters["first_missing_hop_counts"]
                counts[missing[0]] = counts.get(missing[0], 0) + 1
            if state.get("handler") is True:
                self._remember_writeback(document)
        return document

    def _remember_writeback(self, document: Mapping) -> None:
        record = {
            "certificate_id": document["certificate_id"],
            "status": document["status"],
            "missing_hops": list(document["missing_hops"]),
            "writer_pc": document["writer"]["pc"],
            "insn": document["writer"]["insn"],
            "order": document["writer"]["order"],
            "retire_event_id": document["writer"]["retire_event_id"],
            "retirement_event_id": document["handler_record"]
            ["retirement_event_id"],
            "delivery_event_id": document["handler_record"]["delivery_event_id"],
            "commit_event_id": document["handler_record"]["commit_event_id"],
            "acceptance_event_id": document["handler_record"]
            ["acceptance_event_id"],
            "apb_access_event_id": document["handler_record"]
            ["apb_access_event_id"],
            "transaction": dict(document["transaction"]),
            "target_access_id": document["target_access_id"],
            "registered_origin_status": document["handler_record"]
            ["registered_origin_status"],
            "registered_origins": [dict(item) for item
                                   in document["handler_record"]
                                   ["registered_origins"]],
            "source_refs": list(document["handler_record"]["source_refs"]),
            "irq_take_identity": None,
            "second_irq": dict(document["second_irq"]),
        }
        self._writebacks[document["certificate_id"]] = record
        while len(self._writebacks) > self.max_writebacks:
            self._writebacks.popitem(last=False)
            self._counters["writeback_records_dropped"] += 1

    def _document(self, state: dict, status: str, event_id: int,
                  reason: str) -> dict:
        hops = []
        missing = []
        for name in HANDLER_HOP_SEQUENCE:
            entry = state["hops"].get(name)
            if entry is not None and not missing:
                hops.append({"hop_id": name, "event_id": entry["event_id"],
                             "evidence": dict(entry["evidence"])})
            else:
                missing.append(name)
        if status == "certified":
            missing = []
        return {
            "schema_version": SCHEMA_VERSION,
            "certificate_id": _certificate_id(state["key"],
                                              state["access_id"]),
            "status": status,
            "settled_reason": reason,
            "transaction": _key_document(state["key"]),
            "target_access_id": state["access_id"],
            "handler_image_id": self.handler_image_id,
            "writer": dict(state["writer"]) if state["writer"] else None,
            "handler_record": {
                "acceptance_event_id": state["acceptance_event_id"],
                "apb_access_event_id": state["apb_access_event_id"],
                "commit_event_id": state["commit_event_id"],
                "retirement_event_id": state["match_event_id"],
                "delivery_event_id": state["delivery_event_id"],
                "registered_origin_status": state["registered_origin_status"],
                "registered_origins": [dict(item) for item
                                       in state["registered_origins"]],
                "source_refs": list(state["source_refs"]),
            },
            "second_irq": {
                "trigger_id": state["trigger_id"],
                "trigger_event_id": state["trigger_event_id"],
                "observation_event_id": state["observation_event_id"],
                "cpu_irq_input_event_id": state["input_event_id"],
                "cpu_step_event_id": state["input_step_event_id"],
            },
            "hops": hops,
            "missing_hops": missing,
            "completed_event_id": event_id,
            "join_attempts": self._join_attempts(state),
            "chain_extension": {
                # This certificate never decides chain attribution: the handler
                # write's own registered origin is reported, and the decision
                # belongs to audit_chain_extension, which sees the chains.
                "joinable": False,
                "decided_by": "audit_chain_extension",
                "handler_origin_identity_present": (
                    state["registered_origin_status"] == "known"),
                "extension_hop": _EXTENSION_HOP,
                "missing_identity": (
                    None if state["registered_origin_status"] == "known"
                    else missing_chain_extension_identity("unknown")),
            },
            "counters": self.counters(),
            "proof_scope": PROOF_SCOPE,
            "not_proof_of": list(NOT_PROOF_OF),
        }

    def _join_attempts(self, state: Mapping) -> list:
        attempts = []
        for hop_id in HANDLER_HOP_SEQUENCE:
            attached = hop_id in state["hops"]
            attempts.append({
                "key": _HOP_ATTEMPT_KEYS[hop_id],
                "hop_id": hop_id,
                "required": _HOP_ATTEMPT_REQUIRED[hop_id],
                "observed": ({"event_id": state["hops"][hop_id]["event_id"]}
                             if attached else None),
                "relation": "exact" if attached else "absent",
                "exact": attached,
                "why": None if attached else "no event carried this exact identity",
            })
        for key, relation, why in _EXTRA_ATTEMPTS:
            attempts.append({"key": key, "hop_id": None, "required": None,
                             "observed": None, "relation": relation,
                             "exact": False, "why": why})
        return attempts

    def _attach(self, state: dict, hop_id: str, event_id: int, **evidence) -> bool:
        """Attach one exactly joined hop; never overwrite or reorder."""
        if (not _integer(event_id) or event_id < 1
                or event_id > self._last_event_id
                or hop_id in state["hops"]):
            return False
        position = HANDLER_HOP_SEQUENCE.index(hop_id)
        for name, entry in state["hops"].items():
            other = HANDLER_HOP_SEQUENCE.index(name)
            if other < position and entry["event_id"] >= event_id:
                return False
            if other > position and entry["event_id"] <= event_id:
                return False
        state["hops"][hop_id] = {"event_id": event_id, "evidence": dict(evidence)}
        return True

    def _initial_image(self, event: Mapping) -> None:
        """Learn the declared handler image span from the artifact itself."""
        if (self._handler_span is not None or self.handler_image_id is None
                or event.get("image_id") != self.handler_image_id):
            return
        address = event.get("address")
        data_hex = event.get("data_hex")
        if (not _integer(address) or type(data_hex) is not str or not data_hex
                or len(data_hex) % 2 or any(character not in "0123456789abcdefABCDEF"
                                            for character in data_hex)):
            return
        self._handler_span = (address, len(data_hex) // 2)

    def _candidate_for(self, key: object) -> dict | None:
        if not isinstance(key, tuple):
            return None
        state = self._candidates.get(key)
        if state is not None:
            return state
        return None

    def _acceptance(self, event: Mapping) -> None:
        key = _transaction_key(event.get("source_transaction"))
        write = _flag(event.get("write"))
        if (event.get("component") != _CPU_DEVICE or key is None
                or write is not True or event.get("device_id") != _GPIO_A_DEVICE
                or event.get("offset") != _PADOUT_OFFSET):
            return
        entry = {"event_id": event["event_id"], "address": event.get("address"),
                 "byte_enable": event.get("byte_enable"),
                 "write_value": event.get("write_value"), "key": key}
        self._store(self._acceptances, key, entry)
        self._counters["padout_writes_seen"] += 1
        if key in self._candidates or key in self._settled:
            return
        self._candidates[key] = {
            "key": key, "born": event["event_id"], "hops": {},
            "acceptance_event_id": None, "apb_access_event_id": None,
            "commit_event_id": None, "match_event_id": None,
            "delivery_event_id": None, "trigger_id": None,
            "trigger_event_id": None, "observation_event_id": None,
            "input_event_id": None, "input_step_event_id": None,
            "commit_identities": (), "access_id": None, "writer": None,
            "handler": None, "registered_origin_status": "unknown",
            "registered_origins": (), "source_refs": (),
        }
        while len(self._candidates) > self.max_pending:
            evicted, evicted_state = self._candidates.popitem(last=False)
            self._counters["evicted_or_expired"] += 1
            self._settle_state(evicted, evicted_state, "incomplete",
                               self._last_event_id, "max_pending")

    def _apb_access(self, event: Mapping) -> None:
        access_id = event.get("access_id")
        key = _transaction_key(event.get("source_transaction"))
        write = _flag(event.get("write"))
        if (event.get("component") != _GPIO_A_DEVICE or write is not True
                or type(access_id) is not str or not access_id or key is None
                or event.get("decoded_offset") != _PADOUT_OFFSET):
            return
        entry = {"event_id": event["event_id"], "access_id": access_id,
                 "key": key, "wdata": event.get("wdata")}
        self._store(self._accesses, access_id, entry)
        self._store(self._accesses_by_key, key, entry)

    def _commit(self, event: Mapping) -> None:
        if (event.get("component") != _GPIO_A_DEVICE
                or event.get("register") != _PADOUT_REGISTER):
            return
        access_id = event.get("access_id")
        observation = event.get("observation_event_id")
        resources = event.get("bit_resources")
        if (type(access_id) is not str or not access_id
                or not _integer(observation) or not isinstance(resources, list)
                or not resources):
            return
        keys = {_transaction_key(item.get("transaction"))
                for item in resources if isinstance(item, Mapping)}
        if len(keys) != 1:
            return
        key = keys.pop()
        if key is None:
            return
        access = self._accesses.get(access_id)
        if (access is None or access["key"] != key
                or access["event_id"] != observation):
            return
        identities = []
        for item in resources:
            identity = _bit_identity(item)
            if identity is None or identity[:2] != (_GPIO_A_DEVICE,
                                                   _PADOUT_REGISTER):
                return
            identities.append(identity)
        entry = {"event_id": event["event_id"], "access_id": access_id,
                 "key": key, "identities": tuple(identities),
                 "observation_event_id": observation}
        self._store(self._commits, key, entry)
        for identity in identities:
            self._store_identity(self._commit_identities, identity,
                                 {"event_id": event["event_id"], "key": key,
                                  "access_id": access_id})
        state = self._candidate_for(key)
        if state is None or state["handler"] is False:
            return
        acceptance = self._acceptances.get(key)
        if acceptance is None:
            return
        state["access_id"] = access_id
        state["acceptance_event_id"] = acceptance["event_id"]
        state["apb_access_event_id"] = access["event_id"]
        state["commit_event_id"] = event["event_id"]
        state["commit_identities"] = tuple(identities)
        self._attach(state, "handler_mmio_acceptance", acceptance["event_id"],
                     device_id=_GPIO_A_DEVICE, offset=_PADOUT_OFFSET,
                     write=True, address=acceptance["address"],
                     write_value=acceptance["write_value"],
                     transaction=list(key))
        self._attach(state, "handler_register_commit", event["event_id"],
                     component=_GPIO_A_DEVICE, register=_PADOUT_REGISTER,
                     access_id=access_id, observation_event_id=observation,
                     transaction=list(key))

    def _binding(self, event: Mapping) -> None:
        if event.get("component") != _GPIO_B_DEVICE:
            return
        segments = event.get("segments")
        if not isinstance(segments, list):
            return
        for segment in segments:
            if not isinstance(segment, Mapping):
                continue
            origin = segment.get("origin")
            if (not isinstance(origin, Mapping)
                    or origin.get("source_component") != _GPIO_A_DEVICE
                    or origin.get("source_port") != "gpio_out"):
                continue
            for identity in _identities(origin.get("producer_resource_refs")):
                commit = self._commit_identities.get(identity)
                if commit is None:
                    continue
                state = self._candidate_for(commit["key"])
                if state is None or state["handler"] is False:
                    continue
                self._attach(state, "binding_segment", event["event_id"],
                             source_component=_GPIO_A_DEVICE,
                             source_port="gpio_out",
                             source_bit_lo=segment.get("bit_lo"),
                             value=segment.get("value"),
                             delivery_event_id=origin.get("delivery_event_id"),
                             producer_resource_refs=[dict(item) for item
                                                     in origin["producer_resource_refs"]])

    def _binding_resource(self, event: Mapping) -> None:
        if event.get("component") != _GPIO_B_DEVICE:
            return
        resources = event.get("bit_resources")
        if not isinstance(resources, list):
            return
        for item in resources:
            if not isinstance(item, Mapping):
                continue
            identity = _bit_identity(item)
            for origin in _identities(item.get("origin_refs")):
                commit = self._commit_identities.get(origin)
                if commit is None:
                    continue
                if item.get("origin_status") != "known":
                    continue
                self._store_identity(self._bound_inputs, identity,
                                     {"event_id": event["event_id"],
                                      "key": commit["key"]})
                state = self._candidate_for(commit["key"])
                if state is None or state["handler"] is False:
                    continue
                self._attach(state, "binding_input_resource",
                             event["event_id"], component=_GPIO_B_DEVICE,
                             register=item.get("register"), bit=item.get("bit"),
                             value=item.get("value"), version=item.get("version"),
                             origin_status="known",
                             origin_refs=[dict(entry) for entry
                                          in item["origin_refs"]])

    def _trigger(self, event: Mapping) -> None:
        trigger_id = event.get("trigger_id")
        if (event.get("component") != _GPIO_B_DEVICE
                or type(trigger_id) is not str or not trigger_id):
            return
        self._store(self._triggers, trigger_id,
                    {"event_id": event["event_id"], "mask": event.get("mask"),
                     "value": event.get("value")})
        for identity in self._cause_identities(event):
            commit = self._commit_identities.get(identity)
            if commit is None:
                continue
            state = self._candidate_for(commit["key"])
            if state is None or state["handler"] is False:
                continue
            if self._attach(state, "bound_irq_trigger", event["event_id"],
                            component=_GPIO_B_DEVICE, trigger_id=trigger_id,
                            mask=event.get("mask"), value=event.get("value"),
                            committed_bit_identity=list(identity)):
                state["trigger_id"] = trigger_id
                state["trigger_event_id"] = event["event_id"]

    def _cause_identities(self, event: Mapping) -> tuple:
        """Exact committed-bit identities named by a trigger/observation cause."""
        found = []
        causes = event.get("causes")
        if not isinstance(causes, list):
            return ()
        for cause in causes:
            if not isinstance(cause, Mapping):
                continue
            sample = cause.get("current_sample")
            if not isinstance(sample, Mapping):
                continue
            for source in (sample.get("origin_refs"),
                           sample.get("dependencies")):
                for identity in _identities(source):
                    if identity[:2] == (_GPIO_A_DEVICE, _PADOUT_REGISTER):
                        found.append(identity)
        return tuple(found)

    def _retire(self, event: Mapping) -> None:
        if event.get("component") != _CPU_DEVICE:
            return
        self._store(self._retires, event["event_id"], {
            "event_id": event["event_id"], "valid": _flag(event.get("valid")),
            "trap": _flag(event.get("trap")), "insn": event.get("insn"),
            "order": event.get("order"), "pc_rdata": event.get("pc_rdata"),
            "mem_addr": event.get("mem_addr"),
            "mem_wmask": event.get("mem_wmask"),
            "mem_wdata": event.get("mem_wdata")})

    def _retirement_match(self, event: Mapping) -> None:
        if (event.get("component") != _CPU_DEVICE
                or event.get("status") != "accepted"):
            return
        keys = event.get("transaction_keys")
        if not isinstance(keys, list) or len(keys) != 1:
            return
        key = _transaction_key(keys[0])
        if key is None:
            return
        retire_id = event.get("producer_event_id")
        self._store(self._matches, event["event_id"],
                    {"event_id": event["event_id"], "key": key,
                     "producer_event_id": retire_id})
        state = self._candidate_for(key)
        if state is None or state["handler"] is False:
            return
        acceptance = self._acceptances.get(key)
        retire = self._retires.get(retire_id) if _integer(retire_id) else None
        if (acceptance is None or retire is None or retire["valid"] != 1
                or retire["trap"] != 0
                or retire["mem_addr"] != acceptance["address"]
                or retire["mem_wmask"] != acceptance["byte_enable"]
                or retire["mem_wdata"] != acceptance["write_value"]):
            return
        writer = {"pc": retire["pc_rdata"], "insn": retire["insn"],
                  "order": retire["order"], "retire_event_id": retire["event_id"],
                  "classification": self._classification(retire["pc_rdata"])}
        state["writer"] = writer
        state["handler"] = self._in_handler_span(retire["pc_rdata"])
        if state["handler"] is False:
            self._counters["out_of_scope_writes"] += 1
            self._settle_state(key, state, "out_of_scope", event["event_id"],
                               "outside_declared_handler_span")
            return
        self._counters["handler_writes_observed"] += 1
        state["match_event_id"] = event["event_id"]
        self._attach(state, "handler_retirement", retire["event_id"],
                     component=_CPU_DEVICE, insn=retire["insn"],
                     order=retire["order"], pc_rdata=retire["pc_rdata"],
                     mem_addr=retire["mem_addr"], mem_wmask=retire["mem_wmask"],
                     mem_wdata=retire["mem_wdata"], transaction=list(key))
        self._attach(state, "handler_retirement_match", event["event_id"],
                     component=_CPU_DEVICE, transaction=list(key),
                     producer_event_id=retire["event_id"])

    def _retired_delivery(self, event: Mapping) -> None:
        if (event.get("component") != _CPU_DEVICE
                or event.get("status") != "linked_raw"):
            return
        consumer = event.get("consumer_resource")
        if not isinstance(consumer, Mapping):
            return
        access_id = consumer.get("target_access_id")
        match = self._matches.get(event.get("retirement_event_id"))
        if (type(access_id) is not str or not access_id or match is None
                or consumer.get("device_id") != _GPIO_A_DEVICE
                or consumer.get("offset") != _PADOUT_OFFSET
                or _flag(consumer.get("write")) is not True):
            return
        state = self._candidate_for(match["key"])
        if state is None or state["handler"] is False:
            return
        acceptance = self._acceptances.get(match["key"])
        if (acceptance is None
                or consumer.get("write_value") != acceptance["write_value"]
                or state["access_id"] != access_id):
            return
        state["registered_origin_status"] = event.get(
            "registered_origin_status")
        origins = event.get("registered_origins")
        refs = event.get("source_refs")
        state["registered_origins"] = tuple(
            dict(item) for item in origins) if isinstance(origins, list) else ()
        state["source_refs"] = tuple(refs) if isinstance(refs, list) else ()
        state["delivery_event_id"] = event["event_id"]
        self._attach(state, "handler_target_delivery", event["event_id"],
                     component=_CPU_DEVICE, status="linked_raw",
                     registered_origin_status=event.get(
                         "registered_origin_status"),
                     target_access_id=access_id,
                     delivery_event_id=event["event_id"],
                     retirement_event_id=event.get("retirement_event_id"),
                     write_value=consumer.get("write_value"),
                     transaction=list(match["key"]))

    def _irq_observation(self, event: Mapping) -> None:
        trigger_id = event.get("trigger_id")
        if (event.get("component") != _GPIO_B_DEVICE
                or type(trigger_id) is not str or not trigger_id):
            return
        trigger = self._triggers.get(trigger_id)
        if trigger is None or trigger["event_id"] >= event["event_id"]:
            return
        self._store(self._observations, trigger_id,
                    {"event_id": event["event_id"]})
        for identity in self._cause_identities(event):
            commit = self._commit_identities.get(identity)
            if commit is None:
                continue
            state = self._candidate_for(commit["key"])
            if (state is None or state["handler"] is False
                    or state["trigger_id"] != trigger_id):
                continue
            if self._attach(state, "bound_irq_observation", event["event_id"],
                            component=_GPIO_B_DEVICE, trigger_id=trigger_id,
                            mask=event.get("mask"), value=event.get("value"),
                            committed_bit_identity=list(identity)):
                state["observation_event_id"] = event["event_id"]

    def _cpu_irq_input(self, event: Mapping) -> None:
        reference = event.get("source_trigger")
        if (event.get("kind") != "cpu_irq_input"
                or tuple(event.get("source") or ()) != _CPU_IRQ_SOURCE
                or tuple(event.get("target") or ()) != _CPU_IRQ_TARGET
                or not isinstance(reference, Mapping)):
            return
        trigger_id = reference.get("trigger_id")
        trigger_event_id = reference.get("trigger_event_id")
        if (type(trigger_id) is not str or not trigger_id
                or not _integer(trigger_event_id)):
            return
        trigger = self._triggers.get(trigger_id)
        if trigger is None or trigger["event_id"] != trigger_event_id:
            return
        self._inputs.setdefault(trigger_id, {
            "event_id": event["event_id"],
            "cpu_step_event_id": event.get("cpu_step_event_id")})
        for state in tuple(self._candidates.values()):
            if (state["handler"] is False or state["trigger_id"] != trigger_id
                    or state["trigger_event_id"] != trigger_event_id):
                continue
            if self._attach(state, "bound_cpu_irq_input", event["event_id"],
                            component=_CPU_DEVICE, value=event.get("value"),
                            trigger_id=trigger_id,
                            trigger_event_id=trigger_event_id,
                            observation_event_id=reference.get(
                                "observation_event_id"),
                            cpu_step_event_id=event.get("cpu_step_event_id")):
                state["input_event_id"] = event["event_id"]
                state["input_step_event_id"] = event.get("cpu_step_event_id")

    def _in_handler_span(self, pc: object) -> bool | None:
        if self._handler_span is None:
            return None
        if not _integer(pc):
            return False
        start, length = self._handler_span
        return start <= pc < start + length

    def _classification(self, pc: object) -> dict:
        if self._handler_span is None:
            return {"image_id": None, "span": None, "basis": _NO_SPAN_BASIS}
        return {"image_id": self.handler_image_id,
                "span": [self._handler_span[0], self._handler_span[1]],
                "basis": _CLASSIFICATION_BASIS}

    def _settle_state(self, key: tuple, state: dict, status: str,
                      event_id: int, reason: str) -> dict:
        if self._candidates.get(key) is state:
            self._candidates.pop(key)
        self._settled[key] = None
        document = self._document(state, status, event_id, reason)
        if status == "certified":
            self._counters["certificates_certified"] += 1
        elif status == "out_of_scope":
            return document
        else:
            self._counters["certificates_incomplete"] += 1
            missing = document["missing_hops"]
            if missing:
                counts = self._counters["first_missing_hop_counts"]
                counts[missing[0]] = counts.get(missing[0], 0) + 1
        if state.get("handler") is True:
            self._remember_writeback(document)
        return document


# --------------------------------------------------------------------------
# chain-extension audit
# --------------------------------------------------------------------------


def _anchor(chain: Mapping) -> dict | None:
    hop_id = _ANCHOR_HOP.get(chain.get("direction"))
    if hop_id is None:
        return None
    for hop in chain.get("hops") or ():
        if isinstance(hop, Mapping) and hop.get("hop_id") == hop_id:
            return {"hop_id": hop_id, "event_id": hop.get("event_id"),
                    "evidence": dict(hop.get("evidence") or {})}
    return None


def _take_identity(chain: Mapping) -> dict | None:
    taken = None
    trigger = None
    for hop in chain.get("hops") or ():
        if not isinstance(hop, Mapping):
            continue
        if hop.get("hop_id") == "cpu_irq_taken":
            taken = hop
        elif hop.get("hop_id") == "gpio_b_native_irq_trigger":
            trigger = hop
    if taken is None:
        return None
    evidence = dict(taken.get("evidence") or {})
    return {"take_event_id": taken.get("event_id"),
            "step_event_id": evidence.get("step_event_id"),
            "source_event_id": evidence.get("source_event_id"),
            "trigger_id": (dict(trigger.get("evidence") or {}).get("trigger_id")
                           if trigger is not None else None)}


def _observed_origin(record: Mapping) -> dict | None:
    if record.get("registered_origin_status") != "known":
        return None
    origins = record.get("registered_origins")
    refs = record.get("source_refs")
    if (not isinstance(origins, (list, tuple)) or len(origins) != 1
            or not isinstance(refs, (list, tuple)) or len(refs) != 1):
        return None
    origin = origins[0]
    if not isinstance(origin, Mapping):
        return None
    admission_id = origin.get("admission_id")
    if type(admission_id) is not str or not admission_id:
        return None
    if type(refs[0]) is not str or not refs[0]:
        return None
    return {"admission_id": admission_id, "action_id": refs[0]}


def _attempt(key: str, required: object, observed: object, relation: str,
             why: str) -> dict:
    return {"key": key, "required": required, "observed": observed,
            "relation": relation, "exact": relation == "exact", "why": why}


def audit_chain_extension(chain: Mapping,
                          writebacks: Sequence[Mapping]) -> dict:
    """Attempt every exact identity join from one chain to handler writes.

    ``status`` is ``joined`` only when an exact identity field carries the
    association; every other candidate is reported with its relation
    (``mismatch``, ``absent``, ``adjacency_only``, ``classification_only``) so a
    refusal is never silent. A chain's own terminal write is excluded: it is the
    chain's endpoint, not a handler writeback.
    """
    if not isinstance(chain, Mapping):
        raise ValueError("chain certificate must be a mapping")
    direction = chain.get("direction")
    anchor = _anchor(chain)
    attempts = []
    extension_hop = _EXTENSION_HOP
    if anchor is None:
        return {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "status": "no_anchor",
            "direction": direction,
            "chain_certificate_id": chain.get("certificate_id"),
            "chain_source_admission_id": chain.get("source_admission_id"),
            "chain_source_action_id": chain.get("source_action_id"),
            "anchor_hop": None,
            "chain_hop_event_ids": {},
            "join_attempts": [_attempt(
                "anchor_hop", _ANCHOR_HOP.get(direction), None, "absent",
                "the certified chain lists no terminal anchor hop to extend")],
            "writeback_identities": [],
            "self_endpoint_excluded": 0,
            "extension_hop": extension_hop,
            "extended_hops": [],
            "missing_identity": {
                "record": "chain certificate",
                "field": _ANCHOR_HOP.get(direction),
                "observed": "no terminal hop in hops",
                "required": "a certified terminal hop to anchor the extension",
                "why": "an unanchored chain has no identity to extend from"},
            "proof_scope": PROOF_SCOPE,
            "not_proof_of": list(NOT_PROOF_OF),
        }
    evidence = anchor["evidence"]
    admission_id = chain.get("source_admission_id")
    action_id = chain.get("source_action_id")
    take = _take_identity(chain)
    anchor_access = evidence.get("target_access_id")
    anchor_transaction = _key_tuple(evidence.get("transaction"))
    anchor_retirement = evidence.get("retirement_event_id")
    anchor_delivery = evidence.get("delivery_event_id")

    self_endpoint = 0
    kept = []
    for record in writebacks:
        if not isinstance(record, Mapping):
            continue
        # The chain's own terminal write is its endpoint, not a handler
        # writeback. Both target access ids and transaction keys are run-global
        # identities, so this exclusion cannot swallow a different write.
        if (anchor_access is not None
                and record.get("target_access_id") == anchor_access):
            self_endpoint += 1
            continue
        if (anchor_transaction is not None
                and _key_tuple(record.get("transaction")) == anchor_transaction):
            self_endpoint += 1
            continue
        kept.append(dict(record))

    observed_origin = None
    relation = "absent"
    why = ("no handler writeback record carries a registered origin: "
           "registered_origin_status is not 'known' or the origin/ref lists are "
           "not exactly one entry")
    for record in kept:
        origin = _observed_origin(record)
        if origin is not None:
            observed_origin = origin
            if origin["admission_id"] == admission_id and origin["action_id"] == action_id:
                relation = "exact"
                why = ("the handler writeback records the certified chain "
                       "admission as its registered origin")
            else:
                relation = "mismatch"
                why = ("the handler writeback records a different admission "
                       "origin than this chain")
            break
    attempts.append(_attempt(
        "admission_origin_identity",
        {"admission_id": admission_id, "action_id": action_id},
        observed_origin, relation, why))

    if take is None:
        attempts.append(_attempt(
            "irq_take_identity", None, None, "absent",
            "the certified chain lists no cpu_irq_taken hop, and no handler "
            "writeback record names an interrupt take"))
    else:
        matched = None
        for record in kept:
            observed = record.get("irq_take_identity")
            if isinstance(observed, Mapping) and observed == take:
                matched = observed
                break
        attempts.append(_attempt(
            "irq_take_identity", take, matched,
            "exact" if matched is not None else "absent",
            "no field on any handler writeback record names the interrupt take "
            "(cpu_irq_taken.cpu_step_event_id / source_trigger.trigger_id) or the "
            "handler instance" if matched is None else
            "the handler writeback record names this exact interrupt take"))

    if direction == "IP_TO_CPU_TO_IP":
        linked = None
        for record in kept:
            observed = record.get("handler_read_link_identity")
            if isinstance(observed, Mapping):
                linked = observed
                break
        attempts.append(_attempt(
            "handler_read_link_identity",
            {"isr_padin_retirement_event_id": anchor["event_id"]},
            linked, "exact" if linked is not None else "absent",
            "no field on any handler writeback record names the certified ISR "
            "PADIN read retirement or the handler instance, so the handler read "
            "and the handler write are related only by ordering"))

    for key, required, field, normalise in (
            ("target_access_identity", anchor_access, "target_access_id", None),
            ("transaction_identity", anchor_transaction, "transaction",
             _key_tuple),
            ("retirement_event_identity", anchor_retirement,
             "retirement_event_id", None),
            ("delivery_event_identity", anchor_delivery, "delivery_event_id",
             None)):
        observed = None
        matched = False
        for record in kept:
            observed = record.get(field)
            probe = normalise(observed) if normalise is not None else observed
            matched = probe is not None and required is not None and probe == required
            break
        attempts.append(_attempt(
            key,
            (list(required) if key == "transaction_identity"
             and required is not None else required),
            observed,
            "exact" if matched else ("mismatch" if observed is not None
                                     else "absent"),
            ("the handler writeback repeats this exact chain endpoint identity"
             if matched else
             "the certified chain's terminal hop evidence carries no such "
             "identity, so the candidate key is unavailable at certificate "
             "level" if required is None else
             "the handler writeback is a different physical MMIO transaction "
             "than the chain endpoint")))

    for record in kept[:1]:
        attempts.append(_attempt(
            "writer_pc_classification",
            None,
            {"pc": record.get("writer_pc"),
             "handler_span": record.get("handler_span")},
            "classification_only",
            "the handler image span classifies the writer; it is not a "
            "per-invocation identity"))
        attempts.append(_attempt(
            "ordering_adjacency",
            None,
            {"writeback_after_anchor": (
                _integer(record.get("retire_event_id"))
                and _integer(anchor["event_id"])
                and record["retire_event_id"] > anchor["event_id"]),
             "event_gap": (record.get("retire_event_id") - anchor["event_id"]
                           if _integer(record.get("retire_event_id"))
                           and _integer(anchor["event_id"]) else None)},
            "adjacency_only",
            "ordering is available and is never accepted as a join"))
    if not kept:
        attempts.append(_attempt(
            "writer_pc_classification", None, None, "absent",
            "no handler writeback record was retained for this run"))
        attempts.append(_attempt(
            "ordering_adjacency", None, None, "adjacency_only",
            "ordering is available and is never accepted as a join"))

    joined = [attempt for attempt in attempts
              if attempt["exact"] and attempt["key"] in _DECISIVE_KEYS]
    echoes = [attempt["key"] for attempt in attempts
              if attempt["exact"] and attempt["key"] not in _DECISIVE_KEYS]
    status = "joined" if joined else "not_joinable"
    missing = None
    if not joined:
        observed_status = "unknown"
        for record in kept:
            observed_status = record.get("registered_origin_status", "unknown")
            break
        missing = missing_chain_extension_identity(observed_status)
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "status": status,
        "direction": direction,
        "chain_certificate_id": chain.get("certificate_id"),
        "chain_source_admission_id": admission_id,
        "chain_source_action_id": action_id,
        "anchor_hop": anchor["hop_id"],
        "chain_hop_event_ids": {anchor["hop_id"]: anchor["event_id"]},
        "join_attempts": attempts,
        "writeback_identities": [
            {key: record.get(key) for key in (
                "certificate_id", "writer_pc", "insn", "order",
                "retire_event_id", "retirement_event_id", "delivery_event_id",
                "commit_event_id", "acceptance_event_id", "apb_access_event_id",
                "transaction", "target_access_id",
                "registered_origin_status", "registered_origins", "source_refs",
                "irq_take_identity", "status", "missing_hops")}
            for record in kept],
        "self_endpoint_excluded": self_endpoint,
        "extension_hop": extension_hop,
        "extended_hops": [extension_hop] if joined else [],
        "missing_identity": missing,
        "matched_join_keys": [attempt["key"] for attempt in joined],
        "self_echo_keys": echoes,
        "proof_scope": PROOF_SCOPE,
        "not_proof_of": list(NOT_PROOF_OF),
    }
