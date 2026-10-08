"""Incremental, bounded end-to-end propagation chain certificates.

A chain certificate fuses the *already certified* per-hop evidence of one
``source_admission`` into a single end-to-end record. Only exact identity joins
are accepted: admission documents, action IDs, resource versions, transaction
keys, access IDs, retirement IDs and trigger IDs must agree literally. Event
adjacency, equal counts and architectural expectation are never used as a join.

Two declared directions are supported:

``IP_TO_CPU_TO_IP``
    pin-8 external admission -> authenticated GPIO B input/sync versions ->
    native GPIO B IRQ trigger and observation -> CPU interrupt input and
    acceptance -> ISR ``PADIN`` MMIO acceptance/receipt/access/read/delivery/
    data response -> retired ISR load that consumed that exact read.

``CPU_TO_IP_TO_CPU``
    admitted CPU instruction -> fetched word and retired instruction whose
    source bytes are typed back to that admission -> GPIO A ``PADOUT`` MMIO
    acceptance/data acceptance/target receipt/register access/real register
    commit/delivery/data response -> retirement whose known-origin delivery
    link names the same admission.

Certificate material is bounded: at most ``max_pending`` candidates plus one
bounded cache per evidence kind, and every candidate carries at most the
required hop entries. Every candidate is settled at most once. A candidate
that ages out beyond ``max_event_gap``, is evicted by ``max_pending``, crosses
a reset barrier, or is still open at :meth:`ChainCertificates.flush` is emitted
as ``incomplete`` with ``missing_hops`` naming the first gap and every required
hop after it; no later event restores credit for a settled admission.

``cpu_irq_serial_token`` (optional, IP direction only)
    A certified ``irq_serial_certificate.v1`` token is fused as one extra hop
    between ``cpu_irq_taken`` and ``isr_padin_mmio_acceptance``. The join is one
    exact identity: the certificate's ``decision_producer_event_id`` -- the CPU
    step event that produced the native Ibex IRQ receipt the token was
    physically observed on -- must equal the CPU step event id the pin8
    ``cpu_irq_taken`` hop was emitted for, and the certificate must be
    ``certified`` with a nonzero decision serial equal to its retirement serial.
    The hop evidence carries ``decision_serial``, ``retirement_serial``,
    ``decision_event_id``, ``retirement_event_id``, ``take_identity``,
    ``take_identity_event_id``, ``take_identity_schema_version``, ``event_gap``,
    ``scope``, ``not_proof_of`` and ``proof_scope``
    (``exact_nonzero_irq_serial_token_equality``).

    Fail-closed rule, reported as ``serial_token_status`` on every certificate:

    ``absent``
        no certified token names this admission's take. The chain keeps its
        legacy verdict and hop sequence, so an old trace or a run without RVFI
        serial receipts is unchanged: a zero token means "no provable source
        lineage" by the frozen hardware semantics, and an observation the serial
        auditor refused stays in its own bounded rejection list and is never
        promoted here.
    ``witnessed``
        the token hop is attached with the exact certificate fields.
    ``refused``
        a certified token *is* attributable to this admission's take but a
        corroboration failed; ``serial_token_reason`` names the first failed
        check. A refusal is never silent: the admission is settled
        ``incomplete`` at that event and no later event restores its credit. A
        token whose retirement event arrives after the admission has already
        settled cannot amend the settled certificate, exactly like every other
        hop under the one-shot settlement rule.

    ``require_serial_token`` (default False) also makes the hop required for the
    IP direction, so only a witnessed token can certify there. The CPU direction
    carries no interrupt take identity at all, so the token is neither inserted
    into nor required from ``CPU_TO_IP_TO_CPU`` chains; ``serial_token_status``
    is then always ``absent``.

    Hop lists stay recomputable from one declared sequence per direction (the
    ``cpu_irq_serial_token`` entry sits at index ten of the IP sequence):
    ``hops`` lists every witnessed hop in that order, truncated at the first
    required hop that is absent, and ``missing_hops`` names the required hops
    absent from ``hops``. The optional unwitnessed token is simply omitted from
    both. A witnessed token counts towards ``completed_event_id`` through its
    retirement event, exactly like every other hop.

``certificate_id`` is the lowercase SHA-256 hex digest of the canonical UTF-8
JSON array ``[direction, source_admission_id]`` encoded with
``separators=(",", ":")`` and no trailing whitespace. It never depends on the
serial token.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping
import hashlib
import json

from .irq_serial_certificates import (
    CERTIFICATE_SCHEMA as _SERIAL_CERTIFICATE_SCHEMA,
    PROOF_SCOPE as _SERIAL_PROOF_SCOPE,
    IrqSerialCertificates,
)
from .pin8_consumption_certificates import _case
from .pin8_cpu_irq_certificates import Pin8CpuIrqCertificates
from .pin8_irq_certificates import Pin8IrqCertificates
from .source_provenance import SourceAdmission


SCHEMA_VERSION = "runtime_chain_certificate.v1"
IP_TO_CPU_TO_IP = "IP_TO_CPU_TO_IP"
CPU_TO_IP_TO_CPU = "CPU_TO_IP_TO_CPU"
CPU_IRQ_SERIAL_HOP = "cpu_irq_serial_token"
SERIAL_TOKEN_ABSENT = "absent"
SERIAL_TOKEN_WITNESSED = "witnessed"
SERIAL_TOKEN_REFUSED = "refused"

_IP_SOURCE_ID = "gpio_b.external_pin8"
_CPU_SOURCE_ID = "cpu.online_instruction"
_PIN8_BIT = 8
# pulp_gpio_probe_contract.pulp_gpio_register_map(): raw offset 8 is PADIN and
# raw offset 12 is PADOUT, whose committed register name is "out".
_PADIN_OFFSET = 8
_GPIO_A_DEVICE = "gpio_a"
_GPIO_B_DEVICE = "gpio_b"
_CPU_DEVICE = "cpu"
_PADOUT_REGISTER = "out"
_IRQ_MASK = 1 << _PIN8_BIT

_TRANSACTION_FIELDS = ("channel_id", "execution_id", "source_component",
                       "source_epoch", "source_sequence", "testcase_id")
_TRANSACTION_INT_FIELDS = frozenset(("source_epoch", "source_sequence"))

_RESET_KINDS = frozenset(("reset_barrier", "gpio_reset_resource", "cpu_reset"))

_IP_HOPS = (
    "pin8_admission", "pin8_injection", "pin8_segment_applied",
    "pin8_input_resource", "pin8_sync0_sample", "pin8_sync1_sample",
    "gpio_b_native_irq_trigger", "gpio_b_native_irq_observation",
    "cpu_irq_input", "cpu_irq_taken",
    "isr_padin_mmio_acceptance", "isr_padin_target_receipt",
    "isr_padin_target_access", "isr_padin_register_read",
    "isr_padin_mmio_delivery", "isr_padin_data_response",
    "isr_padin_retirement",
)
_CPU_HOPS = (
    "instruction_admission", "instruction_source", "instruction_fetch",
    "mmio_write_acceptance", "mmio_write_data_acceptance",
    "gpio_a_target_receipt", "gpio_a_target_access", "gpio_a_register_commit",
    "mmio_write_delivery", "mmio_write_data_response",
    "instruction_retirement", "instruction_retirement_match",
    "retired_target_delivery",
)
# The serial token witness is a CPU interrupt take witness, so it sits directly
# after ``cpu_irq_taken`` and before the ISR PADIN MMIO leg it never replaces.
_IP_SERIAL_POSITION = _IP_HOPS.index("isr_padin_mmio_acceptance")
_IP_SEQUENCE = (_IP_HOPS[:_IP_SERIAL_POSITION] + (CPU_IRQ_SERIAL_HOP,)
                + _IP_HOPS[_IP_SERIAL_POSITION:])
_IP_WEAK_HOPS = frozenset(("isr_padin_target_receipt", "isr_padin_retirement"))
_CPU_WEAK_HOPS = frozenset(("gpio_a_target_receipt", "retired_target_delivery"))

_PROOF_SCOPE = {IP_TO_CPU_TO_IP: "ip_to_cpu_to_ip_certified_hops",
                CPU_TO_IP_TO_CPU: "cpu_to_ip_to_cpu_certified_hops"}


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _flag(value: object) -> bool | int | None:
    """Normalise a journal on/off flag, refusing every other value."""
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


def _certificate_id(direction: str, admission_id: str) -> str:
    payload = json.dumps([direction, admission_id], separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ChainCertificates:
    """Fuse per-hop authenticated evidence into at most one chain per admission.

    The consumer is fed one contiguous journal slice at a time. The pin-8
    resource/IRQ and CPU-interrupt prefix is delegated to the existing
    :class:`Pin8IrqCertificates` and :class:`Pin8CpuIrqCertificates` auditors and
    never re-derived here; this class only joins their exact event IDs to the
    MMIO and retirement evidence it observes itself.
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096,
                 require_native_receipts: bool = True,
                 require_serial_token: bool = False) -> None:
        if (type(max_pending) is not int or max_pending < 1
                or type(max_event_gap) is not int or max_event_gap < 1):
            raise ValueError("certificate bounds must be positive integers")
        if type(require_native_receipts) is not bool:
            raise ValueError("require_native_receipts must be boolean")
        if type(require_serial_token) is not bool:
            raise ValueError("require_serial_token must be boolean")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self.require_native_receipts = require_native_receipts
        self.require_serial_token = require_serial_token
        self._last_event_id = 0
        self._last_case: dict[str, int] = {}
        self._candidates: OrderedDict[str, dict] = OrderedDict()
        self._settled: OrderedDict[str, None] = OrderedDict()
        self._complete: OrderedDict[str, None] = OrderedDict()
        self._native = Pin8IrqCertificates(max_pending=max_pending,
                                           max_event_gap=max_event_gap)
        self._cpu_irq = Pin8CpuIrqCertificates(max_pending=max_pending,
                                               max_event_gap=max_event_gap)
        self._serial = IrqSerialCertificates(max_pending=max_pending,
                                             max_event_gap=max_event_gap)
        self._serial_witnesses: OrderedDict[int, dict] = OrderedDict()
        self._settled_serial: list = []
        self._ticks: OrderedDict[int, dict] = OrderedDict()
        self._triggers: OrderedDict[str, dict] = OrderedDict()
        self._retires: OrderedDict[int, dict] = OrderedDict()
        self._instr_responses: OrderedDict[int, dict] = OrderedDict()
        self._matches: OrderedDict[int, dict] = OrderedDict()
        self._acceptances: OrderedDict[tuple, dict] = OrderedDict()
        self._data_accepts: OrderedDict[tuple, dict] = OrderedDict()
        self._data_responses: OrderedDict[tuple, dict] = OrderedDict()
        self._receipts: OrderedDict[str, dict] = OrderedDict()
        self._apb_accesses: OrderedDict[str, dict] = OrderedDict()
        self._commits: OrderedDict[int, dict] = OrderedDict()
        self._deliveries: OrderedDict[str, dict] = OrderedDict()
        self._deliveries_by_transaction: OrderedDict[tuple, dict] = OrderedDict()
        self._accesses_by_transaction: OrderedDict[tuple, dict] = OrderedDict()

    # ------------------------------------------------------------------ API

    @property
    def pending_count(self) -> int:
        """Number of unsettled candidates; never above ``max_pending``."""
        return len(self._candidates)

    @property
    def serial_witness_count(self) -> int:
        """Retained tokens that name no live admission take; bounded by capacity."""
        return len(self._serial_witnesses)

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        """Consume the next contiguous journal slice and return new certificates."""
        result = []
        for event in events:
            if (not isinstance(event, Mapping)
                    or type(event.get("event_id")) is not int
                    or event["event_id"] != self._last_event_id + 1):
                raise ValueError("certificate journal must be contiguous")
            event_id = event["event_id"]
            self._last_event_id = event_id
            result.extend(self._expire(event_id))
            component = event.get("component")
            local_tick = event.get("local_tick")
            if component == _CPU_DEVICE and not _integer(local_tick):
                # CPU journal records use "tick" for the same CPU tick.
                local_tick = event.get("tick")
            if type(component) is str and component and _integer(local_tick):
                self._store(self._ticks, event_id,
                            {"event_id": event_id, "component": component,
                             "local_tick": local_tick})
            if event.get("kind") in _RESET_KINDS:
                result.extend(self._settle_all(event_id))
                self._caches_clear()
            else:
                result.extend(self._dispatch(event))
            for certificate in self._native.ingest((event,)):
                self._attach_native(certificate)
            for certificate in self._cpu_irq.ingest((event,)):
                self._attach_cpu_irq(certificate)
            for certificate in self._serial.ingest((event,)):
                self._serial_witness(certificate)
            result.extend(self._drain_settled_serial())
            result.extend(self._settle_complete(event_id))
        return tuple(result)

    def flush(self) -> tuple[dict, ...]:
        """Settle every candidate still open at the end of the journal."""
        return tuple(self._settle_all(self._last_event_id))

    # ------------------------------------------------------------- internals

    def _sequence(self, direction: str) -> tuple[str, ...]:
        """Declared hop sequence of one direction, serial witness included."""
        return _IP_SEQUENCE if direction == IP_TO_CPU_TO_IP else _CPU_HOPS

    def _required(self, direction: str) -> tuple[str, ...]:
        weak = _IP_WEAK_HOPS if direction == IP_TO_CPU_TO_IP else _CPU_WEAK_HOPS
        hops = self._sequence(direction)
        if direction == IP_TO_CPU_TO_IP and not self.require_serial_token:
            hops = tuple(name for name in hops if name != CPU_IRQ_SERIAL_HOP)
        if self.require_native_receipts:
            return hops
        return tuple(name for name in hops if name not in weak)

    def _limit(self, cache: OrderedDict) -> None:
        while len(cache) > self.max_pending:
            cache.popitem(last=False)

    def _store(self, cache: OrderedDict, key: object, entry: dict) -> None:
        cache[key] = entry
        self._limit(cache)

    def _cache_list(self) -> tuple[OrderedDict, ...]:
        return (self._ticks, self._triggers, self._retires,
                self._instr_responses, self._matches, self._acceptances,
                self._data_accepts, self._data_responses, self._receipts,
                self._apb_accesses, self._commits, self._deliveries,
                self._deliveries_by_transaction, self._accesses_by_transaction,
                self._serial_witnesses)

    def _caches_clear(self) -> None:
        for cache in self._cache_list():
            cache.clear()

    def _expire(self, event_id: int) -> list:
        result = []
        for admission_id, state in tuple(self._candidates.items()):
            if event_id - state["admission_event_id"] > self.max_event_gap:
                result.append(self._settle(admission_id, "incomplete", event_id))
        for cache in self._cache_list():
            while cache:
                entry = next(iter(cache.values()))
                if event_id - entry["event_id"] <= self.max_event_gap:
                    break
                cache.popitem(last=False)
        return result

    def _remember(self, admission_id: str) -> None:
        self._settled[admission_id] = None
        self._limit(self._settled)

    def _settle_all(self, event_id: int) -> list:
        return [self._settle(admission_id, "incomplete", event_id)
                for admission_id in tuple(self._candidates)]

    def _settle_complete(self, event_id: int) -> list:
        result = []
        while self._complete:
            admission_id, _ = self._complete.popitem(last=False)
            if admission_id in self._candidates:
                result.append(self._settle(admission_id, "certified", event_id))
        return result

    def _settle(self, admission_id: str, status: str, event_id: int) -> dict:
        state = self._candidates.pop(admission_id)
        self._complete.pop(admission_id, None)
        self._remember(admission_id)
        return self._document(state, status, event_id)

    def _document(self, state: dict, status: str, event_id: int) -> dict:
        required = state["required"]
        hops = []
        missing = []
        for name in state["sequence"]:
            entry = state["hops"].get(name)
            if entry is not None and not missing:
                hops.append({"hop_id": name, "event_id": entry["event_id"],
                             "evidence": dict(entry["evidence"])})
            elif name in required:
                missing.append(name)
        ticks = {}
        for hop in hops:
            component = hop["evidence"].get("component")
            tick = hop["evidence"].get("local_tick")
            if type(component) is str and _integer(tick):
                ticks[component] = tick
        admission = state["admission"]
        endpoint = state.get("endpoint_case")
        witnessed = any(hop["hop_id"] == CPU_IRQ_SERIAL_HOP for hop in hops)
        return {
            "schema_version": SCHEMA_VERSION,
            "certificate_id": _certificate_id(state["direction"],
                                              admission.admission_id),
            "status": status,
            "direction": state["direction"],
            "source_admission_id": admission.admission_id,
            "source_action_id": admission.action_id,
            "source_component": admission.component,
            "source_id": admission.source_id,
            "source_case_id": admission.case_id,
            "source_case_index": admission.case_index,
            "endpoint_case_id": endpoint["case_id"] if endpoint else None,
            "endpoint_case_index": endpoint["case_index"] if endpoint else None,
            "serial_token_status": (SERIAL_TOKEN_WITNESSED if witnessed
                                    else state["serial_status"]),
            "serial_token_reason": (None if witnessed
                                    else state["serial_reason"]),
            "completed_event_id": event_id,
            "completed_local_ticks": ticks,
            "hops": hops,
            "missing_hops": [] if status == "certified" else missing,
            "proof_scope": _PROOF_SCOPE[state["direction"]],
        }

    def _attach(self, state: dict, hop_id: str, event_id: object, kind: str,
                **evidence: object) -> bool:
        """Attach one certified hop; never overwrite or reorder an existing hop."""
        if (not _integer(event_id) or event_id <= 0
                or event_id > self._last_event_id):
            return False
        required = state["required"]
        sequence = state["sequence"]
        if hop_id not in sequence or hop_id in state["hops"]:
            return False
        position = sequence.index(hop_id)
        for name, entry in state["hops"].items():
            other = sequence.index(name)
            if other < position and entry["event_id"] >= event_id:
                return False
            if other > position and entry["event_id"] <= event_id:
                return False
        case = evidence.pop("observed_case", None)
        record = {"kind": kind, **evidence}
        tick = self._ticks.get(event_id)
        if tick is not None:
            record.setdefault("component", tick["component"])
            record.setdefault("local_tick", tick["local_tick"])
        if (isinstance(case, Mapping) and type(case.get("case_id")) is str
                and _integer(case.get("case_index"))):
            state["endpoint_case"] = {"case_id": case["case_id"],
                                      "case_index": case["case_index"]}
        state["hops"][hop_id] = {"event_id": event_id, "evidence": record}
        if all(name in state["hops"] for name in required):
            self._complete[state["admission"].admission_id] = None
        return True

    def _candidate(self, direction: str, action_id: str | None = None) -> dict | None:
        for state in self._candidates.values():
            if state["direction"] != direction:
                continue
            if action_id is None or state["admission"].action_id == action_id:
                return state
        return None

    # -------------------------------------------------------------- dispatch

    def _dispatch(self, event: Mapping) -> list:
        kind = event.get("kind")
        if kind == "source_admission":
            return self._admission(event)
        if kind == "instruction_source":
            return self._instruction_source(event)
        if kind == "gpio_irq_trigger":
            return self._trigger(event)
        if kind == "instr_response":
            return self._instr_response(event)
        if kind == "cpu_retire":
            return self._retire(event)
        if kind == "mmio_acceptance":
            return self._acceptance(event)
        if kind == "data_accept":
            return self._data_accept(event)
        if kind == "data_response":
            return self._data_response(event)
        if kind == "gpio_target_receipt":
            return self._receipt(event)
        if kind == "gpio_apb_access":
            return self._apb_access(event)
        if kind == "gpio_register_commit":
            return self._commit(event)
        if kind == "mmio_delivery":
            return self._delivery(event)
        if kind == "gpio_register_read":
            return self._register_read(event)
        if kind == "cpu_retirement_match":
            return self._retirement_match(event)
        if kind == "cpu_retired_transaction_target_delivery":
            return self._retired_delivery(event)
        return []

    def _admission(self, event: Mapping) -> list:
        try:
            admission = SourceAdmission.from_document(event.get("admission"))
        except (TypeError, ValueError):
            return []
        direction = admission.direction
        if admission.role != "fuzz_source":
            return []
        if direction == IP_TO_CPU_TO_IP:
            if (admission.source_id != _IP_SOURCE_ID
                    or admission.component != _GPIO_B_DEVICE
                    or admission.input_kind != "source_event"):
                return []
        elif direction == CPU_TO_IP_TO_CPU:
            if (admission.source_id != _CPU_SOURCE_ID
                    or admission.component != _CPU_DEVICE
                    or admission.input_kind != "instruction"):
                return []
        else:
            return []
        if _case(event) != {"case_id": admission.case_id,
                            "case_index": admission.case_index}:
            return []
        provenance = event.get("provenance")
        if (not isinstance(provenance, Mapping)
                or provenance.get("origin_status") != "known"
                or provenance.get("origin_admission_ids")
                != [admission.admission_id]):
            return []
        # Case indices advance monotonically per direction, exactly as the
        # per-hop auditors require; a repeated or regressed admission is never
        # re-admitted and can therefore never recover credit.
        if admission.case_index <= self._last_case.get(direction, -1):
            return []
        self._last_case[direction] = admission.case_index
        if (admission.admission_id in self._candidates
                or admission.admission_id in self._settled):
            return []
        required = self._required(direction)
        state = {"admission": admission, "direction": direction,
                 "admission_event_id": event["event_id"], "required": required,
                 "sequence": self._sequence(direction),
                 "serial_status": SERIAL_TOKEN_ABSENT, "serial_reason": None,
                 "hops": {}, "trigger": None, "take": None, "isr": None,
                 "source": None, "retirement": None, "endpoint_case": None}
        self._candidates[admission.admission_id] = state
        self._attach(state, required[0], event["event_id"], "source_admission",
                     admission_id=admission.admission_id,
                     action_id=admission.action_id, observed_case=_case(event))
        result = []
        while len(self._candidates) > self.max_pending:
            evicted, evicted_state = self._candidates.popitem(last=False)
            self._complete.pop(evicted, None)
            self._remember(evicted)
            result.append(self._document(evicted_state, "incomplete",
                                         event["event_id"]))
        return result

    def _instruction_source(self, event: Mapping) -> list:
        action = event.get("source_event_id")
        if type(action) is not str or not action:
            return []
        state = self._candidate(CPU_TO_IP_TO_CPU, action)
        if state is None or state["source"] is not None:
            return []
        provenance = event.get("provenance")
        if (event.get("component") != _CPU_DEVICE
                or not isinstance(provenance, Mapping)
                or provenance.get("origin_status") != "known"
                or provenance.get("origin_admission_ids")
                != [state["admission"].admission_id]):
            return []
        address = event.get("address")
        data_hex = event.get("data_hex")
        if not _integer(address) or type(data_hex) is not str or not data_hex:
            return []
        try:
            length = len(bytes.fromhex(data_hex))
        except ValueError:
            return []
        if length == 0:
            return []
        state["source"] = {"event_id": event["event_id"], "address": address,
                           "length": length, "action_id": action}
        self._attach(state, "instruction_source", event["event_id"],
                     "instruction_source", component=_CPU_DEVICE,
                     address=address, length=length, action_id=action,
                     observed_case=_case(event))
        return []

    def _trigger(self, event: Mapping) -> list:
        if (event.get("component") != _GPIO_B_DEVICE
                or event.get("mask") != _IRQ_MASK):
            return []
        trigger_id = event.get("trigger_id")
        causes = event.get("causes")
        tick_event_id = event.get("observation_event_id")
        if (type(trigger_id) is not str or not trigger_id
                or not _integer(tick_event_id)
                or not isinstance(causes, list) or len(causes) != 1
                or not isinstance(causes[0], Mapping)):
            return []
        current = causes[0].get("current_sample")
        if not isinstance(current, Mapping):
            return []
        refs = current.get("origin_refs")
        if not isinstance(refs, list):
            return []
        self._store(self._triggers, trigger_id, {
            "event_id": event["event_id"], "tick_event_id": tick_event_id,
            "value": current.get("value"),
            "origin_refs": [dict(ref) if isinstance(ref, Mapping) else ref
                            for ref in refs],
            "reset_epoch": event.get("reset_epoch"),
            "observed_case": _case(event)})
        return []

    def _instr_response(self, event: Mapping) -> list:
        address = event.get("address")
        rdata = event.get("rdata")
        if (event.get("component") != _CPU_DEVICE or not _integer(address)
                or not _integer(rdata) or _flag(event.get("write")) != 0):
            return []
        self._store(self._instr_responses, event["event_id"], {
            "event_id": event["event_id"], "address": address, "rdata": rdata,
            "observed_case": _case(event)})
        return []

    def _retire(self, event: Mapping) -> list:
        if event.get("component") != _CPU_DEVICE:
            return []
        self._store(self._retires, event["event_id"], {
            "event_id": event["event_id"], "insn": event.get("insn"),
            "order": event.get("order"), "pc_rdata": event.get("pc_rdata"),
            "valid": _flag(event.get("valid")), "trap": _flag(event.get("trap")),
            "intr": _flag(event.get("intr")), "mem_addr": event.get("mem_addr"),
            "mem_wmask": event.get("mem_wmask"),
            "mem_rmask": event.get("mem_rmask"),
            "mem_wdata": event.get("mem_wdata"),
            "mem_rdata": event.get("mem_rdata"),
            "observed_case": _case(event)})
        return []

    def _acceptance(self, event: Mapping) -> list:
        key = _transaction_key(event.get("source_transaction"))
        write = _flag(event.get("write"))
        if (event.get("component") != _CPU_DEVICE or key is None or write is None
                or type(event.get("device_id")) is not str):
            return []
        self._store(self._acceptances, key, {
            "event_id": event["event_id"], "device_id": event["device_id"],
            "offset": event.get("offset"), "write": write,
            "write_value": event.get("write_value"),
            "address": event.get("address"), "transaction": key,
            "observed_case": _case(event)})
        return []

    def _data_accept(self, event: Mapping) -> list:
        key = _transaction_key(event.get("transaction"))
        write = _flag(event.get("write"))
        if (event.get("component") != _CPU_DEVICE or key is None or write is None
                or not _integer(event.get("address"))):
            return []
        self._store(self._data_accepts, key, {
            "event_id": event["event_id"], "write": write,
            "address": event["address"], "wdata": event.get("wdata"),
            "transaction": key, "observed_case": _case(event)})
        return []

    def _data_response(self, event: Mapping) -> list:
        key = _transaction_key(event.get("transaction"))
        write = _flag(event.get("write"))
        if event.get("component") != _CPU_DEVICE or key is None or write is None:
            return []
        self._store(self._data_responses, key, {
            "event_id": event["event_id"], "write": write,
            "address": event.get("address"), "rdata": event.get("rdata"),
            "transaction": key, "observed_case": _case(event)})
        for state in tuple(self._candidates.values()):
            isr = state["isr"]
            if (isr is None or isr["transaction"] != key or write != 0
                    or event.get("address") != isr["address"]):
                continue
            if self._attach(state, "isr_padin_data_response", event["event_id"],
                            "data_response", component=_CPU_DEVICE, write=0,
                            address=event.get("address"),
                            rdata=event.get("rdata"), transaction=list(key),
                            observed_case=_case(event)):
                isr["response_event_id"] = event["event_id"]
        return []

    def _receipt(self, event: Mapping) -> list:
        access_id = event.get("access_id")
        write = _flag(event.get("write"))
        if (type(access_id) is not str or not access_id or write is None
                or type(event.get("component")) is not str
                or event.get("status") != "received"):
            return []
        self._store(self._receipts, access_id, {
            "event_id": event["event_id"], "component": event.get("component"),
            "raw_offset": event.get("raw_offset"),
            "decoded_offset": event.get("decoded_offset"), "write": write,
            "status": event.get("status"),
            "producer_event_id": event.get("producer_event_id"),
            "observed_case": _case(event)})
        return []

    def _apb_access(self, event: Mapping) -> list:
        access_id = event.get("access_id")
        write = _flag(event.get("write"))
        if (type(access_id) is not str or not access_id or write is None
                or type(event.get("component")) is not str
                or event.get("status") != "observed"):
            return []
        entry = {"event_id": event["event_id"],
                 "component": event.get("component"),
                 "raw_offset": event.get("raw_offset"),
                 "decoded_offset": event.get("decoded_offset"), "write": write,
                 "wdata": event.get("wdata"), "access_id": access_id,
                 "producer_event_id": event.get("producer_event_id"),
                 "transaction": _transaction_key(event.get("source_transaction")),
                 "observed_case": _case(event)}
        self._store(self._apb_accesses, access_id, entry)
        if entry["transaction"] is not None:
            self._store(self._accesses_by_transaction, entry["transaction"], entry)
        return []

    def _commit(self, event: Mapping) -> list:
        access_id = event.get("access_id")
        observation = event.get("observation_event_id")
        if (type(access_id) is not str or not access_id
                or not _integer(observation)
                or type(event.get("component")) is not str
                or type(event.get("register")) is not str
                or event.get("status") != "observed"):
            return []
        self._store(self._commits, observation, {
            "event_id": event["event_id"], "component": event.get("component"),
            "register": event.get("register"), "access_id": access_id,
            "decoded_offset": event.get("decoded_offset"),
            "write_value": event.get("write_value"),
            "observation_event_id": observation,
            "observed_case": _case(event)})
        return []

    def _delivery(self, event: Mapping) -> list:
        access_id = event.get("target_access_id")
        key = _transaction_key(event.get("source_transaction"))
        write = _flag(event.get("write"))
        if (type(access_id) is not str or not access_id or key is None
                or write is None or event.get("component") != _CPU_DEVICE):
            return []
        entry = {"event_id": event["event_id"],
                 "device_id": event.get("device_id"),
                 "offset": event.get("offset"), "write": write,
                 "write_value": event.get("write_value"),
                 "read_value": event.get("read_value"),
                 "address": event.get("address"), "access_id": access_id,
                 "transaction": key, "observed_case": _case(event)}
        self._store(self._deliveries, access_id, entry)
        self._store(self._deliveries_by_transaction, key, entry)
        for state in tuple(self._candidates.values()):
            isr = state["isr"]
            if (isr is None or isr["access_id"] != access_id
                    or isr["delivery_event_id"] is not None
                    or isr["transaction"] != key
                    or event.get("device_id") != _GPIO_B_DEVICE
                    or event.get("offset") != _PADIN_OFFSET or write is not False):
                continue
            if self._attach(state, "isr_padin_mmio_delivery", event["event_id"],
                            "mmio_delivery", component=_CPU_DEVICE,
                            device_id=_GPIO_B_DEVICE, offset=_PADIN_OFFSET,
                            write=False, target_access_id=access_id,
                            transaction=list(key), observed_case=_case(event)):
                isr["delivery_event_id"] = event["event_id"]
        return []

    def _register_read(self, event: Mapping) -> list:
        access_id = event.get("access_id")
        if (event.get("component") != _GPIO_B_DEVICE
                or event.get("register") != "padin_latch"
                or type(access_id) is not str or not access_id
                or not _integer(event.get("observation_event_id"))):
            return []
        resources = event.get("bit_resources")
        if not isinstance(resources, list):
            return []
        pins = [item for item in resources
                if isinstance(item, Mapping) and item.get("bit") == _PIN8_BIT]
        if len(pins) != 1:
            return []
        resource = pins[0]
        refs = resource.get("origin_refs")
        value = resource.get("value")
        if (resource.get("origin_status") != "known"
                or not isinstance(refs, list) or len(refs) != 1
                or not isinstance(refs[0], Mapping)
                or type(value) is not int or value not in (0, 1)):
            return []
        document = dict(refs[0])
        state = None
        for candidate in self._candidates.values():
            if (candidate["direction"] == IP_TO_CPU_TO_IP
                    and candidate["isr"] is None
                    and candidate["take"] is not None
                    and candidate["trigger"] is not None
                    and candidate["trigger"]["value"] == value
                    and candidate["take"]["event_id"] < event["event_id"]
                    and candidate["admission"].document() == document):
                state = candidate
                break
        if state is None:
            return []
        apb = self._apb_accesses.get(access_id)
        if (apb is None or apb["component"] != _GPIO_B_DEVICE
                or apb["event_id"] != event["observation_event_id"]
                or apb["event_id"] != event.get("producer_event_id")
                or apb["decoded_offset"] != _PADIN_OFFSET
                or apb["write"] is not False or apb["transaction"] is None):
            return []
        key = apb["transaction"]
        acceptance = self._acceptances.get(key)
        beat = self._data_accepts.get(key)
        if (acceptance is None or beat is None
                or acceptance["device_id"] != _GPIO_B_DEVICE
                or acceptance["offset"] != _PADIN_OFFSET
                or acceptance["write"] is not False
                or beat["write"] != 0 or beat["address"] != acceptance["address"]):
            return []
        receipt = self._receipts.get(access_id)
        if self.require_native_receipts:
            if (receipt is None or receipt["component"] != _GPIO_B_DEVICE
                    or receipt["raw_offset"] != _PADIN_OFFSET
                    or receipt["write"] is not False
                    or receipt["status"] != "received"
                    or receipt["producer_event_id"] != apb["producer_event_id"]):
                return []
        case = _case(event)
        self._attach(state, "isr_padin_mmio_acceptance", acceptance["event_id"],
                     "mmio_acceptance", component=_CPU_DEVICE,
                     device_id=_GPIO_B_DEVICE, offset=_PADIN_OFFSET, write=False,
                     address=acceptance["address"],
                     data_accept_event_id=beat["event_id"],
                     transaction=list(key), observed_case=case)
        if self.require_native_receipts:
            self._attach(state, "isr_padin_target_receipt", receipt["event_id"],
                         "gpio_target_receipt", component=_GPIO_B_DEVICE,
                         access_id=access_id, write=False, status="received",
                         observed_case=case)
        self._attach(state, "isr_padin_target_access", apb["event_id"],
                     "gpio_apb_access", component=_GPIO_B_DEVICE,
                     access_id=access_id, decoded_offset=_PADIN_OFFSET,
                     write=False, transaction=list(key), observed_case=case)
        self._attach(state, "isr_padin_register_read", event["event_id"],
                     "gpio_register_read", component=_GPIO_B_DEVICE,
                     access_id=access_id, register="padin_latch",
                     bit=_PIN8_BIT, value=value, version=resource.get("version"),
                     admission_id=state["admission"].admission_id,
                     observed_case=case)
        state["isr"] = {"access_id": access_id, "transaction": key,
                        "address": acceptance["address"],
                        "acceptance_event_id": acceptance["event_id"],
                        "data_accept_event_id": beat["event_id"],
                        "read_event_id": event["event_id"],
                        "response_event_id": None,
                        "delivery_event_id": None}
        return []

    def _retirement_match(self, event: Mapping) -> list:
        """Resolve every hop this retirement can prove, one validation each."""
        if (event.get("component") != _CPU_DEVICE
                or event.get("status") != "accepted"):
            return []
        keys = event.get("transaction_keys")
        beats = event.get("data_beats")
        well_formed = (isinstance(keys, list) and len(keys) == 1
                       and isinstance(beats, list) and len(beats) == 1
                       and isinstance(beats[0], Mapping))
        key = _transaction_key(keys[0]) if well_formed else None
        if well_formed and key is not None:
            # Retain the retirement identity for the ISR read chain too, which
            # has no typed source writer at all.
            inner = beats[0].get("response")
            self._store(self._matches, event["event_id"], {
                "event_id": event["event_id"], "transaction": key,
                "data_beat_event_id": beats[0].get("event_id"),
                "response_event_id": (inner.get("event_id")
                                      if isinstance(inner, Mapping) else None),
                "producer_event_id": event.get("producer_event_id"),
                "observed_case": _case(event)})
        if event.get("instruction_origin_status") != "typed_writer_refs":
            return []
        refs = event.get("source_refs")
        cells = event.get("byte_cells")
        responses = event.get("instruction_responses")
        if (not well_formed or key is None
                or not isinstance(responses, list) or len(responses) != 1
                or not isinstance(responses[0], Mapping)
                or not isinstance(refs, list) or len(refs) != 1
                or type(refs[0]) is not str or not refs[0]
                or not isinstance(cells, list) or not cells):
            return []
        beat = beats[0]
        response = responses[0]
        action = refs[0]
        if _transaction_key(beat.get("transaction")) != key:
            return []
        # Identity gate: the retired instruction must be exactly this admitted
        # source and must be the data write of this very transaction.
        state = self._candidate(CPU_TO_IP_TO_CPU, action)
        if state is None or state["source"] is None \
                or state["retirement"] is not None:
            return []
        for cell in cells:
            if (not isinstance(cell, Mapping)
                    or set(cell.get("writer_event_ids") or []) != {action}
                    or set(cell.get("writer_kinds") or []) != {"INSTRUCTION_SOURCE"}):
                return []
        retire = self._retires.get(event.get("producer_event_id"))
        if (retire is None or retire["valid"] != 1 or retire["trap"] != 0
                or retire["intr"] != 0 or not _integer(retire["insn"])
                or event.get("insn") != retire["insn"]
                or event.get("order") != retire["order"]
                or event.get("pc") != retire["pc_rdata"]
                or _flag(beat.get("write")) != 1):
            return []
        snapshot = response.get("snapshot")
        fetch = self._instr_responses.get(response.get("event_id"))
        address = response.get("address")
        if (not isinstance(snapshot, Mapping)
                or set(snapshot.get("writer_event_ids") or []) != {action}
                or set(snapshot.get("writer_kinds") or []) != {"INSTRUCTION_SOURCE"}
                or fetch is None or fetch["address"] != address
                or fetch["rdata"] != response.get("rdata")
                or response.get("rdata") != retire["insn"]
                or not _integer(address)
                or not (state["source"]["address"] <= address
                        < state["source"]["address"] + state["source"]["length"])):
            return []
        data_beat = self._data_accepts.get(key)
        response_beat = self._data_responses.get(key)
        acceptance = self._acceptances.get(key)
        delivery = self._deliveries_by_transaction.get(key)
        apb = self._accesses_by_transaction.get(key)
        if apb is None and delivery is not None:
            apb = self._apb_accesses.get(delivery["access_id"])
        commit = self._commits.get(apb["event_id"]) if apb is not None else None
        receipt = (self._receipts.get(apb["access_id"])
                   if apb is not None else None)
        case = _case(event)
        self._attach(state, "instruction_fetch", fetch["event_id"],
                     "instr_response", component=_CPU_DEVICE, address=address,
                     rdata=fetch["rdata"], observed_case=case)
        if (acceptance is not None
                and acceptance["device_id"] == _GPIO_A_DEVICE
                and acceptance["write"] is True
                and acceptance["write_value"] == beat.get("wdata")
                and data_beat is not None
                and acceptance["address"] == data_beat["address"]):
            self._attach(state, "mmio_write_acceptance", acceptance["event_id"],
                         "mmio_acceptance", component=_CPU_DEVICE,
                         device_id=_GPIO_A_DEVICE, offset=acceptance["offset"],
                         write=True, write_value=acceptance["write_value"],
                         address=acceptance["address"], transaction=list(key),
                         observed_case=case)
        if (data_beat is not None and data_beat["event_id"] == beat.get("event_id")
                and data_beat["address"] == beat.get("address")
                and data_beat["write"] == 1
                and retire["mem_addr"] == data_beat["address"]
                and retire["mem_wdata"] == beat.get("wdata")):
            self._attach(state, "mmio_write_data_acceptance", data_beat["event_id"],
                         "data_accept", component=_CPU_DEVICE, write=1,
                         address=data_beat["address"], wdata=beat.get("wdata"),
                         transaction=list(key), observed_case=case)
        if (self.require_native_receipts and receipt is not None
                and apb is not None and receipt["component"] == _GPIO_A_DEVICE
                and receipt["write"] is True and receipt["status"] == "received"
                and receipt["producer_event_id"] == apb["producer_event_id"]):
            self._attach(state, "gpio_a_target_receipt", receipt["event_id"],
                         "gpio_target_receipt", component=_GPIO_A_DEVICE,
                         access_id=apb["access_id"], write=True,
                         status="received", observed_case=case)
        if (apb is not None and apb["component"] == _GPIO_A_DEVICE
                and apb["write"] is True and apb["wdata"] == beat.get("wdata")
                and (delivery is None or apb["decoded_offset"]
                     == delivery["offset"])):
            self._attach(state, "gpio_a_target_access", apb["event_id"],
                         "gpio_apb_access", component=_GPIO_A_DEVICE,
                         access_id=apb["access_id"],
                         decoded_offset=apb["decoded_offset"], write=True,
                         wdata=apb["wdata"], transaction=list(key),
                         observed_case=case)
        if (commit is not None and apb is not None
                and commit["component"] == _GPIO_A_DEVICE
                and commit["register"] == _PADOUT_REGISTER
                and commit["observation_event_id"] == apb["event_id"]
                and commit["access_id"] == apb["access_id"]
                and commit["decoded_offset"] == apb["decoded_offset"]
                and commit["write_value"] == apb["wdata"]):
            self._attach(state, "gpio_a_register_commit", commit["event_id"],
                         "gpio_register_commit", component=_GPIO_A_DEVICE,
                         register=_PADOUT_REGISTER,
                         decoded_offset=commit["decoded_offset"],
                         write_value=commit["write_value"],
                         observation_event_id=apb["event_id"],
                         observed_case=case)
        if (delivery is not None and delivery["device_id"] == _GPIO_A_DEVICE
                and delivery["write"] is True
                and delivery["write_value"] == beat.get("wdata")
                and data_beat is not None
                and delivery["address"] == data_beat["address"]):
            self._attach(state, "mmio_write_delivery", delivery["event_id"],
                         "mmio_delivery", component=_CPU_DEVICE,
                         device_id=_GPIO_A_DEVICE, offset=delivery["offset"],
                         write=True, write_value=delivery["write_value"],
                         target_access_id=delivery["access_id"],
                         transaction=list(key), observed_case=case)
        inner = beat.get("response")
        if (data_beat is not None and response_beat is not None
                and isinstance(inner, Mapping)
                and inner.get("event_id") == response_beat["event_id"]
                and _transaction_key(inner.get("transaction")) == key
                and response_beat["write"] == 1
                and response_beat["address"] == data_beat["address"]):
            self._attach(state, "mmio_write_data_response",
                         response_beat["event_id"], "data_response",
                         component=_CPU_DEVICE, write=1,
                         address=response_beat["address"],
                         rdata=response_beat["rdata"], transaction=list(key),
                         observed_case=case)
        self._attach(state, "instruction_retirement", retire["event_id"],
                     "cpu_retire", component=_CPU_DEVICE, insn=retire["insn"],
                     order=retire["order"], pc_rdata=retire["pc_rdata"],
                     observed_case=case)
        self._attach(state, "instruction_retirement_match", event["event_id"],
                     "cpu_retirement_match", component=_CPU_DEVICE,
                     action_id=action, order=event.get("order"),
                     address=address, observed_case=case)
        state["retirement"] = {
            "match_event_id": event["event_id"], "transaction": key,
            "delivery_event_id": (delivery["event_id"]
                                  if delivery is not None else None),
            "access_id": (delivery["access_id"] if delivery is not None
                          else (apb["access_id"] if apb is not None else None))}
        return []

    def _retired_delivery(self, event: Mapping) -> list:
        if (event.get("component") != _CPU_DEVICE
                or event.get("status") != "linked_raw"):
            return []
        self._isr_retirement(event)
        self._retired_write(event)
        return []

    def _isr_retirement(self, event: Mapping) -> bool:
        delivery_id = event.get("delivery_event_id")
        state = None
        for candidate in self._candidates.values():
            isr = candidate["isr"]
            if (isr is not None and isr["delivery_event_id"] is not None
                    and isr["delivery_event_id"] == delivery_id):
                state = candidate
                break
        if state is None:
            return False
        isr = state["isr"]
        consumer = event.get("consumer_resource")
        match = self._matches.get(event.get("retirement_event_id"))
        if (not isinstance(consumer, Mapping) or match is None
                or consumer.get("device_id") != _GPIO_B_DEVICE
                or consumer.get("offset") != _PADIN_OFFSET
                or _flag(consumer.get("write")) is not False
                or consumer.get("target_access_id") != isr["access_id"]
                or not _integer(event.get("retirement_event_id"))
                or event["retirement_event_id"] <= state["take"]["event_id"]
                or match["transaction"] != isr["transaction"]
                or match["data_beat_event_id"] != isr["data_accept_event_id"]
                or match["response_event_id"] != isr["response_event_id"]):
            return False
        return self._attach(state, "isr_padin_retirement", event["event_id"],
                            "cpu_retired_transaction_target_delivery",
                            component=_CPU_DEVICE, status="linked_raw",
                            retirement_event_id=event["retirement_event_id"],
                            delivery_event_id=delivery_id,
                            target_access_id=isr["access_id"],
                            registered_origin_status=event.get(
                                "registered_origin_status"),
                            observed_case=_case(event))

    def _retired_write(self, event: Mapping) -> bool:
        origins = event.get("registered_origins")
        refs = event.get("source_refs")
        consumer = event.get("consumer_resource")
        if (event.get("registered_origin_status") != "known"
                or not isinstance(origins, list) or len(origins) != 1
                or not isinstance(origins[0], Mapping)
                or not isinstance(refs, list) or len(refs) != 1
                or type(refs[0]) is not str or not refs[0]
                or not isinstance(consumer, Mapping)):
            return False
        document = dict(origins[0])
        state = None
        for candidate in self._candidates.values():
            if (candidate["direction"] == CPU_TO_IP_TO_CPU
                    and candidate["retirement"] is not None
                    and candidate["admission"].document() == document
                    and candidate["admission"].action_id == refs[0]):
                state = candidate
                break
        if state is None:
            return False
        retirement = state["retirement"]
        if event.get("retirement_event_id") != retirement["match_event_id"]:
            return False
        if (retirement["delivery_event_id"] is not None
                and event.get("delivery_event_id")
                != retirement["delivery_event_id"]):
            return False
        delivery = self._deliveries.get(consumer.get("target_access_id"))
        if (delivery is None
                or delivery["event_id"] != event.get("delivery_event_id")
                or delivery["transaction"] != retirement["transaction"]
                or consumer.get("device_id") != _GPIO_A_DEVICE
                or consumer.get("offset") != delivery["offset"]
                or _flag(consumer.get("write")) is not True
                or consumer.get("write_value") != delivery["write_value"]
                or delivery["device_id"] != _GPIO_A_DEVICE
                or delivery["write"] is not True):
            return False
        return self._attach(state, "retired_target_delivery", event["event_id"],
                            "cpu_retired_transaction_target_delivery",
                            component=_CPU_DEVICE, status="linked_raw",
                            registered_origin_status="known",
                            registered_origin_admission_id=(
                                state["admission"].admission_id),
                            retirement_event_id=event["retirement_event_id"],
                            delivery_event_id=event["delivery_event_id"],
                            target_access_id=delivery["access_id"],
                            observed_case=_case(event))

    def _attach_native(self, certificate: Mapping) -> bool:
        admission_id = certificate.get("admission_id")
        state = self._candidates.get(admission_id)
        if state is None or state["direction"] != IP_TO_CPU_TO_IP:
            return False
        event_ids = certificate.get("event_ids")
        if (not isinstance(event_ids, list) or len(event_ids) != 8
                or not all(_integer(event_id) for event_id in event_ids)):
            return False
        trigger = self._triggers.get(certificate.get("trigger_id"))
        if (trigger is None
                or trigger["event_id"] != certificate.get("trigger_event_id")
                or trigger["tick_event_id"]
                != certificate.get("trigger_tick_event_id")
                or trigger["origin_refs"] != [state["admission"].document()]
                or type(trigger["value"]) is not int
                or trigger["value"] not in (0, 1)):
            return False
        trigger_id = certificate["trigger_id"]
        state["trigger"] = {"trigger_id": trigger_id,
                            "event_id": certificate["trigger_event_id"],
                            "tick_event_id": certificate["trigger_tick_event_id"],
                            "value": trigger["value"],
                            "reset_epoch": trigger.get("reset_epoch")}
        case = certificate.get("consumer_case")
        layout = (
            ("pin8_admission", "source_admission",
             {"admission_id": admission_id}),
            ("pin8_injection", "source_injection",
             {"action_id": state["admission"].action_id}),
            ("pin8_segment_applied", "gpio_input_segment_applied", {}),
            ("pin8_input_resource", "gpio_input_applied_resource", {}),
            ("pin8_sync0_sample", "gpio_input_sample", {"register": "sync0"}),
            ("pin8_sync1_sample", "gpio_input_sample", {"register": "sync1"}),
            ("gpio_b_native_irq_trigger", "gpio_irq_trigger",
             {"trigger_id": trigger_id, "mask": _IRQ_MASK,
              "value": trigger["value"],
              "reset_epoch": trigger.get("reset_epoch")}),
            ("gpio_b_native_irq_observation", "gpio_irq_observation",
             {"trigger_id": trigger_id, "mask": _IRQ_MASK}))
        attached = False
        for (hop_id, kind, fields), event_id in zip(layout, event_ids):
            attached = self._attach(state, hop_id, event_id, kind,
                                    component=_GPIO_B_DEVICE,
                                    observed_case=case, **fields) or attached
        return attached

    def _attach_cpu_irq(self, certificate: Mapping) -> bool:
        admission_id = certificate.get("admission_id")
        state = self._candidates.get(admission_id)
        if state is None or state["direction"] != IP_TO_CPU_TO_IP:
            return False
        trigger = state["trigger"]
        if (trigger is None
                or certificate.get("trigger_id") != trigger["trigger_id"]
                or certificate.get("trigger_event_id") != trigger["event_id"]):
            return False
        input_id = certificate.get("cpu_irq_input_event_id")
        taken_id = certificate.get("cpu_irq_taken_event_id")
        if (not _integer(input_id) or not _integer(taken_id)
                or taken_id <= input_id or taken_id <= trigger["event_id"]):
            return False
        case = certificate.get("consumer_case")
        attached = self._attach(state, "cpu_irq_input", input_id,
                                "cpu_irq_input", component=_CPU_DEVICE,
                                value=1,
                                source_event_id=certificate.get("source_event_id"),
                                observed_case=case)
        attached = self._attach(state, "cpu_irq_taken", taken_id,
                                "cpu_irq_taken", component=_CPU_DEVICE,
                                value=1,
                                source_event_id=certificate.get("source_event_id"),
                                step_event_id=certificate.get("cpu_step_event_id"),
                                observed_case=case) or attached
        state["take"] = {"event_id": taken_id, "input_event_id": input_id,
                         "step_event_id": certificate.get("cpu_step_event_id")}
        self._apply_buffered_serial(state)
        return attached

    # -------------------------------------------------- serial token witness

    def _drain_settled_serial(self) -> list:
        settled, self._settled_serial = self._settled_serial, []
        return settled

    def _serial_witness(self, certificate: Mapping) -> None:
        """Attribute one certified token by its exact CPU step identity."""
        if not isinstance(certificate, Mapping):
            return
        step = certificate.get("decision_producer_event_id")
        if not _integer(step) or step < 1:
            return
        for state in tuple(self._candidates.values()):
            take = state["take"]
            if (state["direction"] == IP_TO_CPU_TO_IP and take is not None
                    and take["step_event_id"] == step):
                self._apply_serial(state, certificate)
                return
        # No live admission owns this take yet. Retain the token under its exact
        # step identity; two different tokens claiming one step are retained as
        # a conflict, never silently collapsed onto the later one.
        entry = {"event_id": self._last_event_id, "step_event_id": step,
                 "certificate": dict(certificate)}
        previous = self._serial_witnesses.get(step)
        if previous is not None and self._serial_identity(
                previous["certificate"]) != self._serial_identity(certificate):
            entry["conflict"] = True
        self._store(self._serial_witnesses, step, entry)

    @staticmethod
    def _serial_identity(certificate: Mapping) -> tuple:
        return (certificate.get("decision_event_id"),
                certificate.get("retirement_event_id"),
                certificate.get("decision_serial"))

    def _apply_buffered_serial(self, state: dict) -> None:
        """Try a token that arrived before its admission's take hop was proven."""
        step = state["take"]["step_event_id"]
        if not _integer(step) or step < 1:
            return
        entry = self._serial_witnesses.pop(step, None)
        if entry is None:
            return
        if entry.get("conflict"):
            self._refuse_serial(state, "duplicate_serial_witness")
        else:
            self._apply_serial(state, entry["certificate"])

    def _apply_serial(self, state: dict, certificate: Mapping) -> None:
        """Attach or refuse one token that names this admission's exact take."""
        existing = state["hops"].get(CPU_IRQ_SERIAL_HOP)
        if existing is not None:
            witness = existing["evidence"]
            if (witness.get("decision_event_id") != certificate.get("decision_event_id")
                    or witness.get("retirement_event_id")
                    != certificate.get("retirement_event_id")
                    or witness.get("decision_serial")
                    != certificate.get("decision_serial")):
                self._refuse_serial(state, "duplicate_serial_witness")
            return
        fields, reason = self._serial_evidence(state, certificate)
        if reason is not None:
            self._refuse_serial(state, reason)
            return
        if not self._attach(state, CPU_IRQ_SERIAL_HOP,
                            certificate["retirement_event_id"],
                            "irq_serial_certificate", **fields):
            self._refuse_serial(state, "serial_witness_out_of_order")

    def _serial_evidence(self, state: dict, certificate: Mapping) -> tuple:
        """Exact corroboration of an attributable token; returns (fields, reason)."""
        if (certificate.get("schema_version") != _SERIAL_CERTIFICATE_SCHEMA
                or certificate.get("kind") != "irq_serial_certificate"
                or certificate.get("status") != "certified"):
            return None, "serial_token_not_certified"
        decision = certificate.get("decision_serial")
        retirement = certificate.get("retirement_serial")
        if not _integer(decision) or decision < 1 or retirement != decision:
            return None, "serial_token_not_certified"
        decision_event = certificate.get("decision_event_id")
        retirement_event = certificate.get("retirement_event_id")
        take_event = certificate.get("take_identity_event_id")
        if (not _integer(decision_event) or decision_event < 1
                or not _integer(retirement_event)
                or retirement_event <= decision_event
                or not _integer(take_event) or take_event < 1):
            return None, "serial_event_identity_incomplete"
        identity = certificate.get("take_identity")
        if not isinstance(identity, Mapping) or not identity:
            return None, "serial_take_identity_missing"
        if (certificate.get("component") != _CPU_DEVICE
                or certificate.get("proof_scope") != _SERIAL_PROOF_SCOPE):
            return None, "serial_scope_invalid"
        epoch = certificate.get("reset_epoch")
        execution = certificate.get("execution_id")
        trigger = state["trigger"]
        trigger_epoch = trigger.get("reset_epoch") if trigger is not None else None
        if (not _integer(epoch) or type(execution) is not str or not execution
                or not _integer(trigger_epoch)):
            return None, "serial_scope_invalid"
        if epoch != trigger_epoch:
            return None, "serial_reset_epoch_mismatch"
        if retirement_event <= state["take"]["event_id"]:
            return None, "serial_witness_out_of_order"
        return {
            "decision_serial": decision, "retirement_serial": retirement,
            "decision_event_id": decision_event,
            "decision_producer_event_id": certificate.get(
                "decision_producer_event_id"),
            "retirement_event_id": retirement_event,
            "retirement_producer_event_id": certificate.get(
                "retirement_producer_event_id"),
            "take_identity": {name: (list(value) if isinstance(value, list)
                                     else value)
                              for name, value in identity.items()},
            "take_identity_event_id": take_event,
            "take_identity_schema_version": certificate.get(
                "take_identity_schema_version"),
            "execution_id": execution, "reset_epoch": epoch,
            "component": _CPU_DEVICE,
            "event_gap": certificate.get("event_gap"),
            "scope": certificate.get("scope"),
            "proof_scope": _SERIAL_PROOF_SCOPE,
            "not_proof_of": list(certificate.get("not_proof_of") or ()),
            "irq_serial_observation_schema": certificate.get(
                "irq_serial_observation_schema"),
            "zero_semantics": certificate.get("zero_semantics"),
            "decision_phase": certificate.get("decision_phase"),
            "retirement_phase": certificate.get("retirement_phase"),
            "decision_sampling": certificate.get("decision_sampling"),
            "retirement_sampling": certificate.get("retirement_sampling"),
            "retirement_order": certificate.get("retirement_order"),
        }, None

    def _refuse_serial(self, state: dict, reason: str) -> None:
        """Fail closed: an attributable but unproven token ends the admission.

        A witness hop attached by an earlier token is withdrawn here: a
        conflicting duplicate contradicts the very evidence the hop would carry,
        so the settled certificate reports ``refused`` and never claims a
        witness. Credit is only ever removed, never restored.
        """
        state["serial_status"] = SERIAL_TOKEN_REFUSED
        state["serial_reason"] = reason
        state["hops"].pop(CPU_IRQ_SERIAL_HOP, None)
        self._complete.pop(state["admission"].admission_id, None)
        admission_id = state["admission"].admission_id
        if admission_id in self._candidates:
            self._settled_serial.append(
                self._settle(admission_id, "incomplete", self._last_event_id))


def declared_hop_sequence(direction: str) -> tuple[str, ...]:
    """Read-only copy of the declared hop order of one direction.

    Appended for read-only consumers (closed-loop feedback): it exposes the
    frozen hop contract that a certificate's ordered ``hops`` must be drawn
    from, without changing any certificate semantics. The optional
    ``cpu_irq_serial_token`` witness keeps its declared position between
    ``cpu_irq_taken`` and ``isr_padin_mmio_acceptance``, and the last entry of
    each sequence is that direction's terminal hop.
    """
    if direction == IP_TO_CPU_TO_IP:
        return _IP_SEQUENCE
    if direction == CPU_TO_IP_TO_CPU:
        return _CPU_HOPS
    raise ValueError("unknown chain certificate direction")


__all__ = ["ChainCertificates", "SCHEMA_VERSION", "IP_TO_CPU_TO_IP",
           "CPU_TO_IP_TO_CPU", "CPU_IRQ_SERIAL_HOP", "SERIAL_TOKEN_ABSENT",
           "SERIAL_TOKEN_WITNESSED", "SERIAL_TOKEN_REFUSED",
           "declared_hop_sequence"]
