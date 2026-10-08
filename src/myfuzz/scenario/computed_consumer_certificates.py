"""Generic consumer-endpoint certificates over a *declared* device-witness registry.

``computed_value_certificate.v1`` certifies one computed RV32I value from an RVFI
retirement, through MMIO store hops, to a device-internal consumption witness --
but its terminal endpoint is hard-wired to a handful of peripheral shapes.  This
module generalises the endpoint: the terminal is driven by
:data:`WITNESS_REGISTRY`, a declared table in which every witness kind states

* the event kind (or the raw-observation shape) that carries it,
* the field paths that carry the delivered value (a word field, a 32-entry
  per-bit list that is recomposed into a word, or a serialised lane byte),
* the exact identity keys it can join on, and
* whether it can join at all -- a kind that carries a value but no exact store
  identity is declared ``joinable=False`` with a reason, so an adjacency-only
  witness can never be promoted into a certificate.

A certificate is emitted only when *every* declared hop joins by exact identity.
Otherwise the settlement is written as an explicit refusal naming the first
missing hop and the first missing identity, e.g.
``device_consumption:uart_fifo_push`` / ``store_transaction_key``.  When the
device has no declared witness kind at all the settlement is ``unknown`` with a
reason and no hop claim -- never a fabricated 0.

The start and propagation hops are the ones the frozen traces were already
verified against: an RVFI ``cpu_retire`` whose ``rd_wdata`` is recomputed from
the instruction word and ``rs1_rdata`` (LUI/OP-IMM arithmetic and shifts with a
non-reserved funct7, ``rd != x0``), then MMIO store hops
(``mmio_acceptance``/``mmio_delivery``/``gpio_target_receipt`` anchors plus
``data_accept``/``data_response`` extensions) that carry the same bytes on the
same enabled lanes under one exact six-field ``TransactionKey``.

Every record -- certified, refused and unknown -- carries the mandatory
``proof_scope`` and ``not_proof_of``: this proves value identity along the
declared keys, not register-file provenance, not device-internal register/FIFO
provenance, not control-flow or cross-instruction dependence, and not the
correctness of the consuming logic.

Bounds are explicit and reported: ``max_pending`` live chains,
``max_event_gap`` events between consecutive hops, ``max_value_history``
remembered computed values and ``max_records`` retained refusal/unknown
samples.  Every eviction or skip is counted (``value_history_evicted``,
``chain_capacity_expired``, ``refusal_records_evicted``,
``unknown_records_evicted``, ``witness_join_failures``, ...).
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from myfuzz.scenario.computed_value_certificates import decode_computed_value


SCHEMA_VERSION = "computed_consumer_certificate.v1"
PROOF_SCOPE = ("exact_value_identity_on_enabled_lanes_from_rvfi_retirement_to_"
               "declared_device_witness")

#: A certificate, a refusal and an unknown record never claim any of these.
NOT_PROOF_OF = (
    "register_file_internal_source_token",
    "device_internal_register_or_fifo_provenance",
    "cross_instruction_data_dependency",
    "computed_value_was_used_by_a_later_instruction",
    "device_consuming_logic_correctness",
    "mmio_address_decode_or_route_ownership",
    "instruction_fetch_or_decode_identity",
    "per_bit_hardware_cone_of_influence",
)

# Declared join targets: each identity key names the pipeline fact it joins to.
JOIN_STORE_TRANSACTION = "store_transaction_key"
JOIN_ROUTED_DEVICE = "routed_device_component"
JOIN_STORE_OFFSET = "store_offset"
JOIN_STORE_BYTE_ENABLE = "store_byte_enable"
JOIN_UPSTREAM_HOP = "certified_upstream_hop_event_id"
JOIN_SERIAL_COUNTER = "serial_counter_increment"

#: Witness kinds whose own event is a device bus access hop.
DEVICE_ACCESS_HOP_KINDS = ("gpio_apb_access",)

_KEY_FIELDS = ("execution_id", "testcase_id", "source_component", "source_epoch",
               "channel_id", "source_sequence")
_TEXT_KEY_FIELDS = ("execution_id", "testcase_id", "source_component", "channel_id")
_INT_KEY_FIELDS = ("source_epoch", "source_sequence")

_RESET_KINDS = frozenset(("reset_barrier", "gpio_reset_resource", "cpu_reset"))
_ANCHOR_KINDS = frozenset(("mmio_acceptance", "mmio_delivery", "gpio_target_receipt"))
_EXTENSION_KINDS = frozenset(("data_accept", "data_response"))
_DEVICE_DELIVERY_KINDS = frozenset(("mmio_delivery", "gpio_target_receipt"))

#: Pipeline hop names used by refusal records ("the first missing hop").
HOP_RVFI_COMPUTE = "rvfi_compute"
HOP_MMIO_STORE_ROUTE = "mmio_store_route"
HOP_DEVICE_CONSUMPTION = "device_consumption"


# --------------------------------------------------------------------------
# declared witness registry
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ValuePath:
    """One declared field path that can carry the delivered value.

    ``kind`` declares the semantics of the resolved leaves:

    ``word``       a single 32-bit word;
    ``bit_list``   32 per-bit entries recomposed into a word (``bit_field``, when
                   declared, must confirm the bit index of every entry);
    ``lane_byte``  one byte that must equal the byte of the stored word on the
                   chain's lane (used by serialised transports).

    When ``identity_field`` is declared, every entry of a bit list must carry
    that field and it must equal the store transaction key: a per-bit identity
    join, not an adjacency join.
    """

    path: tuple[str, ...]
    kind: str = "word"
    identity_field: tuple[str, ...] | None = None
    bit_field: tuple[str, ...] | None = None
    note: str = ""


@dataclass(frozen=True)
class IdentityKey:
    """One exact identity key a witness kind declares it can join on."""

    name: str
    field_path: tuple[str, ...]
    join: str
    required: bool = True
    when: str = "always"
    note: str = ""


@dataclass(frozen=True)
class WitnessKind:
    """A declared device-internal witness shape."""

    name: str
    event_kind: str | None
    components: tuple[str, ...]
    value_paths: tuple[ValuePath, ...]
    identity_keys: tuple[IdentityKey, ...]
    carries_value: bool = True
    joinable: bool = True
    unjoinable_reason: str | None = None
    priority: int = 0
    shape: str = "event_kind"
    allowed_statuses: tuple[str, ...] = ()
    requires_paths: tuple[tuple[str, ...], ...] = ()
    bool_fields: tuple[tuple[tuple[str, ...], bool], ...] = ()
    error_field: tuple[str, ...] | None = None
    probe_expectations: tuple[tuple[str, object], ...] = ()
    observed_in_studied_artifacts: bool = True
    note: str = ""


@dataclass(frozen=True)
class AbsentWitnessKind:
    """A declared kind the studied artifacts do not carry (never a silent 0)."""

    name: str
    reason: str
    note: str = ""


def _value_fields(kind: WitnessKind) -> tuple[tuple[str, ...], ...]:
    return tuple(value.path for value in kind.value_paths)


#: The declared registry.  Order matters: the first declared kind for a device is
#: the hop a chain names when no witness event ever touched it.
WITNESS_REGISTRY: tuple[WitnessKind, ...] = (
    WitnessKind(
        name="gpio_register_commit",
        event_kind="gpio_register_commit",
        components=("gpio_a", "gpio_b"),
        value_paths=(
            ValuePath(("write_value",), note="full-word APB write value"),
            ValuePath(("post_value",), note="register value after the commit"),
            ValuePath(("bit_resources", "[]", "value"), kind="bit_list",
                      identity_field=("transaction",), bit_field=("bit",),
                      note="per-bit resource values, each keyed to the transaction"),
        ),
        identity_keys=(
            IdentityKey("store_transaction_key", ("fullkey",), JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("raw_offset",), JOIN_STORE_OFFSET,
                        note="decoded register offset of the committed write"),
            IdentityKey("certified_upstream_hop_event_id", ("observation_event_id",),
                        JOIN_UPSTREAM_HOP, required=False,
                        when="device_access_hop_present",
                        note="must name the certified device bus access hop"),
        ),
        allowed_statuses=("observed",),
        note="GPIO register committed from a real APB write; carries the full key",
        priority=40,
    ),
    WitnessKind(
        name="gpio_consumption_match",
        event_kind="gpio_consumption_match",
        components=("gpio_a", "gpio_b"),
        value_paths=(
            ValuePath(("proof_resource", "[]", "value"), kind="bit_list",
                      identity_field=("transaction",), bit_field=("bit",),
                      note="per-bit resources, each keyed to the transaction"),
        ),
        identity_keys=(
            IdentityKey("store_transaction_key", ("fullkey",), JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("raw_offset",), JOIN_STORE_OFFSET,
                        required=False, when="field_present",
                        note="this shape carries no offset field"),
        ),
        allowed_statuses=("accepted", "unknown"),
        note="device-side consumption match row; status accepted/unknown both mean "
             "the identity matched (rejected/incomplete never join), while origin "
             "lineage status is not part of this proof",
        priority=35,
    ),
    WitnessKind(
        name="gpio_apb_access",
        event_kind="gpio_apb_access",
        components=("gpio_a", "gpio_b"),
        value_paths=(ValuePath(("wdata",), note="APB write data"),),
        identity_keys=(
            IdentityKey("store_transaction_key", ("source_transaction",),
                        JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("raw_offset",), JOIN_STORE_OFFSET),
        ),
        allowed_statuses=("observed",),
        bool_fields=((("write",), True),),
        error_field=("target_response", "error"),
        probe_expectations=(("psel", 1), ("penable", 1), ("pwrite", 1),
                            ("pwdata", "$value"), ("pready", 1), ("pslverr", 0),
                            ("apb_addr", "$offset")),
        note="observed device bus access with the full APB probe set",
        priority=20,
    ),
    WitnessKind(
        name="gpio_register_read",
        event_kind="gpio_register_read",
        components=("gpio_a", "gpio_b"),
        value_paths=(
            ValuePath(("read_value",), note="value returned by the register read"),
            ValuePath(("post_value",), note="register value after the read"),
        ),
        identity_keys=(
            IdentityKey("store_transaction_key", ("fullkey",), JOIN_STORE_TRANSACTION,
                        note="this is the read access transaction, not the store"),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
        ),
        allowed_statuses=("observed",),
        note="register readback witness; the read key must equal the store key",
        priority=25,
    ),
    WitnessKind(
        name="uart_tick_observation_access",
        event_kind="uart_tick_observation",
        components=("uart",),
        value_paths=(ValuePath(("access", "delivery_context", "value"),
                               note="delivered value in the access context"),),
        identity_keys=(
            IdentityKey("store_transaction_key", ("access", "source_transaction"),
                        JOIN_STORE_TRANSACTION),
            IdentityKey("access_delivery_context_key",
                        ("access", "delivery_context", "source_transaction"),
                        JOIN_STORE_TRANSACTION,
                        note="the access context must repeat the same transaction"),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("access", "raw_offset"), JOIN_STORE_OFFSET),
            IdentityKey("store_byte_enable", ("access", "delivery_context", "be"),
                        JOIN_STORE_BYTE_ENABLE),
        ),
        requires_paths=(("access",),),
        bool_fields=((("access", "write"), True),),
        note="UART tick observation that carries a write access context",
        priority=30,
    ),
    WitnessKind(
        name="uart_serial_observation",
        event_kind=None,
        shape="raw_peripheral_observation",
        components=("uart",),
        value_paths=(ValuePath(("outputs", "serial_tx_last"), kind="lane_byte",
                               note="serialised byte of the addressed lane"),),
        identity_keys=(
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("serial_counter_increment", ("outputs", "serial_tx_count"),
                        JOIN_SERIAL_COUNTER, when="baseline_present",
                        note="must step exactly +1 from the baseline observed "
                             "before the delivery"),
        ),
        requires_paths=(("outputs",),),
        note="raw serial sample: carries no store transaction key, so it joins "
             "by device identity plus an observed +1 counter step on the lane byte",
        priority=50,
    ),
    WitnessKind(
        name="uart_rdata_access",
        event_kind="uart_rdata_access",
        components=("uart",),
        value_paths=(
            ValuePath(("read_value",), note="value returned to the CPU read"),
            ValuePath(("read_capture", "post", "probe_uart_fifo_data"),
                      note="physical FIFO data probe of the read"),
        ),
        identity_keys=(
            IdentityKey("store_transaction_key",
                        ("delivery_context", "source_transaction"),
                        JOIN_STORE_TRANSACTION,
                        note="this is the read access transaction, not the store"),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("raw_offset",), JOIN_STORE_OFFSET),
        ),
        note="UART data-register read access witness (read direction)",
        priority=22,
    ),
    WitnessKind(
        name="uart_fifo_pop",
        event_kind="uart_fifo_pop",
        components=("uart",),
        value_paths=(ValuePath(("value",), note="FIFO entry value popped"),),
        identity_keys=(
            IdentityKey("store_transaction_key", ("access", "source_transaction"),
                        JOIN_STORE_TRANSACTION,
                        note="pop carries the read access transaction only"),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("access", "raw_offset"), JOIN_STORE_OFFSET),
        ),
        note="device-internal FIFO entry pop; joins on the read access key",
        priority=15,
    ),
    WitnessKind(
        name="uart_fifo_push",
        event_kind="uart_fifo_push",
        components=("uart",),
        value_paths=(ValuePath(("value",), note="FIFO entry value pushed"),),
        identity_keys=(
            IdentityKey("store_transaction_key", ("source_transaction",),
                        JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
        ),
        joinable=False,
        unjoinable_reason=(
            "device_internal_fifo_entry_token_carries_no_store_transaction_key"),
        note="FIFO push names entry_id/frame_id only; no exact store join exists",
        priority=15,
    ),
    WitnessKind(
        name="gpio_pad_observation",
        event_kind=None,
        shape="raw_peripheral_observation",
        components=("gpio_a", "gpio_b"),
        value_paths=(
            ValuePath(("outputs", "gpio_out"), note="pad output word"),
            ValuePath(("outputs", "rdata"), note="register read data of the sample"),
        ),
        identity_keys=(
            IdentityKey("store_transaction_key", ("source_transaction",),
                        JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
        ),
        requires_paths=(("outputs",),),
        joinable=False,
        unjoinable_reason="raw_pad_sample_has_no_transaction_key_adjacency_only",
        note="raw pad sample: value only, no identity keys at all",
        priority=10,
    ),
    WitnessKind(
        name="spi_transfer",
        event_kind="spi_transfer",
        components=("spi0", "spi", "spi_host", "spi_device"),
        value_paths=(ValuePath(("value",), note="transferred word"),),
        identity_keys=(
            IdentityKey("store_transaction_key", ("source_transaction",),
                        JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("raw_offset",), JOIN_STORE_OFFSET),
        ),
        observed_in_studied_artifacts=False,
        note="declared SPI transfer endpoint; no producer in the studied artifacts",
        priority=30,
    ),
    WitnessKind(
        name="timer_tick",
        event_kind="timer_tick",
        components=("timer", "rv_timer", "timer_interrupt"),
        value_paths=(ValuePath(("value",), note="timer compare/tick value"),),
        identity_keys=(
            IdentityKey("store_transaction_key", ("source_transaction",),
                        JOIN_STORE_TRANSACTION),
            IdentityKey("routed_device_component", ("component",), JOIN_ROUTED_DEVICE),
            IdentityKey("store_offset", ("raw_offset",), JOIN_STORE_OFFSET),
        ),
        observed_in_studied_artifacts=False,
        note="declared timer endpoint; no producer in the studied artifacts",
        priority=30,
    ),
)

#: Declared kinds with no producer in the studied artifacts: a chain on such a
#: device is refused naming the kind, never credited with a fabricated 0.
ABSENT_WITNESS_KINDS: tuple[AbsentWitnessKind, ...] = tuple(
    AbsentWitnessKind(name=kind.name,
                      reason="declared_witness_kind_absent_from_artifact",
                      note=kind.note)
    for kind in WITNESS_REGISTRY if not kind.observed_in_studied_artifacts)


def declared_witness_names() -> tuple[str, ...]:
    return tuple(kind.name for kind in WITNESS_REGISTRY)


def witness_registry() -> dict[str, WitnessKind]:
    return {kind.name: kind for kind in WITNESS_REGISTRY}


def witness_kind_table() -> list[dict]:
    """The declared registry as plain JSON data (for reports and CLIs)."""
    table = []
    for kind in WITNESS_REGISTRY:
        table.append({
            "name": kind.name,
            "event_kind": kind.event_kind,
            "shape": kind.shape,
            "components": list(kind.components),
            "value_fields": [list(path) for path in _value_fields(kind)],
            "value_semantics": [value.kind for value in kind.value_paths],
            "identity_keys": [
                {"name": identity.name, "field_path": list(identity.field_path),
                 "join": identity.join, "required": identity.required,
                 "when": identity.when}
                for identity in kind.identity_keys],
            "carries_value": kind.carries_value,
            "joinable": kind.joinable,
            "unjoinable_reason": kind.unjoinable_reason,
            "priority": kind.priority,
            "allowed_statuses": list(kind.allowed_statuses),
            "observed_in_studied_artifacts": kind.observed_in_studied_artifacts,
            "note": kind.note,
            "proof_scope": PROOF_SCOPE,
            "not_proof_of": list(NOT_PROOF_OF),
        })
    return table


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _uint(value: object, bits: int) -> bool:
    return type(value) is int and 0 <= value < 1 << bits


def _flag(value: object) -> bool:
    return (type(value) is bool and value) or (type(value) is int and value == 1)


def _enabled_lanes(byte_enable: int) -> list[int]:
    return [lane for lane in range(4) if byte_enable >> lane & 1]


def _lane_bytes(value: int, lanes: Iterable[int]) -> dict[str, int]:
    return {str(lane): (value >> (8 * lane)) & 0xff for lane in lanes}


def _matches_lanes(observed: int, expected: int, lanes: Iterable[int]) -> bool:
    return all((observed >> (8 * lane)) & 0xff == (expected >> (8 * lane)) & 0xff
               for lane in lanes)


def _valid_key(key: object) -> bool:
    if not isinstance(key, Mapping) or set(key) != set(_KEY_FIELDS):
        return False
    if any(type(key[field]) is not str or not key[field].strip()
           for field in _TEXT_KEY_FIELDS):
        return False
    if key["channel_id"] != "data":
        return False
    return all(_uint(key[field], 64) for field in _INT_KEY_FIELDS)


def _key_tuple(key: Mapping) -> tuple:
    return tuple(key[field] for field in _KEY_FIELDS)


def _resolve(event: object, path: tuple[str, ...], index: int = 0) -> list:
    """Resolve a dotted field path; ``[]`` expands one list of mappings."""
    if index >= len(path):
        return [event]
    segment = path[index]
    if segment == "[]":
        if not isinstance(event, list):
            return []
        leaves: list = []
        for item in event:
            leaves.extend(_resolve(item, path, index + 1))
        return leaves
    if not isinstance(event, Mapping) or segment not in event:
        return []
    return _resolve(event[segment], path, index + 1)


def _single(event: object, path: tuple[str, ...]) -> object | None:
    leaves = _resolve(event, path)
    return leaves[0] if len(leaves) == 1 else None


def _list_elements(event: object, path: tuple[str, ...]) -> list | None:
    """Return the list expanded at the first ``[]`` segment, or ``None``."""
    for index, segment in enumerate(path):
        if segment != "[]":
            continue
        leaves = _resolve(event, path[:index])
        if len(leaves) == 1 and isinstance(leaves[0], list):
            return leaves[0]
        return None
    return None


def _bit_list_word(leaves: list) -> int | None:
    if len(leaves) != 32 or not all(_uint(leaf, 1) for leaf in leaves):
        return None
    return sum(leaf << bit for bit, leaf in enumerate(leaves))


def _event_key(event: Mapping, kind: str) -> object:
    if kind in _EXTENSION_KINDS:
        return event.get("transaction")
    return event.get("source_transaction")


# --------------------------------------------------------------------------
# consumer
# --------------------------------------------------------------------------


class ComputedConsumerCertificates:
    """Bounded, fail-closed consumer over the declared witness registry.

    ``ingest`` returns every record settled by that call and ``flush`` settles
    the rest.  Records are plain JSON-serialisable dicts whose ``status`` is
    ``certified``, ``refused`` or ``unknown``; every one carries the mandatory
    ``proof_scope`` and ``not_proof_of``.
    """

    def __init__(self, *, max_pending: int = 64, max_event_gap: int = 4096,
                 max_value_history: int = 256, max_records: int = 256,
                 max_serial_components: int = 64, max_witnesses: int = 8) -> None:
        for name, value in (("max_pending", max_pending),
                            ("max_event_gap", max_event_gap),
                            ("max_value_history", max_value_history),
                            ("max_records", max_records),
                            ("max_serial_components", max_serial_components),
                            ("max_witnesses", max_witnesses)):
            if type(value) is not int or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self.max_value_history = max_value_history
        self.max_records = max_records
        self.max_serial_components = max_serial_components
        self.max_witnesses = max_witnesses
        self._last_event_id: int | None = None
        self._values: OrderedDict[tuple, dict] = OrderedDict()
        self._chains: OrderedDict[tuple, dict] = OrderedDict()
        self._unmatched_stores: OrderedDict[tuple, None] = OrderedDict()
        self._serial: OrderedDict[str, dict] = OrderedDict()
        self._serial_previous: dict = {}
        self._evidence: dict[str, dict] = {}
        self._rejections: dict[str, int] = {}
        self._counters: dict[str, int] = {}
        self._refusal_by_hop: dict[str, int] = {}
        self._refusal_by_identity: dict[str, int] = {}
        self._unknown_by_reason: dict[str, int] = {}
        self._certificates: list[dict] = []
        self._refusals: list[dict] = []
        self._unknowns: list[dict] = []
        self._certified_count = 0
        self._refused_count = 0
        self._unknown_count = 0
        self._rvfi_retirements = 0

    # -- public evidence ----------------------------------------------------
    @property
    def certificates(self) -> tuple[dict, ...]:
        return tuple(self._certificates)

    @property
    def refusals(self) -> tuple[dict, ...]:
        return tuple(self._refusals)

    @property
    def unknowns(self) -> tuple[dict, ...]:
        return tuple(self._unknowns)

    @property
    def rejections(self) -> dict:
        return dict(self._rejections)

    @property
    def counters(self) -> dict:
        return dict(self._counters)

    @property
    def refusal_reasons(self) -> dict:
        return dict(self._refusal_by_hop)

    @property
    def refusal_identities(self) -> dict:
        return dict(self._refusal_by_identity)

    @property
    def unknown_reasons(self) -> dict:
        return dict(self._unknown_by_reason)

    def witness_evidence_row(self, name: str) -> dict:
        kind = witness_registry().get(name)
        if kind is None:
            raise KeyError(name)
        row = self._evidence_row(kind)
        return {"events": row["events"], "components": dict(row["components"]),
                "certified": row["certified"], "join_failures": row["join_failures"],
                "joined_by_key": dict(row["joined_by_key"]),
                "status_rejections": row["status_rejections"],
                "gate_rejections": row["gate_rejections"],
                "unjoinable_rejections": row["unjoinable_rejections"],
                "without_pending_chain": row["without_pending_chain"],
                "status": "observed" if row["events"] else "absent_from_artifact"}

    @property
    def witness_evidence(self) -> dict:
        return {kind.name: self.witness_evidence_row(kind.name)
                for kind in WITNESS_REGISTRY if kind.name in self._evidence}

    @property
    def pending_count(self) -> int:
        return len(self._chains)

    @property
    def computed_value_count(self) -> int:
        return len(self._values)

    @property
    def certified_count(self) -> int:
        return self._certified_count

    @property
    def refused_count(self) -> int:
        return self._refused_count

    @property
    def unknown_count(self) -> int:
        return self._unknown_count

    @property
    def rvfi_retirement_count(self) -> int:
        return self._rvfi_retirements

    def evidence_status(self) -> str:
        """``unknown`` when the stream carried no RVFI retirement at all."""
        return "ok" if self._rvfi_retirements else "unknown"

    def evidence_reason(self) -> str | None:
        return None if self._rvfi_retirements else "no_rvfi_retirement_events"

    def registry_table(self) -> list[dict]:
        return witness_kind_table()

    # -- bounded accounting -------------------------------------------------
    def _reject(self, reason: str) -> None:
        self._rejections[reason] = self._rejections.get(reason, 0) + 1

    def _count(self, name: str, amount: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + amount

    def _evidence_row(self, kind: WitnessKind) -> dict:
        row = self._evidence.get(kind.name)
        if row is None:
            row = {"events": 0, "components": {}, "certified": 0,
                   "join_failures": 0, "joined_by_key": {},
                   "status_rejections": 0, "gate_rejections": 0,
                   "unjoinable_rejections": 0, "without_pending_chain": 0}
            self._evidence[kind.name] = row
        return row

    # -- stream -------------------------------------------------------------
    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        records: list[dict] = []
        for event in events:
            records.extend(self._consume(event))
        return tuple(records)

    def flush(self) -> tuple[dict, ...]:
        records: list[dict] = []
        for key in list(self._chains):
            records.append(self._settle(key))
        for candidate in list(self._values.values()):
            if candidate.get("used"):
                continue
            records.append(self._refuse(
                reason="computed_value_never_reached_a_store",
                missing_hop=HOP_MMIO_STORE_ROUTE,
                missing_identity=JOIN_STORE_TRANSACTION,
                event_id=candidate["event_id"], transaction=None,
                device=None, computed=candidate))
        self._values.clear()
        return tuple(records)

    def _cancel_all(self, reason: str | None) -> None:
        self._chains.clear()
        self._values.clear()
        self._serial.clear()
        if reason:
            self._reject(reason)

    def _consume(self, event: object) -> tuple[dict, ...]:
        if not isinstance(event, Mapping) or not _uint(event.get("event_id"), 64) \
                or event["event_id"] < 1:
            self._cancel_all("malformed_event")
            self._last_event_id = None
            return ()
        event_id = event["event_id"]
        if self._last_event_id is not None:
            if event_id <= self._last_event_id:
                self._cancel_all("non_monotonic_event_id")
                return ()
            if event_id != self._last_event_id + 1:
                self._cancel_all("journal_gap")
        self._last_event_id = event_id

        kind = event.get("kind")
        if kind in _RESET_KINDS:
            self._cancel_all("reset_barrier_cancelled_pending"
                             if self._chains or self._values else None)
            return ()
        if kind == "cpu_retire":
            self._retire(event)
        elif kind in _ANCHOR_KINDS:
            return tuple(self._anchor(event) + self._expire(event_id))
        elif kind in _EXTENSION_KINDS:
            return tuple(self._extend(event) + self._expire(event_id))
        else:
            return tuple(self._witness_event(event) + self._expire(event_id))
        return tuple(self._expire(event_id))

    # -- start: a recomputed RVFI retirement --------------------------------
    def _retire(self, event: Mapping) -> None:
        self._rvfi_retirements += 1
        if event.get("trap") != 0:
            self._reject("retirement_trap_observation_only")
            return
        if "valid" in event and not _flag(event["valid"]):
            self._reject("invalid_retirement_valid")
            return
        if "phase" in event and event["phase"] != "post":
            self._reject("retirement_phase_not_post")
            return
        execution_id = event.get("execution_id")
        epoch = event.get("source_epoch")
        reset_epoch = event.get("reset_epoch")
        if epoch is None:
            epoch = reset_epoch
        if (type(execution_id) is not str or not execution_id.strip()
                or not _uint(epoch, 64)
                or (reset_epoch is not None and reset_epoch != epoch)
                or not _uint(event.get("insn"), 32)
                or not _uint(event.get("rd_addr"), 5)
                or not _uint(event.get("rd_wdata"), 32)
                or not _uint(event.get("rs1_addr"), 5)
                or not _uint(event.get("rs1_rdata"), 32)):
            self._reject("malformed_retirement_fields")
            return
        if (event["insn"] >> 7) & 31 == 0:
            self._reject("discarded_zero_register_write")
            return
        decoded = decode_computed_value(event["insn"], event["rs1_rdata"])
        if decoded is None:
            self._reject("unsupported_instruction_observation_only")
            return
        operation = decoded["operation"]
        rs1 = (event["insn"] >> 15) & 31
        if (event["rd_addr"] != (event["insn"] >> 7) & 31
                or (operation != "lui" and event["rs1_addr"] != rs1)
                or event["rd_wdata"] != decoded["computed_value"]):
            self._reject("illegal_computed_value")
            return
        candidate = {
            "hop_id": "cpu_compute", "kind": "cpu_retire",
            "event_id": event["event_id"], "order": event.get("order"),
            "pc": event.get("pc_rdata"), "insn": event["insn"],
            "operation": operation, "immediate": decoded["immediate"],
            "rd_addr": event["rd_addr"], "computed_value": event["rd_wdata"],
            "rs1_addr": event["rs1_addr"], "rs1_rdata": event["rs1_rdata"],
            "execution_id": execution_id, "epoch": epoch, "used": False,
        }
        self._values[(execution_id, epoch, event["event_id"])] = candidate
        self._count("computed_values_seen")
        while len(self._values) > self.max_value_history:
            self._values.popitem(last=False)
            self._count("value_history_evicted")

    # -- propagation: MMIO store hops under one TransactionKey --------------
    def _store_fields(self, event: Mapping, kind: str):
        if not _flag(event.get("write")):
            return None
        if kind == "data_response" and event.get("error") != 0:
            return None
        byte_enable = event.get("byte_enable", event.get("be"))
        value = event.get("write_value")
        if value is None:
            value = event.get("wdata")
        if not _uint(value, 32):
            return None
        if byte_enable is None:
            return (None, value) if kind == "gpio_target_receipt" else None
        if not _uint(byte_enable, 4) or byte_enable == 0:
            return None
        return byte_enable, value

    def _hop(self, event: Mapping, kind: str, key: Mapping, byte_enable: int,
             value: int) -> dict:
        return {"hop_id": kind, "kind": kind, "event_id": event["event_id"],
                "device_id": event.get("device_id", event.get("component")),
                "address": event.get("address"),
                "offset": event.get("offset", event.get("raw_offset")),
                "byte_enable": byte_enable, "value": value,
                "transaction": dict(key)}

    def _anchor(self, event: Mapping) -> list[dict]:
        kind = event["kind"]
        key = _event_key(event, kind)
        if not _valid_key(key):
            if _flag(event.get("write")):
                self._reject("malformed_transaction_key")
            return []
        fields = self._store_fields(event, kind)
        if fields is None:
            if _flag(event.get("write")):
                self._reject("malformed_hop_fields")
            return []
        byte_enable, value = fields
        chain = self._chains.get(_key_tuple(key))
        if chain is not None:
            return self._extend_chain(chain, event, kind, byte_enable, value)
        if byte_enable is None:
            return []
        return self._open_chain(event, kind, dict(key), byte_enable, value)

    def _open_chain(self, event: Mapping, kind: str, key: dict, byte_enable: int,
                    value: int) -> list[dict]:
        event_id = event["event_id"]
        lanes = _enabled_lanes(byte_enable)
        matches = [candidate for candidate in self._values.values()
                   if candidate["execution_id"] == key["execution_id"]
                   and candidate["epoch"] == key["source_epoch"]
                   and 0 < event_id - candidate["event_id"] <= self.max_event_gap
                   and _matches_lanes(value, candidate["computed_value"], lanes)]
        if not matches:
            key_tuple = _key_tuple(key)
            if key_tuple not in self._unmatched_stores:
                self._unmatched_stores[key_tuple] = None
                while len(self._unmatched_stores) > 4 * self.max_pending:
                    self._unmatched_stores.popitem(last=False)
                return [self._refuse(
                    reason="no_matching_computed_value_within_max_event_gap",
                    missing_hop=HOP_RVFI_COMPUTE,
                    missing_identity="computed_value_history",
                    event_id=event_id, transaction=key,
                    device=event.get("device_id"))]
            return []
        compute = matches[-1]
        compute["used"] = True
        reports: list[dict] = []
        while len(self._chains) >= self.max_pending:
            oldest = next(iter(self._chains))
            self._count("chain_capacity_expired")
            reports.append(self._settle(oldest))
        chain = {
            "key": key, "compute": compute,
            "compute_alternatives": [c["event_id"] for c in matches[:-1]],
            "byte_enable": byte_enable, "enabled_lanes": lanes,
            "lane_values": _lane_bytes(value, lanes), "store_value": value,
            "device": event.get("device_id", event.get("component")),
            "address": event.get("address"),
            "offset": event.get("offset", event.get("raw_offset")),
            "execution_id": key["execution_id"], "epoch": key["source_epoch"],
            "hops": [compute, self._hop(event, kind, key, byte_enable, value)],
            "last_event_id": event_id, "first_hop_event_id": event_id,
            "witness": None, "witnesses": [], "missing": None, "delivered": False,
            "serial_base": None, "serial_lane": (event.get("address") or 0) & 3,
            "device_access_hop_event_id": None,
        }
        self._chains[_key_tuple(key)] = chain
        self._count("chains_opened")
        if kind in _DEVICE_DELIVERY_KINDS:
            chain["delivered"] = True
            self._bind_serial(chain)
        return reports

    def _bind_serial(self, chain: dict) -> None:
        """Capture the serial counter baseline observed before the delivery.

        Without an observation before the delivery there is no baseline, so the
        chain is never serial-eligible: an assumed zero baseline could credit an
        unrelated byte.
        """
        device = chain["device"]
        if device is None or device == "cpu" or chain["serial_base"] is not None:
            return
        observed = self._serial.get(device)
        chain["serial_base"] = observed["count"] if observed else None

    def _extend(self, event: Mapping) -> list[dict]:
        kind = event["kind"]
        key = _event_key(event, kind)
        if not _valid_key(key):
            self._reject("malformed_transaction_key")
            return []
        chain = self._chains.get(_key_tuple(key))
        if chain is None:
            self._count("extension_without_chain")
            return []
        fields = self._store_fields(event, kind)
        if fields is None:
            if _flag(event.get("write")):
                self._reject("malformed_hop_fields")
            return []
        return self._extend_chain(chain, event, kind, *fields)

    def _extend_chain(self, chain: dict, event: Mapping, kind: str, byte_enable: int,
                      value: int) -> list[dict]:
        event_id = event["event_id"]
        key = chain["key"]
        if byte_enable is None:
            byte_enable = chain["byte_enable"]
        offset = event.get("offset", event.get("raw_offset"))
        address = event.get("aligned_address", event.get("address"))
        if ((offset is not None and chain["offset"] is not None
             and offset != chain["offset"])
                or (kind in _EXTENSION_KINDS and address is not None
                    and chain["address"] is not None and address != chain["address"])):
            return [self._drop_chain(chain, "hop_address_mismatch",
                                     missing_identity=JOIN_STORE_OFFSET)]
        if byte_enable != chain["byte_enable"]:
            return [self._drop_chain(chain, "hop_lane_mismatch",
                                     missing_identity=JOIN_STORE_BYTE_ENABLE)]
        if value != chain["store_value"]:
            return [self._drop_chain(chain, "hop_value_mismatch",
                                     missing_identity="store_enabled_lane_value")]
        if event_id <= chain["last_event_id"] or event_id - chain["last_event_id"] > \
                self.max_event_gap:
            return [self._drop_chain(chain, "hop_out_of_order",
                                     missing_identity="hop_event_id_order")]
        chain["hops"].append(self._hop(event, kind, key, byte_enable, value))
        chain["last_event_id"] = event_id
        if kind in _DEVICE_DELIVERY_KINDS:
            chain["delivered"] = True
            if chain["device"] in (None, "cpu"):
                chain["device"] = event.get("device_id", event.get("component"))
            chain["serial_lane"] = (event.get("address") or 0) & 3
            self._bind_serial(chain)
        if kind in DEVICE_ACCESS_HOP_KINDS:
            chain["device_access_hop_event_id"] = event_id
        self._count("mmio_hops")
        return []

    def _drop_chain(self, chain: dict, reason: str, *, missing_identity: str,
                    missing_hop: str = HOP_MMIO_STORE_ROUTE) -> dict:
        self._chains.pop(_key_tuple(chain["key"]), None)
        self._reject(reason)
        return self._refuse(reason=reason, missing_hop=missing_hop,
                            missing_identity=missing_identity,
                            event_id=chain["last_event_id"],
                            transaction=chain["key"], device=chain["device"],
                            computed=chain["compute"])

    # -- terminal: declared device-internal witnesses ------------------------
    def _witness_event(self, event: Mapping) -> list[dict]:
        records: list[dict] = []
        component = event.get("component")
        outputs = event.get("outputs")
        if event.get("kind") is None and isinstance(outputs, Mapping) \
                and "serial_tx_count" in outputs:
            self._note_serial(component, event)
        for kind in WITNESS_REGISTRY:
            if component not in kind.components:
                continue
            if not self._matches_shape(kind, event):
                continue
            row = self._evidence_row(kind)
            row["events"] += 1
            row["components"][component] = row["components"].get(component, 0) + 1
            records.extend(self._try_witness(kind, component, event))
        return records

    @staticmethod
    def _matches_shape(kind: WitnessKind, event: Mapping) -> bool:
        if kind.shape == "raw_peripheral_observation":
            if event.get("kind") is not None:
                return False
        elif event.get("kind") != kind.event_kind:
            return False
        return all(_resolve(event, path) for path in kind.requires_paths)

    def _chains_for(self, component: object) -> list[dict]:
        return [chain for chain in self._chains.values()
                if chain["device"] == component]

    def _note_missing(self, chain: dict, *, hop: str, identity: str,
                      reason: str) -> None:
        """Keep the first missing hop seen in stream order."""
        if chain["missing"] is None:
            chain["missing"] = {"hop": hop, "identity": identity, "reason": reason}

    def _try_witness(self, kind: WitnessKind, component: object,
                     event: Mapping) -> list[dict]:
        hop = f"{HOP_DEVICE_CONSUMPTION}:{kind.name}"
        chains = self._chains_for(component)
        if not chains:
            self._evidence_row(kind)["without_pending_chain"] += 1
            self._count("witness_events_without_pending_chain")
            return []
        records: list[dict] = []
        for chain in chains:
            if not kind.joinable:
                row = self._evidence_row(kind)
                row["unjoinable_rejections"] += 1
                self._count("witness_unjoinable_rejections")
                self._note_missing(chain, hop=hop,
                                   identity=kind.identity_keys[0].name,
                                   reason="declared_witness_cannot_join")
                continue
            if kind.allowed_statuses and \
                    event.get("status") not in kind.allowed_statuses:
                row = self._evidence_row(kind)
                row["status_rejections"] += 1
                self._count("witness_status_rejections")
                self._note_missing(
                    chain, hop=hop,
                    identity="witness_status:" + "/".join(kind.allowed_statuses),
                    reason="witness_status_not_allowed")
                continue
            gate = self._gate_failure(kind, event)
            if gate is not None:
                row = self._evidence_row(kind)
                row["gate_rejections"] += 1
                self._count("witness_gate_rejections")
                self._note_missing(chain, hop=hop, identity=gate,
                                   reason="witness_gate_field_mismatch")
                continue
            joined, conclusive = self._join_witness(kind, chain, event, hop)
            records.extend(joined)
            if conclusive and any(identity.join == JOIN_SERIAL_COUNTER
                                  for identity in kind.identity_keys):
                # Exactly one serial byte may ever be attributed to one store.
                chain["serial_base"] = None
        return records

    def _gate_failure(self, kind: WitnessKind, event: Mapping) -> str | None:
        for path, expected in kind.bool_fields:
            if not _flag(_single(event, path)) == bool(expected):
                return "gate_field:" + ".".join(path)
        if kind.error_field is not None:
            error = _single(event, kind.error_field)
            if error is not None and error != 0:
                return "error_field:" + ".".join(kind.error_field)
        if kind.probe_expectations:
            value = self._word_from_paths(kind, event)
            if value is None:
                return "value_field:" + ".".join(kind.value_paths[0].path)
            offset = None
            for identity in kind.identity_keys:
                if identity.join == JOIN_STORE_OFFSET:
                    offset = _single(event, identity.field_path)
                    break
            for name, expected in kind.probe_expectations:
                if expected == "$value":
                    expected = value
                elif expected == "$offset":
                    expected = offset
                if _single(event, ("pre", "gpio_probe_" + name)) != expected:
                    return "probe:gpio_probe_" + name
        return None

    def _word_from_paths(self, kind: WitnessKind, event: Mapping) -> int | None:
        for value_path in kind.value_paths:
            if value_path.kind == "bit_list":
                word = _bit_list_word(_resolve(event, value_path.path))
            elif value_path.kind == "lane_byte":
                word = None
            else:
                word = _single(event, value_path.path)
            if _uint(word, 32):
                return word
        return None

    def _join_witness(self, kind: WitnessKind, chain: dict, event: Mapping,
                      hop: str) -> tuple[list[dict], bool]:
        """Join one declared witness to one chain by exact identity, or note why not.

        Returns ``(records, conclusive)``.  ``conclusive=False`` means the event
        could not decide the join yet (a serial sample whose counter did not
        advance): nothing is recorded and the chain keeps its eligibility.
        Identity keys are evaluated before the value, so a foreign key is always
        reported as the missing identity even when the value also differs.  A
        joined witness is remembered on the chain but does not settle it: a
        stronger declared witness for the same chain may still arrive, and the
        settlement (expiry, capacity or ``flush``) emits one certificate that
        names the strongest joined witness.
        """
        event_id = event["event_id"]
        row = self._evidence_row(kind)
        joins: list[dict] = []
        for identity, observed, expected, status, reason in \
                self._eval_identities(kind, chain, event):
            if status == "deferred":
                return [], False
            joins.append({"name": identity.name, "join": identity.join,
                          "field_path": list(identity.field_path),
                          "observed": observed, "expected": expected,
                          "status": status, "note": identity.note})
            if status in ("mismatch", "absent"):
                row["join_failures"] += 1
                row["joined_by_key"][identity.name] = \
                    row["joined_by_key"].get(identity.name, 0) + 1
                self._count("witness_join_failures")
                self._note_missing(chain, hop=hop, identity=identity.name,
                                   reason=reason)
                return [], True
        value_ok, value_identity, value_reason, value_words = \
            self._check_witness_value(kind, chain, event)
        if not value_ok:
            row["join_failures"] += 1
            row["joined_by_key"][value_identity] = \
                row["joined_by_key"].get(value_identity, 0) + 1
            self._count("witness_join_failures")
            self._note_missing(chain, hop=hop, identity=value_identity,
                               reason=value_reason)
            if value_reason == "witness_value_mismatch":
                return [self._drop_chain(chain, value_reason,
                                         missing_identity=value_identity,
                                         missing_hop=hop)], True
            return [], True
        if event_id <= chain["last_event_id"] or \
                event_id - chain["last_event_id"] > self.max_event_gap:
            self._note_missing(chain, hop=hop, identity="hop_event_id_order",
                               reason="hop_out_of_order")
            return [], True
        chain["last_event_id"] = event_id
        witness = {"hop_id": HOP_DEVICE_CONSUMPTION, "kind": kind.name,
                   "event_id": event_id, "component": event.get("component"),
                   "local_tick": event.get("local_tick"),
                   "value": value_words[0][1] if value_words else None,
                   "identity_keys": [identity.name for identity in kind.identity_keys],
                   "joins": joins}
        if kind.name in DEVICE_ACCESS_HOP_KINDS:
            chain["device_access_hop_event_id"] = event_id
        chain["hops"].append(witness)
        chain["witnesses"].append(witness)
        while len(chain["witnesses"]) > self.max_witnesses:
            oldest = chain["witnesses"].pop(0)
            for index, joined in enumerate(chain["hops"]):
                if joined is oldest:
                    del chain["hops"][index]
                    break
            self._count("witness_history_evicted")
        chain["witness"] = self._strongest_witness(chain["witnesses"])
        row["certified"] += 1
        self._count("terminal_witnesses")
        return [], True

    @staticmethod
    def _strongest_witness(witnesses: list[dict]) -> dict:
        """Highest declared priority; on a tie the earliest event id wins."""
        registry = witness_registry()
        return max(witnesses, key=lambda witness: (
            registry[witness["kind"]].priority, -witness["event_id"]))

    def _check_witness_value(self, kind: WitnessKind, chain: dict,
                             event: Mapping):
        """Return ``(ok, identity, reason, [(path, word), ...])``."""
        words: list[tuple[tuple[str, ...], int]] = []
        lanes = chain["enabled_lanes"]
        for value_path in kind.value_paths:
            if value_path.kind == "bit_list":
                elements = _list_elements(event, value_path.path)
                if not elements:
                    continue
                if value_path.identity_field is not None:
                    field = value_path.identity_field[0]
                    for index, item in enumerate(elements):
                        if not isinstance(item, Mapping) or \
                                item.get(field) != chain["key"]:
                            return (False, "per_bit_transaction_key",
                                    "witness_identity_mismatch", words)
                        if value_path.bit_field is not None and \
                                item.get(value_path.bit_field[0]) != index:
                            return (False, "per_bit_identity_field",
                                    "witness_identity_mismatch", words)
                word = _bit_list_word(_resolve(event, value_path.path))
                if word is not None and not _matches_lanes(word, chain["store_value"],
                                                           lanes):
                    return (False, "store_enabled_lane_value",
                            "witness_value_mismatch", words)
            elif value_path.kind == "lane_byte":
                word = _single(event, value_path.path)
                lane = chain["serial_lane"]
                expected = (chain["store_value"] >> (8 * lane)) & 0xff
                if not _uint(word, 8):
                    continue
                if word != expected:
                    return (False, "store_enabled_lane_value",
                            "witness_value_mismatch", words)
            else:
                word = _single(event, value_path.path)
                if not _uint(word, 32):
                    continue
                if not _matches_lanes(word, chain["store_value"], lanes):
                    return (False, "store_enabled_lane_value",
                            "witness_value_mismatch", words)
            if word is not None:
                words.append((value_path.path, word))
        if not words:
            return (False, "value_field:" + ".".join(kind.value_paths[0].path),
                    "witness_value_not_carried", words)
        return (True, None, None, words)

    def _eval_identities(self, kind: WitnessKind, chain: dict, event: Mapping):
        for identity in kind.identity_keys:
            if identity.when == "device_access_hop_present" and \
                    chain["device_access_hop_event_id"] is None:
                yield (identity, None, chain["device_access_hop_event_id"],
                       "absent_by_declaration", "declared_absent_identity")
                continue
            if identity.when == "baseline_present" and chain["serial_base"] is None:
                yield (identity, None, None, "absent",
                       "no_observed_serial_baseline")
                continue
            observed = _single(event, identity.field_path)
            expected = self._expected_for(identity, chain)
            if identity.join == JOIN_SERIAL_COUNTER:
                base = chain["serial_base"]
                previous = self._serial_previous.get(chain["device"])
                lane_byte = chain["lane_values"].get(str(chain["serial_lane"]))
                if base is not None and _uint(observed, 64) and observed <= base:
                    # The transport has not emitted a new byte yet: this sample
                    # neither joins nor fails the chain, and it must not consume
                    # the one serial attribution a store may ever claim.
                    yield (identity, observed, base + 1, "deferred",
                           "serial_counter_not_advanced")
                    continue
                if (not _uint(observed, 64) or base is None
                        or observed != base + 1
                        or previous is None or previous.get("count") != base
                        or lane_byte is None):
                    yield (identity, observed,
                           None if base is None else base + 1, "mismatch",
                           "witness_identity_mismatch")
                    continue
                expected = base + 1
            if observed is None:
                if identity.required:
                    yield (identity, None, expected, "absent",
                           "witness_identity_absent")
                else:
                    yield (identity, None, expected, "absent_by_declaration",
                           "declared_absent_identity")
                continue
            if observed != expected:
                yield (identity, observed, expected, "mismatch",
                       "witness_identity_mismatch")
                continue
            yield (identity, observed, expected, "matched", None)

    @staticmethod
    def _expected_for(identity: IdentityKey, chain: dict):
        if identity.join == JOIN_STORE_TRANSACTION:
            return dict(chain["key"])
        if identity.join == JOIN_ROUTED_DEVICE:
            return chain["device"]
        if identity.join == JOIN_STORE_OFFSET:
            return chain["offset"]
        if identity.join == JOIN_STORE_BYTE_ENABLE:
            return chain["byte_enable"]
        if identity.join == JOIN_UPSTREAM_HOP:
            return chain["device_access_hop_event_id"]
        return None

    # -- settlement ---------------------------------------------------------
    def _expire(self, event_id: int) -> list[dict]:
        reports = []
        for key, chain in list(self._chains.items()):
            if event_id - chain["last_event_id"] > self.max_event_gap:
                self._count("chains_expired_by_event_gap")
                reports.append(self._settle(key))
        return reports

    def _first_declared_kind(self, device: object) -> WitnessKind | None:
        for kind in WITNESS_REGISTRY:
            if device in kind.components:
                return kind
        return None

    def _settle(self, key: tuple) -> dict:
        chain = self._chains.pop(key)
        if chain["witness"] is not None:
            return self._certificate(chain)
        missing = chain["missing"]
        if missing is None:
            kind = self._first_declared_kind(chain["device"])
            if kind is None:
                return self._unknown(
                    reason=f"no_declared_witness_kind_for_device:{chain['device']}",
                    event_id=chain["last_event_id"], transaction=chain["key"],
                    device=chain["device"], computed=chain["compute"])
            # The refusal always names the first declared endpoint of the device;
            # the reason distinguishes "the endpoint family did emit witnesses,
            # but none joined this chain" from "this artifact carries none of
            # the declared kinds at all".
            observed = any(self._evidence_row(candidate)["events"]
                           for candidate in WITNESS_REGISTRY
                           if chain["device"] in candidate.components)
            if observed:
                reason = "no_declared_device_witness_joined"
            else:
                reason = "declared_witness_kind_absent_from_artifact"
                self._count("refusals_naming_absent_witness_kind")
            return self._refuse(
                reason=reason,
                missing_hop=f"{HOP_DEVICE_CONSUMPTION}:{kind.name}",
                missing_identity=kind.identity_keys[0].name,
                event_id=chain["last_event_id"], transaction=chain["key"],
                device=chain["device"], computed=chain["compute"])
        return self._refuse(
            reason=missing["reason"], missing_hop=missing["hop"],
            missing_identity=missing["identity"],
            event_id=chain["last_event_id"], transaction=chain["key"],
            device=chain["device"], computed=chain["compute"])

    def _base_record(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, "proof_scope": PROOF_SCOPE,
                "not_proof_of": list(NOT_PROOF_OF)}

    def _certificate(self, chain: dict) -> dict:
        self._certified_count += 1
        certificate = self._base_record()
        certificate.update({
            "status": "certified",
            "reason": None,
            "missing_hop": None,
            "missing_identity": None,
            "witness_kind": chain["witness"]["kind"],
            "witness_event_id": chain["witness"]["event_id"],
            "device": chain["device"],
            "execution": {"execution_id": chain["execution_id"],
                          "testcase_id": chain["key"]["testcase_id"],
                          "source_epoch": chain["epoch"]},
            "transaction": dict(chain["key"]),
            "computed": dict(chain["compute"],
                             alternative_event_ids=list(chain["compute_alternatives"])),
            "enabled_lanes": list(chain["enabled_lanes"]),
            "lane_values": dict(chain["lane_values"]),
            "store_value": chain["store_value"],
            "identity_joins": self._identity_joins(chain),
            "witnesses": [dict(witness) for witness in chain["witnesses"]],
            "event_ids": [hop["event_id"] for hop in chain["hops"]],
            "hops": list(chain["hops"]),
            "event_gap": {
                "retirement_to_store": chain["first_hop_event_id"]
                - chain["compute"]["event_id"],
                "store_to_witness": chain["witness"]["event_id"]
                - chain["first_hop_event_id"],
            },
        })
        self._certificates.append(certificate)
        return certificate

    def _identity_joins(self, chain: dict) -> list[dict]:
        """The exact identity joins verified when the witness was accepted."""
        return [dict(join) for join in chain["witness"].get("joins", [])]

    def _refuse(self, *, reason: str, missing_hop: str, missing_identity: str,
                event_id: int, transaction: Mapping | None = None,
                device: object = None, computed: Mapping | None = None) -> dict:
        self._refused_count += 1
        self._refusal_by_hop[missing_hop] = self._refusal_by_hop.get(missing_hop, 0) + 1
        self._refusal_by_identity[missing_identity] = \
            self._refusal_by_identity.get(missing_identity, 0) + 1
        record = self._base_record()
        record.update({
            "status": "refused",
            "reason": reason,
            "missing_hop": missing_hop,
            "missing_identity": missing_identity,
            "device": device,
            "event_id": event_id,
            "transaction": None if transaction is None else dict(transaction),
            "computed": None if computed is None else dict(computed),
            "witness_kinds_seen": sorted(
                name for name, row in self._evidence.items() if row["events"]),
        })
        if len(self._refusals) < self.max_records:
            self._refusals.append(record)
        else:
            self._count("refusal_records_evicted")
        return record

    def _unknown(self, *, reason: str, event_id: int, transaction: Mapping | None,
                 device: object, computed: Mapping | None) -> dict:
        self._unknown_count += 1
        self._unknown_by_reason[reason] = self._unknown_by_reason.get(reason, 0) + 1
        record = self._base_record()
        record.update({
            "status": "unknown",
            "reason": reason,
            "missing_hop": None,
            "missing_identity": None,
            "device": device,
            "event_id": event_id,
            "transaction": None if transaction is None else dict(transaction),
            "computed": None if computed is None else dict(computed),
        })
        if len(self._unknowns) < self.max_records:
            self._unknowns.append(record)
        else:
            self._count("unknown_records_evicted")
        return record

    # -- serial bookkeeping --------------------------------------------------
    def _note_serial(self, component: object, event: Mapping) -> None:
        """Remember the sampling state *before* this raw sample is processed."""
        self._serial_previous = {component: self._serial.get(component)}
        outputs = event.get("outputs")
        if isinstance(outputs, Mapping):
            self._serial[component] = {"count": outputs.get("serial_tx_count"),
                                       "last": outputs.get("serial_tx_last"),
                                       "event_id": event["event_id"]}
            while len(self._serial) > self.max_serial_components:
                self._serial.popitem(last=False)
                self._count("serial_observations_evicted")
        self._count("serial_observations")
