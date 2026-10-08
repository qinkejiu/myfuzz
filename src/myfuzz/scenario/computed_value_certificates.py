"""Certificates tying one CPU-computed RV32I value to the value a device consumed.

The consumer is a bounded, incremental, fail-closed join over an ordered event
journal.  A certificate starts at a real RVFI retirement (``cpu_retire`` with
``trap == 0``) whose instruction is a supported LUI / OP-IMM arithmetic or
immediate encoding and whose ``rd_wdata`` is *recomputed* from the instruction
word and ``rs1_rdata``.  It then follows MMIO store hops that carry the same
bytes on the same enabled lanes under one exact ``TransactionKey`` and ends at a
device-internal consumption witness (a GPIO register commit row, an observed
GPIO APB access, a UART access observation, or a UART serial byte/count change).

Evidence limits are explicit.  The join proves *value identity on the enabled
lane bytes* between the computed retirement and the device consumption event; it
proves nothing about an internal register-file token, about a cross-instruction
data dependency, or about the computed register being the operand a later store
actually read.  Every certificate carries ``not_proof_of`` for exactly that
reason.

The stream must be contiguous.  Any gap in ``event_id`` (or a malformed event)
cancels every pending candidate, so no certificate can ever span an unobserved
interval; a reset barrier does the same.  Bounds: ``max_pending`` live chains,
``max_value_history`` remembered computed values, ``max_event_gap`` events
between consecutive hops, ``max_consumption_witnesses`` retained device
witnesses.

Join conditions, each of which must hold or the chain is dropped without a
certificate:

* start -- ``cpu_retire`` with ``trap == 0``, ``valid == 1`` (when present),
  ``phase == 'post'`` (when present), a supported LUI/OP-IMM word, ``rd != x0``,
  matching ``rd_addr``/``rs1_addr`` fields, and ``rd_wdata`` equal to the value
  recomputed from the word and ``rs1_rdata``;
* propagation -- an MMIO store hop (``mmio_acceptance``/``mmio_delivery``/
  ``gpio_target_receipt`` anchor, then ``data_accept``/``data_response``) whose
  exact six-field ``TransactionKey`` matches, whose byte enable equals the
  anchored one, whose value equals the anchored value on every enabled lane,
  whose address/offset matches, and whose event id strictly increases within
  ``max_event_gap``; the CPU scope (``execution_id``, ``source_epoch``) must
  equal the retirement's;
* terminal -- one device-internal witness under the same identity: a
  ``gpio_register_commit`` whose ``fullkey``, word value, per-bit values and
  per-bit transactions match and whose ``observation_event_id`` names the
  certified ``gpio_apb_access``; an ``gpio_apb_access`` with ``status ==
  'observed'`` and matching APB probes; a ``uart_tick_observation`` whose access
  context repeats the transaction and the written value; or the first UART
  serial observation after the delivery whose count advances by exactly one and
  whose byte equals the stored byte of the address lane.

Rejection keys (per event, except ``mmio_store_without_computed_value`` which is
counted once per store transaction): ``malformed_event``, ``journal_gap``,
``non_monotonic_event_id``, ``malformed_retirement_fields``,
``retirement_trap_observation_only``, ``invalid_retirement_valid``,
``retirement_phase_not_post``, ``unsupported_instruction_observation_only``,
``discarded_zero_register_write``, ``illegal_computed_value``,
``malformed_transaction_key``, ``malformed_hop_fields``, ``hop_lane_mismatch``,
``hop_value_mismatch``, ``hop_address_mismatch``, ``hop_out_of_order``,
``mmio_store_without_computed_value``, ``terminal_without_chain``,
``terminal_value_mismatch``, ``terminal_identity_mismatch``,
``uart_serial_observation_mismatch``, ``reset_barrier_cancelled_pending``,
``expired_without_device_consumption``.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping


SCHEMA_VERSION = "computed_value_certificate.v1"
PROOF_SCOPE = ("exact_value_identity_on_enabled_lanes_from_rvfi_compute_"
               "to_device_consumption")

#: A certificate never claims any of these.
NOT_PROOF_OF = (
    "register_file_internal_source_token",
    "cross_instruction_data_dependency",
    "computed_value_was_used_by_a_later_instruction",
    "mmio_address_decode_or_route_ownership",
    "device_internal_fifo_or_serializer_token",
    "instruction_fetch_or_decode_identity",
    "per_bit_hardware_cone_of_influence",
)

_KEY_FIELDS = ("execution_id", "testcase_id", "source_component", "source_epoch",
               "channel_id", "source_sequence")
_TEXT_KEY_FIELDS = ("execution_id", "testcase_id", "source_component", "channel_id")
_INT_KEY_FIELDS = ("source_epoch", "source_sequence")

#: Events that cancel every pending candidate: identity after them is new.
_RESET_KINDS = frozenset(("reset_barrier", "gpio_reset_resource", "cpu_reset"))

#: MMIO anchors carry the routed device and start a certificate chain.
_ANCHOR_KINDS = frozenset(("mmio_acceptance", "mmio_delivery", "gpio_target_receipt"))
#: CPU-side beats only ever extend an already anchored chain.
_EXTENSION_KINDS = frozenset(("data_accept", "data_response"))

_DEVICE_DELIVERY_KINDS = frozenset(("mmio_delivery", "gpio_target_receipt"))

#: Consumption witness strength; the strongest observed one is ``consumption``.
_WITNESS_PRIORITY = {
    "uart_serial_observation": 5,
    "gpio_register_commit": 4,
    "uart_tick_observation_access": 3,
    "gpio_apb_access": 2,
}


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _uint(value: object, bits: int) -> bool:
    return type(value) is int and 0 <= value < 1 << bits


def _flag(value: object) -> bool:
    """Accept the boolean and integer spellings the frozen traces both use."""
    return (type(value) is bool and value) or (type(value) is int and value == 1)


def _enabled_lanes(byte_enable: int) -> list[int]:
    return [lane for lane in range(4) if byte_enable >> lane & 1]


def _lane_bytes(value: int, lanes: Iterable[int]) -> dict[str, int]:
    return {str(lane): (value >> (8 * lane)) & 0xff for lane in lanes}


def _matches_lanes(store_value: int, computed_value: int, lanes: Iterable[int]) -> bool:
    return all((store_value >> (8 * lane)) & 0xff == (computed_value >> (8 * lane)) & 0xff
               for lane in lanes)


def _decode_encoding(insn: object) -> dict | None:
    """Decode one supported RV32I LUI / OP-IMM arithmetic word, or None.

    SLLI/SRLI/SRAI are OP-IMM forms whose operation comes from the reserved
    funct7 = insn[31:25]: exactly zero for SLLI/SRLI and exactly 0b0100000 for
    SRAI.  Any other funct7 leaves the word reserved and is never re-read as a
    wider shamt.  A word with rd == x0 discards its write: it is decoded here
    but is not a value (see :func:`decode_computed_value`).
    """
    if not _uint(insn, 32) or insn & 3 != 3:
        return None
    opcode, funct3 = insn & 0x7f, (insn >> 12) & 7
    rd = (insn >> 7) & 31
    if opcode == 0x37:
        return {"operation": "lui", "immediate": insn & 0xfffff000, "rd": rd}
    if opcode != 0x13:
        return None
    if funct3 in (0, 4, 6, 7):
        operation = {0: "addi", 4: "xori", 6: "ori", 7: "andi"}[funct3]
        return {"operation": operation, "immediate": _signed(insn >> 20, 12), "rd": rd}
    funct7 = insn >> 25
    if funct3 == 1 and funct7 == 0:
        return {"operation": "slli", "immediate": (insn >> 20) & 31, "rd": rd}
    if funct3 == 5 and funct7 in (0, 0b0100000):
        return {"operation": "srli" if funct7 == 0 else "srai",
                "immediate": (insn >> 20) & 31, "rd": rd}
    return None


def _apply(operation: str, immediate: int, rs1_rdata: int) -> int:
    if operation == "lui":
        return immediate & 0xffffffff
    if operation == "addi":
        return (rs1_rdata + immediate) & 0xffffffff
    if operation == "xori":
        return (rs1_rdata ^ immediate) & 0xffffffff
    if operation == "ori":
        return (rs1_rdata | immediate) & 0xffffffff
    if operation == "andi":
        return (rs1_rdata & immediate) & 0xffffffff
    if operation == "slli":
        return (rs1_rdata << immediate) & 0xffffffff
    if operation == "srli":
        return rs1_rdata >> immediate
    return (_signed(rs1_rdata, 32) >> immediate) & 0xffffffff


def decode_computed_value(insn: object, rs1_rdata: object = 0) -> dict | None:
    """Return the supported arithmetic/immediate result, or None.

    ``None`` means the encoding is unsupported or reserved, ``rs1_rdata`` is not
    a 32-bit value, or the destination is x0 (a discarded write is not a value a
    device can later consume).
    """
    decoded = _decode_encoding(insn)
    if decoded is None or decoded["rd"] == 0 or not _uint(rs1_rdata, 32):
        return None
    return {"operation": decoded["operation"], "immediate": decoded["immediate"],
            "computed_value": _apply(decoded["operation"], decoded["immediate"],
                                     rs1_rdata)}


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


def _event_key(event: Mapping, kind: str) -> object:
    if kind in _EXTENSION_KINDS:
        return event.get("transaction")
    return event.get("source_transaction")


class ComputedValueCertificates:
    """Bounded incremental consumer emitting ``computed_value_certificate.v1``.

    Certificates are emitted when a chain settles: it is expired by
    ``max_event_gap``, displaced by ``max_pending``, or ended by ``flush``.  A
    settled chain with a consumption witness is ``certified``; otherwise it is
    ``incomplete`` with the missing hop named.  Any contradiction (value, lane,
    transaction key, ordering, forged field) drops the chain and is counted in
    :attr:`rejections`; a dropped chain never yields a certificate.
    """

    def __init__(self, *, max_pending: int = 64, max_event_gap: int = 4096,
                 max_value_history: int = 256, max_consumption_witnesses: int = 8) -> None:
        for name, value in (("max_pending", max_pending),
                            ("max_event_gap", max_event_gap),
                            ("max_value_history", max_value_history),
                            ("max_consumption_witnesses", max_consumption_witnesses)):
            if type(value) is not int or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self.max_value_history = max_value_history
        self.max_consumption_witnesses = max_consumption_witnesses
        self._last_event_id: int | None = None
        self._values: OrderedDict[tuple, dict] = OrderedDict()
        self._chains: OrderedDict[tuple, dict] = OrderedDict()
        self._unmatched: OrderedDict[tuple, None] = OrderedDict()
        self._serial: dict[str, dict] = {}
        self._rejections: dict[str, int] = {}
        self._counters: dict[str, int] = {}
        self._certified_count = 0
        self._incomplete_count = 0

    # -- public evidence ----------------------------------------------------
    @property
    def rejections(self) -> dict:
        return dict(self._rejections)

    @property
    def counters(self) -> dict:
        return dict(self._counters)

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
    def incomplete_count(self) -> int:
        return self._incomplete_count

    # -- bounded accounting -------------------------------------------------
    def _reject(self, reason: str) -> None:
        self._rejections[reason] = self._rejections.get(reason, 0) + 1

    def _count(self, name: str, amount: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + amount

    # -- stream -------------------------------------------------------------
    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        certificates: list[dict] = []
        for event in events:
            certificates.extend(self._consume(event))
        return tuple(certificates)

    def flush(self) -> tuple[dict, ...]:
        certificates = [self._settle(key, "expired_without_device_consumption")
                        for key in list(self._chains)]
        return tuple(certificates)

    def _cancel_all(self, reason: str) -> None:
        for key in list(self._chains):
            del self._chains[key]
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
            reason = ("reset_barrier_cancelled_pending"
                      if self._chains or self._values else None)
            self._cancel_all(reason)
            return ()
        if kind == "cpu_retire":
            self._retire(event)
        elif kind in _ANCHOR_KINDS:
            return tuple(self._anchor(event))
        elif kind in _EXTENSION_KINDS:
            return tuple(self._extend(event))
        elif kind == "gpio_apb_access":
            return tuple(self._apb_access(event))
        elif kind == "gpio_register_commit":
            return tuple(self._register_commit(event))
        elif kind == "uart_tick_observation":
            return tuple(self._uart_access(event))
        elif self._is_serial_observation(event):
            return tuple(self._serial_observation(event))
        return tuple(self._expire(event_id))

    @staticmethod
    def _is_serial_observation(event: Mapping) -> bool:
        outputs = event.get("outputs")
        return (event.get("component") == "uart" and isinstance(outputs, Mapping)
                and _uint(outputs.get("serial_tx_count"), 64)
                and _uint(outputs.get("serial_tx_last"), 32))

    # -- start: a recomputed RVFI retirement --------------------------------
    def _retire(self, event: Mapping) -> None:
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
        decoded = _decode_encoding(event["insn"])
        if decoded is None:
            self._reject("unsupported_instruction_observation_only")
            return
        if decoded["rd"] == 0:
            self._reject("discarded_zero_register_write")
            return
        operation = decoded["operation"]
        rs1 = (event["insn"] >> 15) & 31
        rs1_rdata = 0 if operation == "lui" else event["rs1_rdata"]
        if (event["rd_addr"] != decoded["rd"]
                or (operation != "lui" and event["rs1_addr"] != rs1)
                or event["rd_wdata"] != _apply(operation, decoded["immediate"], rs1_rdata)):
            self._reject("illegal_computed_value")
            return
        value = event["rd_wdata"]
        candidate = {
            "hop_id": "cpu_compute", "kind": "cpu_retire", "event_id": event["event_id"],
            "order": event.get("order"), "pc": event.get("pc_rdata"), "insn": event["insn"],
            "operation": operation, "immediate": decoded["immediate"],
            "rd_addr": event["rd_addr"], "computed_value": value,
            "rs1_addr": event["rs1_addr"], "rs1_rdata": event["rs1_rdata"],
            "execution_id": execution_id, "epoch": epoch,
        }
        self._values[(execution_id, epoch, event["event_id"])] = candidate
        self._count("computed_values_seen")
        while len(self._values) > self.max_value_history:
            self._values.popitem(last=False)
            self._count("value_history_evicted")

    # -- propagation: MMIO store hops under one TransactionKey --------------
    def _store_fields(self, event: Mapping, kind: str):
        """Return (byte_enable, value) for one write hop, or None when not a write.

        ``gpio_target_receipt`` carries no byte enable: the device receipt is a
        full-word write, so it may only extend a chain whose lanes are known.
        """
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

    def _chain_for(self, event: Mapping, kind: str) -> dict | None:
        key = _event_key(event, kind)
        if not _valid_key(key):
            self._reject("malformed_transaction_key")
            return None
        chain = self._chains.get(_key_tuple(key))
        if chain is None or chain.get("key") != dict(key):
            return None
        return chain

    def _anchor(self, event: Mapping) -> list[dict]:
        kind, event_id = event["kind"], event["event_id"]
        key = _event_key(event, kind)
        if not _valid_key(key):
            self._reject("malformed_transaction_key")
            return self._expire(event_id)
        fields = self._store_fields(event, kind)
        if fields is None:
            # A read, an errored response, or a malformed beat is not a value hop.
            if _flag(event.get("write")):
                self._reject("malformed_hop_fields")
            return self._expire(event_id)
        byte_enable, value = fields
        chain = self._chains.get(_key_tuple(key))
        if chain is not None:
            return self._extend_chain(chain, event, kind, byte_enable, value)
        if byte_enable is None:
            # A device receipt without lane information can never start a chain.
            return self._expire(event_id)
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
            # Counted once per store transaction, not once per hop event.
            key_tuple = _key_tuple(key)
            if key_tuple not in self._unmatched:
                self._unmatched[key_tuple] = None
                while len(self._unmatched) > 4 * self.max_pending:
                    self._unmatched.popitem(last=False)
                self._reject("mmio_store_without_computed_value")
            return self._expire(event_id)
        compute = matches[-1]
        reports: list[dict] = []
        while len(self._chains) >= self.max_pending:
            oldest = next(iter(self._chains))
            self._count("chain_capacity_expired")
            reports.append(self._settle(oldest, "expired_without_device_consumption"))
        device = event.get("device_id", event.get("component"))
        hop = self._mmio_hop(event, kind, key, byte_enable, value)
        chain = {
            "key": key, "compute": compute,
            "compute_alternatives": [c["event_id"] for c in matches[:-1]],
            "byte_enable": byte_enable, "enabled_lanes": lanes,
            "lane_values": _lane_bytes(value, lanes), "store_value": value,
            "device": device, "address": event.get("address"),
            "offset": event.get("offset", event.get("raw_offset")),
            "epoch": key["source_epoch"], "execution_id": key["execution_id"],
            "hops": [compute, hop], "last_event_id": event_id,
            "first_hop_event_id": event_id, "witnesses": [], "consumption": None,
            "serial_base": None, "serial_lane": None, "delivered": False,
        }
        self._bind_device(chain)
        self._chains[_key_tuple(key)] = chain
        self._count("chains_opened")
        return reports + self._expire(event_id)

    def _bind_device(self, chain: dict) -> None:
        """Bind the routed device and, at delivery, the serial counter baseline.

        Without an observation before the delivery there is no baseline, so the
        chain is never serial-eligible: an assumed zero baseline could credit an
        unrelated byte.
        """
        device = chain["device"]
        if device is None or device == "cpu":
            return
        chain["serial_lane"] = (chain["address"] or 0) & 3
        if chain["delivered"] and chain["serial_base"] is None:
            observed = self._serial.get(device)
            chain["serial_base"] = observed["count"] if observed else None

    def _mmio_hop(self, event: Mapping, kind: str, key: dict, byte_enable: int,
                  value: int) -> dict:
        return {"hop_id": kind, "kind": kind, "event_id": event["event_id"],
                "device_id": event.get("device_id", event.get("component")),
                "address": event.get("address"),
                "offset": event.get("offset", event.get("raw_offset")),
                "byte_enable": byte_enable, "value": value,
                "transaction": dict(key)}

    def _extend(self, event: Mapping) -> list[dict]:
        kind, event_id = event["kind"], event["event_id"]
        chain = self._chain_for(event, kind)
        if chain is None:
            return self._expire(event_id)
        fields = self._store_fields(event, kind)
        if fields is None:
            if _flag(event.get("write")):
                self._reject("malformed_hop_fields")
            return self._expire(event_id)
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
            self._drop_chain(chain, "hop_address_mismatch")
            return self._expire(event_id)
        if byte_enable != chain["byte_enable"]:
            self._drop_chain(chain, "hop_lane_mismatch")
            return self._expire(event_id)
        if value != chain["store_value"]:
            self._drop_chain(chain, "hop_value_mismatch")
            return self._expire(event_id)
        if event_id <= chain["last_event_id"] or event_id - chain["last_event_id"] > \
                self.max_event_gap:
            self._drop_chain(chain, "hop_out_of_order")
            return self._expire(event_id)
        hop = self._mmio_hop(event, kind, key, byte_enable, value)
        chain["hops"].append(hop)
        chain["last_event_id"] = event_id
        if kind in _DEVICE_DELIVERY_KINDS:
            chain["delivered"] = True
            if chain["device"] in (None, "cpu"):
                chain["device"] = event.get("device_id", event.get("component"))
            self._bind_device(chain)
        self._count("mmio_hops")
        return self._expire(event_id)

    def _drop_chain(self, chain: dict, reason: str) -> None:
        self._chains.pop(_key_tuple(chain["key"]), None)
        self._reject(reason)

    # -- terminal: device-internal consumption ------------------------------
    def _witness(self, kind: str, event: Mapping, **observed) -> dict:
        hop = {"hop_id": "device_consumption", "kind": kind,
               "event_id": event["event_id"], "component": event.get("component"),
               "local_tick": event.get("local_tick")}
        hop.update(observed)
        return hop

    def _attach_witness(self, chain: dict, witness: dict) -> None:
        """Append one device witness, keeping both hop views bounded and equal."""
        chain["witnesses"].append(witness)
        chain["hops"].append(witness)
        while len(chain["witnesses"]) > self.max_consumption_witnesses:
            oldest = chain["witnesses"].pop(0)
            for index, hop in enumerate(chain["hops"]):
                if hop is oldest:
                    del chain["hops"][index]
                    break
        chain["consumption"] = (max(chain["witnesses"],
                                    key=lambda hop: _WITNESS_PRIORITY[hop["kind"]])
                                if chain["witnesses"] else None)

    def _apb_access(self, event: Mapping) -> list[dict]:
        kind, event_id = event["kind"], event["event_id"]
        if event.get("status") != "observed" or not _flag(event.get("write")):
            return self._expire(event_id)
        chain = self._chain_for(event, kind)
        if chain is None:
            if _valid_key(event.get("source_transaction")):
                self._reject("terminal_without_chain")
            return self._expire(event_id)
        value = event.get("wdata")
        offset = event.get("raw_offset")
        probes = event.get("pre")
        expected = {"psel": 1, "penable": 1, "pwrite": 1, "pwdata": value,
                    "pready": 1, "pslverr": 0, "apb_addr": offset}
        valid_probes = (isinstance(probes, Mapping)
                        and all(probes.get("gpio_probe_" + name) == probe
                                for name, probe in expected.items()))
        response = event.get("target_response")
        if (not _uint(value, 32) or not _uint(offset, 32)
                or not _matches_lanes(value, chain["store_value"], chain["enabled_lanes"])
                or offset != chain["offset"]):
            self._drop_chain(chain, "terminal_value_mismatch")
            return self._expire(event_id)
        if not valid_probes or (isinstance(response, Mapping) and response.get("error") != 0):
            self._drop_chain(chain, "terminal_identity_mismatch")
            return self._expire(event_id)
        if event_id <= chain["last_event_id"] or event_id - chain["last_event_id"] > \
                self.max_event_gap:
            self._drop_chain(chain, "hop_out_of_order")
            return self._expire(event_id)
        witness = self._witness(kind, event, offset=offset, wdata=value,
                                address=event.get("address"),
                                access_id=event.get("access_id"),
                                probes=dict(expected))
        chain["last_event_id"] = event_id
        self._attach_witness(chain, witness)
        self._count("terminal_witnesses")
        return self._expire(event_id)

    def _register_commit(self, event: Mapping) -> list[dict]:
        kind, event_id = event["kind"], event["event_id"]
        commit_key = event.get("fullkey")
        if not _valid_key(commit_key):
            self._reject("malformed_transaction_key")
            return self._expire(event_id)
        chain = self._chains.get(_key_tuple(commit_key))
        if chain is None or chain.get("key") != dict(commit_key):
            if event.get("status") == "observed":
                self._reject("terminal_without_chain")
            return self._expire(event_id)
        if event.get("status") != "observed":
            return self._expire(event_id)
        value = event.get("write_value")
        resources = event.get("bit_resources")
        bit_values = ({item.get("bit"): item for item in resources
                       if isinstance(item, Mapping)} if isinstance(resources, list) else {})
        enabled_bits = [bit for bit in range(32)
                        if (chain["byte_enable"] >> (bit // 8)) & 1]
        bits_value_valid = _uint(value, 32) and all(
            bit in bit_values and _uint(bit_values[bit].get("value"), 1)
            and bit_values[bit]["value"] == (value >> bit) & 1 for bit in enabled_bits)
        bits_identity_valid = _uint(value, 32) and all(
            bit in bit_values and bit_values[bit].get("transaction") == chain["key"]
            for bit in enabled_bits)
        if (not _uint(value, 32)
                or not _matches_lanes(value, chain["store_value"], chain["enabled_lanes"])
                or not bits_value_valid):
            self._drop_chain(chain, "terminal_value_mismatch")
            return self._expire(event_id)
        apb = next((hop for hop in chain["hops"]
                    if hop.get("kind") == "gpio_apb_access"), None)
        consistent = (event.get("observation_event_id") == apb["event_id"]
                      if apb is not None else True)
        if (not bits_identity_valid or not consistent
                or ("post_value" in event and event["post_value"] != value)
                or (all(_uint(event.get(name), 32)
                        for name in ("pre_value", "post_value", "changed_mask"))
                    and event["changed_mask"] != event["pre_value"] ^ event["post_value"])):
            self._drop_chain(chain, "terminal_identity_mismatch")
            return self._expire(event_id)
        if event_id <= chain["last_event_id"] or event_id - chain["last_event_id"] > \
                self.max_event_gap:
            self._drop_chain(chain, "hop_out_of_order")
            return self._expire(event_id)
        witness = self._witness(kind, event, register=event.get("register"),
                                offset=event.get("raw_offset"), write_value=value,
                                pre_value=event.get("pre_value"),
                                post_value=event.get("post_value"),
                                changed_mask=event.get("changed_mask"),
                                operation=event.get("operation"),
                                observation_event_id=event.get("observation_event_id"))
        chain["last_event_id"] = event_id
        self._attach_witness(chain, witness)
        self._count("terminal_witnesses")
        return self._expire(event_id)

    def _uart_access(self, event: Mapping) -> list[dict]:
        event_id = event["event_id"]
        access = event.get("access")
        if not isinstance(access, Mapping):
            return self._expire(event_id)
        context = access.get("delivery_context")
        key = context.get("source_transaction") if isinstance(context, Mapping) else None
        if not _valid_key(key):
            self._reject("malformed_transaction_key")
            return self._expire(event_id)
        if not _flag(context.get("write")) and not _flag(access.get("write")):
            return self._expire(event_id)
        chain = self._chains.get(_key_tuple(key))
        if chain is None or chain.get("key") != dict(key):
            self._reject("terminal_without_chain")
            return self._expire(event_id)
        value = context.get("value")
        offset = access.get("raw_offset")
        if (not _uint(value, 32) or not _uint(offset, 32)
                or not _matches_lanes(value, chain["store_value"], chain["enabled_lanes"])
                or offset != chain["offset"]):
            self._drop_chain(chain, "terminal_value_mismatch")
            return self._expire(event_id)
        if (event_id <= chain["last_event_id"]
                or event_id - chain["last_event_id"] > self.max_event_gap
                or not isinstance(access.get("source_transaction"), Mapping)
                or access["source_transaction"] != chain["key"]):
            self._drop_chain(chain, "terminal_identity_mismatch")
            return self._expire(event_id)
        witness = self._witness("uart_tick_observation_access", event,
                                offset=offset, wdata=value,
                                access_id=access.get("access_id"))
        chain["last_event_id"] = event_id
        self._attach_witness(chain, witness)
        self._count("terminal_witnesses")
        return self._expire(event_id)

    def _serial_observation(self, event: Mapping) -> list[dict]:
        event_id = event["event_id"]
        outputs = event["outputs"]
        count, byte = outputs["serial_tx_count"], outputs["serial_tx_last"]
        component = event["component"]
        previous = self._serial.get(component)
        self._serial[component] = {"count": count, "last": byte, "event_id": event_id}
        self._count("serial_observations")
        reports: list[dict] = []
        for chain in list(self._chains.values()):
            if chain["device"] != component or chain["serial_base"] is None:
                continue
            if event_id <= chain["last_event_id"]:
                continue
            base = chain["serial_base"]
            if count <= base:
                continue
            lane = chain["serial_lane"]
            expected = chain["lane_values"].get(str(lane))
            if (count == base + 1 and expected is not None and byte == expected
                    and previous is not None and previous["count"] == base
                    and event_id - chain["last_event_id"] <= self.max_event_gap):
                witness = self._witness("uart_serial_observation", event,
                                        serial_tx_count=count, serial_tx_last=byte,
                                        serial_base=base, lane=lane)
                chain["last_event_id"] = event_id
                self._attach_witness(chain, witness)
                self._count("terminal_witnesses")
            else:
                # The first serial byte after this store is not the stored lane
                # byte, so this chain can never claim a serial witness.  Its
                # already verified device witnesses stand.
                self._reject("uart_serial_observation_mismatch")
            # Exactly one serial byte may ever be attributed to one store.
            chain["serial_base"] = None
        reports.extend(self._expire(event_id))
        return reports

    # -- settlement ---------------------------------------------------------
    def _expire(self, event_id: int) -> list[dict]:
        reports = []
        for key, chain in list(self._chains.items()):
            if event_id - chain["last_event_id"] > self.max_event_gap:
                reports.append(self._settle(key, "expired_without_device_consumption"))
        return reports

    def _settle(self, key: tuple, reason: str) -> dict:
        chain = self._chains.pop(key)
        hops = chain["hops"]
        certified = chain["consumption"] is not None
        if certified:
            self._certified_count += 1
        else:
            self._incomplete_count += 1
            self._reject(reason)
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "certified" if certified else "incomplete",
            "reason": None if certified else reason,
            "missing_hops": [] if certified else ["device_consumption"],
            "proof_scope": PROOF_SCOPE,
            "not_proof_of": list(NOT_PROOF_OF),
            "execution": {"execution_id": chain["execution_id"],
                          "testcase_id": chain["key"]["testcase_id"],
                          "source_epoch": chain["epoch"]},
            "transaction": dict(chain["key"]),
            "device": chain["device"],
            "computed": dict(chain["compute"],
                             alternative_event_ids=list(chain["compute_alternatives"])),
            "enabled_lanes": list(chain["enabled_lanes"]),
            "lane_values": dict(chain["lane_values"]),
            "store_value": chain["store_value"],
            "event_ids": [hop["event_id"] for hop in hops],
            "hops": hops,
            "consumption": chain["consumption"],
            "consumption_witnesses": list(chain["witnesses"]),
            "event_gap": {
                "compute_to_store": chain["first_hop_event_id"] - chain["compute"]["event_id"],
                "store_to_last_hop": chain["last_event_id"] - chain["first_hop_event_id"],
            },
        }
