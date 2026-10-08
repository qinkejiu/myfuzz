"""Incremental observations-only checks for the generated Ibex/PULP GPIO chain.

The checker consumes one ``OnlineCaseReceipt`` at a time.  It never treats a
missing stage as a DUT failure: every finding needs an accepted transaction and
the corresponding real RTL observation.  State is retained across online case
boundaries, just like the RTL sessions.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json

from .session_runtime import OnlineCaseReceipt


def _endpoint(value: object) -> tuple[str, str] | None:
    if (isinstance(value, (tuple, list)) and len(value) == 2
            and all(isinstance(item, str) for item in value)):
        return value[0], value[1]
    return None


def _word(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 0xffffffff else None


def _identity(value: object) -> tuple | None:
    if not isinstance(value, Mapping):
        return None
    fields = ("execution_id", "testcase_id", "source_component",
              "source_epoch", "channel_id", "source_sequence")
    result = tuple(value.get(field) for field in fields)
    if (any(item is None for item in result)
            or result[2] != "cpu" or result[4] != "data"
            or type(result[3]) is not int or type(result[5]) is not int):
        return None
    return result


def _canonical_event_bytes(event: Mapping) -> bytes:
    return json.dumps(dict(event), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _event_fingerprint(events) -> tuple[int, str]:
    """Hash a suffix in order without retaining or serializing it as one blob."""
    digest = hashlib.sha256()
    digest.update(b"[")
    count = 0
    for event in events:
        if not isinstance(event, Mapping):
            raise ValueError("online receipt contains a non-event")
        if count:
            digest.update(b",")
        digest.update(_canonical_event_bytes(event))
        count += 1
    digest.update(b"]")
    return count, digest.hexdigest()


class IbexPulpOnlineChecker:
    """Check only witnessed relationships in a continuous CPU/A/B session.

    ``result_address`` is the fixed bootstrap ISR's RAM result slot.  Set it
    to ``None`` for programs without the direct PADIN-to-RAM Store contract.
    The four-clock GPIO settle bound applies only after GPIO A output enable
    has been observed to cover the checked low byte.

    A PADIN response can be checked for any real CPU read. The fixed ISR's
    RAM result Store is checked only after the IRQ input, vector and handler
    fetches, the handler's PADIN read, and its Store instruction are observed.
    Instruction fetch alone is not treated as a DUT result.
    """

    _VECTORS = frozenset((0x10100, 0x1012c))
    _ISR_ENTRY = 0x10200
    _ISR_PADIN_LW = 0x10214
    _ISR_RESULT_SW = 0x1021c
    _ISR_MRET = 0x10240

    def __init__(self, *, result_address: int | None = 0x10000,
                 gpio_settle_ticks: int = 4) -> None:
        if (result_address is not None and (type(result_address) is not int
                                            or result_address < 0
                                            or result_address % 4)):
            raise ValueError("result_address must be a word-aligned address")
        if type(gpio_settle_ticks) is not int or gpio_settle_ticks < 1:
            raise ValueError("gpio_settle_ticks must be positive")
        self.result_address = result_address
        self.gpio_settle_ticks = gpio_settle_ticks
        self._last_event_id = 0
        self._case_results: dict[str, tuple[int, str, tuple[str, ...]]] = {}
        self._a_enable: int | None = None
        self._a_output: tuple[int, int, int | None] | None = None
        self._a_pending: tuple[int, int | None] | None = None  # low byte, first tick
        self._a_observed: dict[int, int] = {}
        self._b_bound_low: int | None = None
        self._b_irq: int | None = None
        self._b_sync: tuple[int, int] | None = None
        self._b_sync_since: int | None = None
        self._pulse_waiting_for_cpu = False
        self._irq_seen_by_cpu = False
        self._reads: dict[tuple, int] = {}
        self._isr_round = 0
        self._isr_phase = "outside"
        self._isr_read_fetch_seen = False
        self._isr_store_fetch_seen = False
        self._isr_mret_fetch_seen = False
        self._isr_read_key: tuple | None = None
        self._last_consumed: tuple[tuple, int, int] | None = None

    def __call__(self, receipt: OnlineCaseReceipt) -> tuple[str, ...]:
        if not isinstance(receipt, OnlineCaseReceipt):
            raise ValueError("OnlineCaseReceipt is required")
        prior = self._case_results.get(receipt.case_id)
        if prior is not None:
            count, digest = _event_fingerprint(receipt.events)
            if (count, digest) != prior[:2]:
                raise ValueError("case receipt identity reused with different events")
            return prior[2]
        findings: list[str] = []
        digest = hashlib.sha256()
        digest.update(b"[")
        count = 0
        for event in receipt.events:
            if not isinstance(event, Mapping):
                raise ValueError("online receipt contains a non-event")
            event_id = event.get("event_id")
            if type(event_id) is not int or event_id <= self._last_event_id:
                raise ValueError("online event IDs must strictly increase")
            if count:
                digest.update(b",")
            digest.update(_canonical_event_bytes(event))
            count += 1
            self._last_event_id = event_id
            self._observe(event, findings)
        digest.update(b"]")
        result = tuple(dict.fromkeys(findings))
        self._case_results[receipt.case_id] = (count, digest.hexdigest(), result)
        return result

    def _observe(self, event: Mapping, findings: list[str]) -> None:
        event_id = event["event_id"]
        kind = event.get("kind")
        component = event.get("component")
        outputs = event.get("outputs")
        if kind == "reset_barrier":
            self._a_pending = None
            self._a_enable = None
            self._a_output = None
            self._a_observed.clear()
            self._b_bound_low = None
            self._b_irq = None
            self._b_sync = None
            self._b_sync_since = None
            self._pulse_waiting_for_cpu = False
            self._irq_seen_by_cpu = False
            self._reads.clear()
            self._close_isr()
            return

        if component == "gpio_a" and isinstance(outputs, Mapping):
            value = _word(outputs.get("gpio_out"))
            tick = event.get("local_tick")
            if value is not None:
                self._a_observed[event_id] = value
                if len(self._a_observed) > 256:
                    self._a_observed.pop(next(iter(self._a_observed)))
                if type(tick) is int:
                    self._a_output = (value, tick, event.get("producer_event_id"))
                    self._check_a_output(value, tick, findings)

        if component == "gpio_b" and isinstance(outputs, Mapping):
            irq = outputs.get("irq", outputs.get("interrupt"))
            if irq in (0, 1) and type(irq) is int:
                self._b_irq = irq
            sync = _word(outputs.get("gpio_in_sync"))
            tick = event.get("local_tick")
            if sync is not None and type(tick) is int:
                if self._b_sync is None or self._b_sync[0] != sync:
                    self._b_sync_since = tick
                self._b_sync = (sync, tick)
            inputs = event.get("inputs")
            if (isinstance(inputs, Mapping) and self._b_bound_low is not None
                    and _word(inputs.get("gpio_in")) is not None
                    and inputs["gpio_in"] & 0xff != self._b_bound_low):
                findings.append("gpio_b_bound_input_mismatch")

        if component == "cpu" and isinstance(event.get("inputs"), Mapping):
            irq_input = event["inputs"].get("irq")
            if self._pulse_waiting_for_cpu and type(irq_input) is int:
                if irq_input & 1 != 1:
                    findings.append("cpu_irq_pulse_input_mismatch")
                else:
                    self._irq_seen_by_cpu = True
                self._pulse_waiting_for_cpu = False
            if isinstance(outputs, Mapping) and outputs.get("instr_req_accepted") == 1:
                address = _word(outputs.get("instr_addr"))
                if address is not None:
                    self._observe_cpu_fetch(address)
            if isinstance(outputs, Mapping) and outputs.get("data_rsp_consumed") == 1:
                epoch = outputs.get("data_rsp_source_epoch")
                sequence = outputs.get("data_rsp_source_sequence")
                if type(epoch) is int and type(sequence) is int:
                    candidates = [key for key in self._reads
                                  if key[3] == epoch and key[5] == sequence]
                    if len(candidates) == 1:
                        key = candidates[0]
                        actual = _word(outputs.get("data_rsp_rdata"))
                        if actual is not None and actual != self._reads[key]:
                            findings.append("cpu_gpio_b_padin_response_mismatch")
                        if (actual is not None and key == self._isr_read_key
                                and self._isr_phase == "handler"):
                            self._last_consumed = (key, self._reads[key], self._isr_round)
                        del self._reads[key]

        if kind == "mmio_delivery" and component == "cpu":
            device = event.get("device_id")
            offset = event.get("offset")
            if device == "gpio_a" and event.get("write") is True:
                write = _word(event.get("write_value"))
                if offset == 4 and write is not None and event.get("byte_enable") == 15:
                    self._a_enable = write
                    self._a_pending = None
                elif offset == 0x0c and write is not None and event.get("byte_enable") == 15:
                    # The target access may have sampled its output before the
                    # delivery event was appended. Use that real sample too.
                    if self._a_enable is not None and self._a_enable & 0xff == 0xff:
                        first_tick = (self._a_output[1]
                                      if self._a_output is not None
                                      and self._a_output[2] == event.get("producer_event_id")
                                      else None)
                        self._a_pending = (write & 0xff, first_tick)
                        if first_tick is not None and self._a_output is not None:
                            self._check_a_output(self._a_output[0],
                                                 self._a_output[1], findings)
                    else:
                        self._a_pending = None
            if device == "gpio_b" and offset == 8 and event.get("write") is False:
                read = _word(event.get("read_value"))
                key = _identity(event.get("source_transaction"))
                if read is not None and key is not None:
                    self._reads[key] = read
                    if (self._isr_phase == "handler" and self._isr_read_fetch_seen
                            and self._isr_read_key is None):
                        self._isr_read_key = key
                    if (self._isr_phase == "handler"
                            and self._b_sync is not None and self._b_sync_since is not None
                            and self._b_sync[1] - self._b_sync_since
                            >= self.gpio_settle_ticks
                            and read != self._b_sync[0]):
                        findings.append("gpio_b_padin_read_mismatch")

        if kind == "dataflow_delivery" and (
                _endpoint(event.get("source")) == ("gpio_a", "gpio_out")
                and _endpoint(event.get("target")) == ("gpio_b", "gpio_in")
                and event.get("source_bit_offset") == 0
                and event.get("target_bit_offset") == 0
                and event.get("width") == 8):
            value = _word(event.get("value"))
            producer = event.get("producer_event_id")
            real_output = self._a_observed.get(producer)
            if value is not None:
                if real_output is not None and value != real_output & 0xff:
                    findings.append("gpio_a_to_b_delivery_mismatch")
                self._b_bound_low = value

        if kind == "source_start" and (
                _endpoint(event.get("source")) == ("gpio_b", "irq")
                and _endpoint(event.get("target")) == ("cpu", "irq")
                and self._b_irq is not None and self._b_irq != 1):
            findings.append("gpio_b_irq_source_mismatch")
        if kind == "pulse_start" and (
                _endpoint(event.get("source")) == ("gpio_b", "irq")
                and _endpoint(event.get("target")) == ("cpu", "irq")):
            self._pulse_waiting_for_cpu = True
        if kind in ("pulse_cancel", "pulse_end"):
            self._pulse_waiting_for_cpu = False

        if (kind == "memory_write" and component == "cpu"
                and self.result_address is not None
                and event.get("address") == self.result_address
                and event.get("byte_enable") == 15
                and self._isr_phase == "handler"
                and self._isr_store_fetch_seen
                and self._last_consumed is not None):
            key, expected, round_id = self._last_consumed
            store_key = _identity(event.get("transaction"))
            value = _word(event.get("value"))
            if (round_id == self._isr_round and store_key is not None
                    and store_key[:5] == key[:5]
                    and store_key[5] > key[5] and value is not None):
                if value != expected:
                    findings.append("cpu_gpio_b_padin_store_mismatch")
                self._last_consumed = None

    def _close_isr(self) -> None:
        self._isr_phase = "outside"
        self._isr_read_fetch_seen = False
        self._isr_store_fetch_seen = False
        self._isr_mret_fetch_seen = False
        self._isr_read_key = None
        self._last_consumed = None
        self._irq_seen_by_cpu = False

    def _observe_cpu_fetch(self, address: int) -> None:
        """Use accepted real instruction fetches as a conservative ISR window."""
        if address in self._VECTORS:
            irq_seen = self._irq_seen_by_cpu
            self._close_isr()
            if not irq_seen:
                return
            self._isr_round += 1
            self._isr_phase = "vector"
            return
        if self._isr_phase == "vector":
            if address == self._ISR_ENTRY:
                self._isr_phase = "handler"
            return
        if self._isr_phase != "handler":
            return
        if address == self._ISR_PADIN_LW:
            self._isr_read_fetch_seen = True
        elif address == self._ISR_RESULT_SW:
            self._isr_store_fetch_seen = True
        elif address == self._ISR_MRET:
            self._isr_mret_fetch_seen = True
        elif self._isr_mret_fetch_seen and not self._ISR_ENTRY <= address <= self._ISR_MRET:
            self._close_isr()

    def _check_a_output(self, value: int, tick: int,
                        findings: list[str]) -> None:
        pending = self._a_pending
        if pending is None:
            return
        expected, first_tick = pending
        if value & 0xff == expected:
            self._a_pending = None
        elif first_tick is None:
            self._a_pending = (expected, tick)
        elif first_tick is not None and tick >= first_tick + self.gpio_settle_ticks:
            findings.append("gpio_a_padout_output_mismatch")
            self._a_pending = None
