"""Unified P5 controlled fault family for calibrating the detection chain.

Boundary (read before use)
--------------------------
* A fault rewrites, duplicates or inserts events **only in the private copy that
  is handed to a checker**. The runner journal, the saved trace bytes, DUT state
  and every original event object stay untouched. Only the targeted event is
  deep-copied; all other events are shared by reference and never mutated.
* Every emitted finding is a calibration record
  (``calibration_only: true``). It must never be counted as a natural RTL
  defect, and it is reported separately from the unperturbed baseline findings.
* A fault is injected only after a real witnessed anchor was located, and the
  perturbation must make the declared **existing** checker invariant fire.  If
  the invariant is not reached, if the mutation would be a no-op, or if the
  unperturbed observation already reports the expected finding, the family
  raises instead of claiming a successful calibration.
* The family never addresses a DUT port, signal, pin or trace write.  A
  configuration that tries to is rejected (fail-closed).

Four classes are covered:

``wrong_irq``
    wrong IRQ evidence/bit/timing anchor (observed GPIO B IRQ level, CPU IRQ
    input bit; the witnessed source tick is a hard selection anchor).
``wrong_read_data``
    wrong read-back data (GPIO B PADIN response, GPIO B PADIN delivery read,
    UART RXDATA response).
``duplicate_submission``
    one delivery is submitted a second time (re-asserted IRQ pulse start, or a
    PADIN delivery replayed with a conflicting payload).
``broken_binding_value``
    the GPIO A -> B bound value is broken (delivery payload, observed GPIO B
    bound input byte).

Duplicate faults need one extra event in the checker input, so they insert one
synthetic copy and renumber the following ``event_id`` values (and their
``producer_event_id`` references) by that constant.  Payload values are never
touched by the renumbering, the shift is recorded in every finding, and the
unperturbed baseline chain keeps the original numbering.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace

from .ibex_pulp_online_checker import IbexPulpOnlineChecker
from .ibex_uart_online_checker import IbexUartOnlineChecker
from .session_runtime import OnlineCaseReceipt

FAULT_SCHEMA_VERSION = "p5_controlled_fault.v1"
FINDING_SCHEMA_VERSION = "p5_controlled_fault_finding.v1"
REPLAY_SCHEMA_VERSION = "p5_controlled_fault_replay.v1"
FAULT_KINDS = ("wrong_irq", "wrong_read_data", "duplicate_submission",
               "broken_binding_value")
CHECKER_NAMES = ("ibex_pulp_online", "ibex_uart_online")
_FINDING_PREFIX = "p5_controlled_fault"
_OBSERVATION_BOUNDARY = "checker_input_copy"

_CHECKER_FACTORIES: dict[str, Callable[[], object]] = {
    "ibex_pulp_online": IbexPulpOnlineChecker,
    "ibex_uart_online": IbexUartOnlineChecker,
}

#: Keys that would point a "fault" at the real DUT, its pins, or the raw trace.
#: They are rejected everywhere in a configuration, at any nesting depth.
_FORBIDDEN_KEYS = frozenset({
    "dut", "dut_port", "dut_write", "dut_signal", "dut_pin", "dut_target",
    "rtl", "rtl_write", "rtl_port", "rtl_signal", "rtl_pin",
    "hardware", "hardware_write", "hardware_port", "physical_write",
    "physical_port", "port_write", "write_port", "direct_write", "drive_port",
    "force", "forced", "force_value", "apply_to_dut", "write_to_dut",
    "device_write", "raw_trace_write", "trace_write", "journal_write",
    "override_trace", "gpio_force",
})


class ControlledFaultConfigError(ValueError):
    """A controlled fault configuration is not admissible."""


class ControlledFaultCalibrationError(RuntimeError):
    """A controlled fault could not reach its declared checker invariant."""


# --------------------------------------------------------------------------
# canonical helpers
# --------------------------------------------------------------------------

def _canonical_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_text(value).encode("utf-8")).hexdigest()


def _endpoint(value: object) -> tuple[str, str] | None:
    if (isinstance(value, (tuple, list)) and len(value) == 2
            and all(isinstance(item, str) for item in value)):
        return value[0], value[1]
    return None


def _integer(value: object) -> int | None:
    return value if type(value) is int else None


def _provenance(event: Mapping) -> Mapping:
    provenance = event.get("provenance")
    return provenance if isinstance(provenance, Mapping) else {}


def _source_admission_ids(events: Sequence[Mapping]) -> list[str]:
    ids = []
    for event in events:
        if event.get("kind") != "source_admission":
            continue
        admission = event.get("admission")
        if isinstance(admission, Mapping):
            admission_id = admission.get("admission_id")
            if isinstance(admission_id, str) and admission_id not in ids:
                ids.append(admission_id)
    return ids


def _pulp_identity(transaction: object) -> tuple | None:
    """Mirror ``IbexPulpOnlineChecker._identity`` for one delivery."""
    if not isinstance(transaction, Mapping):
        return None
    fields = ("execution_id", "testcase_id", "source_component",
              "source_epoch", "channel_id", "source_sequence")
    result = tuple(transaction.get(field) for field in fields)
    if (any(item is None for item in result) or result[2] != "cpu"
            or result[4] != "data" or type(result[3]) is not int
            or type(result[5]) is not int):
        return None
    return result


# --------------------------------------------------------------------------
# variant table
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _VariantSpec:
    kind: str
    variant: str
    checker: str
    expected_finding: str
    operation: str
    field: str
    selector_keys: tuple[str, ...]
    replacement: str           # "required" | "forbidden"
    irq_level: bool = False    # replacement must be 0 or 1
    maximum: int | None = None  # inclusive upper bound for int replacements
    bit_clear: bool = False    # replacement must keep bit 0 clear


_SPECS = (
    _VariantSpec("wrong_irq", "observation_irq_level", "ibex_pulp_online",
                 "gpio_b_irq_source_mismatch", "rewrite", "outputs.irq",
                 ("case_id", "source_start_event_id", "observation_event_id",
                  "source_tick", "original_value"), "required",
                 irq_level=True, maximum=1),
    _VariantSpec("wrong_irq", "cpu_irq_input_bit", "ibex_pulp_online",
                 "cpu_irq_pulse_input_mismatch", "rewrite", "inputs.irq",
                 ("case_id", "pulse_start_event_id", "cpu_event_id",
                  "local_tick", "original_value"), "required",
                 maximum=0xffffffff, bit_clear=True),
    _VariantSpec("wrong_read_data", "cpu_response_data", "ibex_pulp_online",
                 "cpu_gpio_b_padin_response_mismatch", "rewrite",
                 "outputs.data_rsp_rdata",
                 ("case_id", "read_event_id", "response_event_id",
                  "original_value"), "required", maximum=0xffffffff),
    _VariantSpec("wrong_read_data", "delivery_read_data", "ibex_pulp_online",
                 "cpu_gpio_b_padin_response_mismatch", "rewrite",
                 "read_value",
                 ("case_id", "read_event_id", "response_event_id",
                  "original_value"), "required", maximum=0xffffffff),
    _VariantSpec("wrong_read_data", "uart_cpu_response_data",
                 "ibex_uart_online", "cpu_uart_rxdata_response_mismatch",
                 "rewrite", "outputs.data_rsp_rdata",
                 ("case_id", "read_event_id", "response_event_id",
                  "original_value"), "required", maximum=0xffffffff),
    _VariantSpec("duplicate_submission", "irq_pulse_resubmission",
                 "ibex_pulp_online", "cpu_irq_pulse_input_mismatch",
                 "duplicate", "pulse_start",
                 ("case_id", "pulse_start_event_id", "insert_before_event_id",
                  "local_tick"), "forbidden"),
    _VariantSpec("duplicate_submission", "mmio_delivery_replay",
                 "ibex_pulp_online", "cpu_gpio_b_padin_response_mismatch",
                 "duplicate", "read_value",
                 ("case_id", "read_event_id", "insert_before_event_id",
                  "original_value"), "required", maximum=0xffffffff),
    _VariantSpec("broken_binding_value", "delivery_value",
                 "ibex_pulp_online", "gpio_a_to_b_delivery_mismatch",
                 "rewrite", "value",
                 ("case_id", "delivery_event_id", "producer_event_id",
                  "original_value"), "required", maximum=0xff),
    _VariantSpec("broken_binding_value", "bound_input_value",
                 "ibex_pulp_online", "gpio_b_bound_input_mismatch",
                 "rewrite", "inputs.gpio_in",
                 ("case_id", "delivery_event_id", "observation_event_id",
                  "original_value"), "required", maximum=0xff),
)

_VARIANTS: dict[tuple[str, str], _VariantSpec] = {
    (spec.kind, spec.variant): spec for spec in _SPECS}

_ENTRY_KEYS = ("kind", "variant", "checker", "expected_finding", "operation",
               "selector", "mutation")
_EVENT_ID_KEYS = frozenset((
    "source_start_event_id", "observation_event_id", "pulse_start_event_id",
    "cpu_event_id", "read_event_id", "response_event_id",
    "insert_before_event_id", "delivery_event_id", "producer_event_id",
))
_TICK_KEYS = frozenset(("source_tick", "local_tick"))


# --------------------------------------------------------------------------
# configuration validation
# --------------------------------------------------------------------------

def _reject_forbidden_keys(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ControlledFaultConfigError(
                    f"{path} contains a non-string key {key!r}")
            normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
            tokens = normalized.split("_")
            if (normalized in _FORBIDDEN_KEYS or "dut" in tokens
                    or normalized.startswith("dut_")
                    or normalized.endswith("_to_dut")):
                raise ControlledFaultConfigError(
                    "controlled faults must not address a real DUT, pin, "
                    f"hardware or trace write: {path}.{key}")
            _reject_forbidden_keys(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_forbidden_keys(item, f"{path}[{index}]")


def _require_keys(raw: Mapping, allowed: Sequence[str], label: str,
                  *, optional: Sequence[str] = ()) -> None:
    unknown = sorted(str(key) for key in set(raw) - set(allowed) - set(optional))
    if unknown:
        raise ControlledFaultConfigError(
            f"{label} has unknown keys: {', '.join(unknown)}")
    missing = sorted(str(key) for key in set(allowed) - set(raw))
    if missing:
        raise ControlledFaultConfigError(
            f"{label} is missing keys: {', '.join(missing)}")


def _validate_identifier(value: object, label: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ControlledFaultConfigError(
            f"{label} must be an integer in 0..{maximum}")
    return value


def _validate_selector(raw: object, spec: _VariantSpec, label: str) -> dict:
    if not isinstance(raw, Mapping):
        raise ControlledFaultConfigError(f"{label} must be an object")
    unknown = sorted(str(key) for key in set(raw) - set(spec.selector_keys))
    if unknown:
        raise ControlledFaultConfigError(
            f"{label} has unknown keys for {spec.variant}: {', '.join(unknown)}")
    selector: dict = {}
    for key in spec.selector_keys:
        if key not in raw:
            continue
        value = raw[key]
        if key == "case_id":
            if not isinstance(value, str) or not value:
                raise ControlledFaultConfigError(
                    f"{label}.case_id must be a non-empty string")
            selector[key] = value
            continue
        if key in _TICK_KEYS:
            if type(value) is not int or value < 0:
                raise ControlledFaultConfigError(
                    f"{label}.{key} must be a non-negative integer")
            selector[key] = value
            continue
        bound = 0xffffffff if key == "original_value" else 0xffffffff
        selector[key] = _validate_identifier(
            value, f"{label}.{key}", maximum=bound)
    if any(key != "case_id" for key in selector) and "case_id" not in selector:
        raise ControlledFaultConfigError(
            f"{label} must also pin case_id when an anchor is pinned")
    return {key: selector[key] for key in spec.selector_keys if key in selector}


def _validate_mutation(raw: object, spec: _VariantSpec, label: str) -> dict:
    if not isinstance(raw, Mapping):
        raise ControlledFaultConfigError(f"{label} must be an object")
    _require_keys(raw, ("field", "replacement"), label)
    field = raw["field"]
    if field != spec.field:
        raise ControlledFaultConfigError(
            f"{label}.field must be {spec.field!r} for {spec.variant}")
    replacement = raw["replacement"]
    if spec.replacement == "forbidden":
        if replacement is not None:
            raise ControlledFaultConfigError(
                f"{label}.replacement must be null for {spec.variant}")
        return {"field": field, "replacement": None}
    if type(replacement) is not int:
        raise ControlledFaultConfigError(
            f"{label}.replacement must be an integer for {spec.variant}")
    if spec.irq_level and replacement not in (0, 1):
        raise ControlledFaultConfigError(
            f"{label}.replacement must be 0 or 1 for {spec.variant}")
    if spec.maximum is not None and not 0 <= replacement <= spec.maximum:
        raise ControlledFaultConfigError(
            f"{label}.replacement must be in 0..{spec.maximum} "
            f"for {spec.variant}")
    if spec.bit_clear and replacement & 1:
        raise ControlledFaultConfigError(
            f"{label}.replacement must keep bit 0 clear for {spec.variant}")
    return {"field": field, "replacement": replacement}


def _validate_entry(raw: object, index: int) -> dict:
    label = f"faults[{index}]"
    if not isinstance(raw, Mapping):
        raise ControlledFaultConfigError(f"{label} must be an object")
    _require_keys(raw, _ENTRY_KEYS, label, optional=("fault_id",))
    kind = raw["kind"]
    if not isinstance(kind, str) or kind not in FAULT_KINDS:
        raise ControlledFaultConfigError(
            f"{label}.kind must be one of {', '.join(FAULT_KINDS)}")
    variant = raw["variant"]
    spec = _VARIANTS.get((kind, variant)) if isinstance(variant, str) else None
    if spec is None:
        known = sorted(name for name, _ in _VARIANTS if name == kind)
        raise ControlledFaultConfigError(
            f"{label}.variant must be one of {', '.join(known)} for {kind}")
    checker = raw["checker"]
    if checker != spec.checker:
        raise ControlledFaultConfigError(
            f"{label}.checker must be {spec.checker!r} for {spec.variant}")
    expected = raw["expected_finding"]
    if expected != spec.expected_finding:
        raise ControlledFaultConfigError(
            f"{label}.expected_finding must be {spec.expected_finding!r} "
            f"for {spec.variant}")
    operation = raw["operation"]
    if operation != spec.operation:
        raise ControlledFaultConfigError(
            f"{label}.operation must be {spec.operation!r} for {spec.variant}")
    selector = _validate_selector(raw["selector"], spec, f"{label}.selector")
    mutation = _validate_mutation(raw["mutation"], spec, f"{label}.mutation")
    entry = {"kind": kind, "variant": variant, "checker": checker,
             "expected_finding": expected, "operation": operation,
             "selector": selector, "mutation": mutation}
    entry["fault_id"] = _fault_id(entry)
    pinned = raw.get("fault_id")
    if pinned is not None:
        if not isinstance(pinned, str) or pinned != entry["fault_id"]:
            raise ControlledFaultConfigError(
                f"{label}.fault_id does not match the configured fault "
                f"identity {entry['fault_id']}")
    return entry


def _fault_id(entry: Mapping) -> str:
    identity = {key: entry[key] for key in _ENTRY_KEYS}
    digest = _canonical_sha256(identity)[:16]
    return f"{_FINDING_PREFIX}_{entry['kind']}_{digest}"


def validate_fault_document(document: object) -> dict:
    """Validate and canonicalize a ``p5_controlled_fault.v1`` document."""
    if not isinstance(document, Mapping):
        raise ControlledFaultConfigError("fault document must be an object")
    _reject_forbidden_keys(document, "fault document")
    _require_keys(document, ("schema_version", "faults"), "fault document")
    if document["schema_version"] != FAULT_SCHEMA_VERSION:
        raise ControlledFaultConfigError(
            f"fault document schema_version must be {FAULT_SCHEMA_VERSION!r}")
    faults = document["faults"]
    if not isinstance(faults, (list, tuple)) or not faults:
        raise ControlledFaultConfigError(
            "fault document faults must be a non-empty list")
    entries = [_validate_entry(raw, index) for index, raw in enumerate(faults)]
    if len({entry["fault_id"] for entry in entries}) != len(entries):
        raise ControlledFaultConfigError(
            "fault document repeats one configured fault identity")
    return {"schema_version": FAULT_SCHEMA_VERSION, "faults": entries}


# --------------------------------------------------------------------------
# observation helpers (all read-only)
# --------------------------------------------------------------------------

def _is_source_start(event: Mapping) -> bool:
    return (event.get("kind") == "source_start"
            and _endpoint(event.get("source")) == ("gpio_b", "irq")
            and _endpoint(event.get("target")) == ("cpu", "irq"))


def _is_pulse_start(event: Mapping) -> bool:
    return (event.get("kind") == "pulse_start"
            and _endpoint(event.get("source")) == ("gpio_b", "irq")
            and _endpoint(event.get("target")) == ("cpu", "irq"))


def _irq_level(event: Mapping) -> int | None:
    if event.get("component") != "gpio_b":
        return None
    outputs = event.get("outputs")
    if not isinstance(outputs, Mapping):
        return None
    values = [outputs[name] for name in ("irq", "interrupt") if name in outputs]
    if not values or any(type(value) is not int for value in values):
        return None
    if len(set(values)) != 1 or values[0] not in (0, 1):
        return None
    return values[0]


def _cpu_irq_input(event: Mapping) -> int | None:
    if event.get("component") != "cpu":
        return None
    inputs = event.get("inputs")
    if not isinstance(inputs, Mapping):
        return None
    return _integer(inputs.get("irq"))


def _gpio_b_padin_read(event: Mapping) -> tuple[int, dict, tuple] | None:
    if (event.get("kind") != "mmio_delivery" or event.get("component") != "cpu"
            or event.get("device_id") != "gpio_b" or event.get("offset") != 8
            or event.get("write") is not False):
        return None
    value = _integer(event.get("read_value"))
    key = _pulp_identity(event.get("source_transaction"))
    if value is None or key is None:
        return None
    return value, {"source_epoch": key[3], "source_sequence": key[5]}, key


def _uart_rxdata_read(event: Mapping) -> tuple[int, dict] | None:
    if (event.get("kind") != "mmio_delivery" or event.get("component") != "cpu"
            or event.get("device_id") != "uart" or event.get("offset") != 0x18
            or event.get("write") is not False):
        return None
    value = _integer(event.get("read_value"))
    transaction = event.get("source_transaction")
    if value is None or not isinstance(transaction, Mapping):
        return None
    epoch = _integer(transaction.get("source_epoch"))
    sequence = _integer(transaction.get("source_sequence"))
    if epoch is None or sequence is None:
        return None
    return value, {"source_epoch": epoch, "source_sequence": sequence}


def _cpu_response(event: Mapping, epoch: int, sequence: int,
                  *, kind_must_be_none: bool = False) -> int | None:
    if event.get("component") != "cpu":
        return None
    if kind_must_be_none and event.get("kind") is not None:
        return None
    outputs = event.get("outputs")
    if not isinstance(outputs, Mapping) or outputs.get("data_rsp_consumed") != 1:
        return None
    if (outputs.get("data_rsp_source_epoch") != epoch
            or outputs.get("data_rsp_source_sequence") != sequence):
        return None
    return _integer(outputs.get("data_rsp_rdata"))


def _is_a_to_b_delivery(event: Mapping) -> bool:
    return (event.get("kind") == "dataflow_delivery"
            and _endpoint(event.get("source")) == ("gpio_a", "gpio_out")
            and _endpoint(event.get("target")) == ("gpio_b", "gpio_in")
            and event.get("source_bit_offset") == 0
            and event.get("target_bit_offset") == 0
            and event.get("width") == 8)


def _gpio_a_output_low(event: Mapping) -> int | None:
    if event.get("component") != "gpio_a":
        return None
    outputs = event.get("outputs")
    if not isinstance(outputs, Mapping):
        return None
    value = _integer(outputs.get("gpio_out"))
    return None if value is None else value & 0xff


def _pulse_state(events: Sequence[Mapping], upto: int) -> tuple[int | None, int | None]:
    """Mirror the checker's pending-pulse state before ``events[upto]``."""
    pending: int | None = None
    consumed: int | None = None
    for index in range(upto):
        event = events[index]
        if _is_pulse_start(event):
            pending = index
            continue
        if event.get("kind") in ("pulse_cancel", "pulse_end"):
            pending = None
            continue
        irq = _cpu_irq_input(event)
        if irq is not None and pending is not None:
            if irq & 1:
                consumed = pending
            pending = None
    return pending, consumed


class _Search:
    """Read-only event search with strict (pinned) or witness (lax) failure."""

    def __init__(self, events: Sequence[Mapping], strict: bool) -> None:
        self.events = events
        self.strict = strict
        self.index_by_id: dict[int, int] = {}
        for index, event in enumerate(events):
            event_id = event.get("event_id")
            if type(event_id) is int:
                self.index_by_id.setdefault(event_id, index)

    def fail(self, message: str):
        if self.strict:
            raise ControlledFaultCalibrationError(message)
        return None

    def index_of(self, event_id: int, label: str) -> int | None:
        index = self.index_by_id.get(event_id)
        if index is None:
            return self.fail(
                f"pinned {label} {event_id} is not in this observation")
        return index


# --------------------------------------------------------------------------
# anchors: locate witnessed injection sites
# --------------------------------------------------------------------------

def _locate_irq_observation(search: _Search, selector: Mapping) -> dict | None:
    start_pin = selector.get("source_start_event_id")
    observation_pin = selector.get("observation_event_id")
    tick_pin = selector.get("source_tick")
    value_pin = selector.get("original_value")
    candidates = ([start_pin] if start_pin is not None else
                  [index for index, event in enumerate(search.events)
                   if _is_source_start(event)])
    for candidate in candidates:
        start_index = (search.index_of(candidate, "source_start_event_id")
                       if start_pin is not None else candidate)
        if start_index is None:
            return None
        start = search.events[start_index]
        if not _is_source_start(start):
            result = search.fail(
                f"pinned source_start event {candidate} is not a gpio_b.irq "
                "to cpu.irq source start")
            if result is None:
                continue
            return result
        tick = _integer(start.get("source_tick"))
        if tick is None:
            result = search.fail("witnessed source start has no integer source_tick")
            if result is None:
                continue
            return result
        if tick_pin is not None and tick_pin != tick:
            result = search.fail(
                f"pinned source_tick {tick_pin} differs from observed tick {tick}")
            if result is None:
                continue
            return result
        if observation_pin is not None:
            index = search.index_of(observation_pin, "observation_event_id")
            if index is None:
                return None
            if index >= start_index:
                result = search.fail(
                    "pinned gpio_b observation does not precede the source start")
                if result is None:
                    continue
                return result
            event = search.events[index]
            if (_irq_level(event) != 1
                    or event.get("local_tick") != tick):
                result = search.fail(
                    "pinned gpio_b observation does not witness irq=1 at the "
                    "source tick")
                if result is None:
                    continue
                return result
        else:
            index = next((position for position in range(start_index - 1, -1, -1)
                          if _irq_level(search.events[position]) == 1
                          and search.events[position].get("local_tick") == tick),
                         None)
            if index is None:
                continue
            event = search.events[index]
        if value_pin is not None and value_pin != 1:
            result = search.fail("pinned original_value is not the witnessed irq level")
            if result is None:
                continue
            return result
        provenance = _provenance(start)
        return {
            "mutation_index": index,
            "observation_event_id": event.get("event_id"),
            "selector_ids": {"source_start_event_id": start.get("event_id"),
                             "observation_event_id": event.get("event_id")},
            "related": {"source_start_event_id": start.get("event_id")},
            "provenance_index": start_index,
            "ticks": {"source_tick": tick},
            "original_value": 1,
            "transaction": None,
            "source_tick": tick,
            "origin_status": provenance.get("origin_status"),
            "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
            "insert_index": None,
        }
    return None


def _locate_cpu_irq_input(search: _Search, selector: Mapping) -> dict | None:
    """Find the watched CPU observation that consumes a pending IRQ pulse.

    The perturbation makes that observation claim "no IRQ" while the source
    still has a pending ``gpio_b.irq`` pulse, which is exactly the
    ``cpu_irq_pulse_input_mismatch`` contradiction.
    """
    pulse_pin = selector.get("pulse_start_event_id")
    cpu_pin = selector.get("cpu_event_id")
    tick_pin = selector.get("local_tick")
    value_pin = selector.get("original_value")
    if cpu_pin is not None:
        cpu_index = search.index_of(cpu_pin, "cpu_event_id")
        if cpu_index is None:
            return None
        candidates = [cpu_index]
    else:
        candidates = [index for index, event in enumerate(search.events)
                      if (_cpu_irq_input(event) is not None
                          and _cpu_irq_input(event) & 1)]
    for cpu_index in candidates:
        irq = _cpu_irq_input(search.events[cpu_index])
        if irq is None or not irq & 1:
            result = search.fail(
                "pinned cpu_event_id does not witness an asserted irq input")
            if result is None:
                continue
            return result
        pending, _consumed = _pulse_state(search.events, cpu_index)
        if pending is None:
            result = search.fail(
                "no pending gpio_b.irq pulse precedes the cpu event")
            if result is None:
                continue
            return result
        pulse_index = pending
        if pulse_pin is not None:
            pinned_index = search.index_of(pulse_pin, "pulse_start_event_id")
            if pinned_index is None:
                return None
            if pinned_index != pulse_index:
                result = search.fail(
                    "pinned pulse_start_event_id is not the pulse pending at "
                    "the cpu event")
                if result is None:
                    continue
                return result
        tick = _integer(search.events[cpu_index].get("local_tick"))
        if tick_pin is not None and tick_pin != tick:
            result = search.fail(
                f"pinned local_tick {tick_pin} differs from observed tick {tick}")
            if result is None:
                continue
            return result
        if value_pin is not None and value_pin != irq:
            result = search.fail(
                "pinned original_value is not the witnessed cpu irq input")
            if result is None:
                continue
            return result
        pulse = search.events[pulse_index]
        provenance = _provenance(pulse)
        return {
            "mutation_index": cpu_index,
            "observation_event_id": search.events[cpu_index].get("event_id"),
            "selector_ids": {"pulse_start_event_id": pulse.get("event_id"),
                             "cpu_event_id": search.events[cpu_index].get("event_id")},
            "related": {"pulse_start_event_id": pulse.get("event_id")},
            "provenance_index": pulse_index,
            "ticks": {"local_tick": tick} if tick is not None else {},
            "original_value": irq,
            "transaction": None,
            "source_tick": None,
            "origin_status": provenance.get("origin_status"),
            "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
            "insert_index": None,
        }
    return None


def _read_candidates(search: _Search, kind: str, selector: Mapping):
    pin = selector.get("read_event_id")
    matcher = _uart_rxdata_read if kind == "uart" else _gpio_b_padin_read
    if pin is not None:
        index = search.index_of(pin, "read_event_id")
        if index is None:
            return None
        result = matcher(search.events[index])
        if result is None:
            search.fail(f"pinned read_event_id {pin} is not a witnessed {kind} read")
            return None
        return [(index, result)]
    found = []
    for index, event in enumerate(search.events):
        result = matcher(event)
        if result is not None:
            found.append((index, result))
    return found


def _locate_read_response(search: _Search, selector: Mapping, *, kind: str,
                          response_key: str, require_kind_none: bool,
                          mutation_target: str) -> dict | None:
    value_pin = selector.get("original_value")
    response_pin = selector.get(response_key)
    candidates = _read_candidates(search, kind, selector)
    if candidates is None:
        return None
    for read_index, read in candidates:
        read_value, transaction, *_rest = read
        sequence = transaction["source_sequence"]
        epoch = transaction["source_epoch"]
        if response_pin is not None:
            response_index = search.index_of(response_pin, response_key)
            if response_index is None:
                return None
            if response_index <= read_index:
                result = search.fail(
                    f"pinned {response_key} does not follow the read event")
                if result is None:
                    continue
                return result
            rdata = _cpu_response(search.events[response_index], epoch, sequence,
                                  kind_must_be_none=require_kind_none)
            if rdata is None or rdata != read_value:
                result = search.fail(
                    f"pinned {response_key} does not consume the witnessed read")
                if result is None:
                    continue
                return result
        else:
            matches = [index for index in range(read_index + 1, len(search.events))
                       if _cpu_response(search.events[index], epoch, sequence,
                                        kind_must_be_none=require_kind_none)
                       is not None]
            if not matches:
                continue
            response_index = matches[0]
        consumed = [index for index in range(read_index + 1)
                    if _read_identity_index(search.events[index], kind)
                    == (epoch, sequence)]
        if len(consumed) != 1:
            result = search.fail(
                "pinned read identity is ambiguous in this observation")
            if result is None:
                continue
            return result
        if value_pin is not None and value_pin != read_value:
            result = search.fail(
                "pinned original_value is not the witnessed read value")
            if result is None:
                continue
            return result
        event = search.events[read_index]
        provenance = _provenance(event)
        mutation_index = (read_index if mutation_target == "read"
                          else response_index)
        related = ({"read_event_id": event.get("event_id")}
                   if mutation_target == "response"
                   else {response_key: search.events[response_index].get("event_id")})
        return {
            "mutation_index": mutation_index,
            "observation_event_id": search.events[mutation_index].get("event_id"),
            "selector_ids": {"read_event_id": event.get("event_id"),
                             response_key: search.events[response_index].get("event_id")},
            "related": related,
            "provenance_index": read_index,
            "ticks": {},
            "original_value": read_value,
            "transaction": dict(transaction),
            "source_tick": None,
            "origin_status": provenance.get("origin_status"),
            "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
            "insert_index": response_index if response_key == "insert_before_event_id" else None,
        }
    return None


def _read_identity_index(event: Mapping, kind: str) -> tuple[int, int] | None:
    matcher = _uart_rxdata_read if kind == "uart" else _gpio_b_padin_read
    result = matcher(event)
    if result is None:
        return None
    transaction = result[1]
    return transaction["source_epoch"], transaction["source_sequence"]


def _locate_pulse_resubmission(search: _Search, selector: Mapping) -> dict | None:
    pulse_pin = selector.get("pulse_start_event_id")
    insert_pin = selector.get("insert_before_event_id")
    tick_pin = selector.get("local_tick")
    if insert_pin is not None:
        insert_index = search.index_of(insert_pin, "insert_before_event_id")
        if insert_index is None:
            return None
        candidates = [insert_index]
    else:
        candidates = [index for index, event in enumerate(search.events)
                      if (_cpu_irq_input(event) is not None
                          and _cpu_irq_input(event) & 1 == 0)]
    for insert_index in candidates:
        irq = _cpu_irq_input(search.events[insert_index])
        if irq is None or irq & 1:
            result = search.fail(
                "pinned insert_before_event_id is not a cpu irq input with "
                "bit 0 clear")
            if result is None:
                continue
            return result
        pending, consumed = _pulse_state(search.events, insert_index)
        if pending is not None or consumed is None:
            result = search.fail(
                "no consumed gpio_b.irq pulse precedes the pinned cpu event")
            if result is None:
                continue
            return result
        if pulse_pin is not None:
            pulse_index = search.index_of(pulse_pin, "pulse_start_event_id")
            if pulse_index is None:
                return None
            if pulse_index != consumed or not _is_pulse_start(search.events[pulse_index]):
                result = search.fail(
                    "pinned pulse_start_event_id is not the pulse consumed "
                    "before the cpu event")
                if result is None:
                    continue
                return result
        else:
            pulse_index = consumed
        tick = _integer(search.events[insert_index].get("local_tick"))
        if tick_pin is not None and tick_pin != tick:
            result = search.fail(
                f"pinned local_tick {tick_pin} differs from observed tick {tick}")
            if result is None:
                continue
            return result
        pulse = search.events[pulse_index]
        provenance = _provenance(pulse)
        return {
            "mutation_index": pulse_index,
            "observation_event_id": pulse.get("event_id"),
            "selector_ids": {"pulse_start_event_id": pulse.get("event_id"),
                             "insert_before_event_id":
                                 search.events[insert_index].get("event_id")},
            "related": {"insert_before_event_id":
                            search.events[insert_index].get("event_id")},
            "provenance_index": pulse_index,
            "ticks": {"local_tick": tick} if tick is not None else {},
            "original_value": 1,
            "transaction": None,
            "source_tick": None,
            "origin_status": provenance.get("origin_status"),
            "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
            "insert_index": insert_index,
        }
    return None


def _locate_delivery_value(search: _Search, selector: Mapping) -> dict | None:
    delivery_pin = selector.get("delivery_event_id")
    producer_pin = selector.get("producer_event_id")
    value_pin = selector.get("original_value")
    if delivery_pin is not None:
        delivery_index = search.index_of(delivery_pin, "delivery_event_id")
        if delivery_index is None:
            return None
        candidates = [delivery_index]
    else:
        candidates = [index for index, event in enumerate(search.events)
                      if _is_a_to_b_delivery(event)]
    for delivery_index in candidates:
        event = search.events[delivery_index]
        value = _integer(event.get("value"))
        producer = _integer(event.get("producer_event_id"))
        if not _is_a_to_b_delivery(event) or value is None or producer is None:
            result = search.fail(
                "pinned delivery_event_id is not a wide gpio_a.gpio_out to "
                "gpio_b.gpio_in delivery")
            if result is None:
                continue
            return result
        if value_pin is not None and value_pin != value:
            result = search.fail(
                "pinned original_value is not the witnessed delivery value")
            if result is None:
                continue
            return result
        producer_index = search.index_by_id.get(producer)
        if producer_index is None or producer_index >= delivery_index:
            result = search.fail(
                "delivery producer observation does not precede the delivery")
            if result is None:
                continue
            return result
        real_output = _gpio_a_output_low(search.events[producer_index])
        if producer_pin is not None and producer_pin != producer:
            result = search.fail(
                "pinned producer_event_id is not the witnessed producer")
            if result is None:
                continue
            return result
        if real_output is None or real_output != value:
            result = search.fail(
                "delivery value does not match the observed gpio_a output")
            if result is None:
                continue
            return result
        provenance = _provenance(event)
        return {
            "mutation_index": delivery_index,
            "observation_event_id": event.get("event_id"),
            "selector_ids": {"delivery_event_id": event.get("event_id"),
                             "producer_event_id": producer},
            "related": {"producer_event_id": producer},
            "provenance_index": delivery_index,
            "ticks": {},
            "original_value": value,
            "transaction": None,
            "source_tick": None,
            "origin_status": provenance.get("origin_status"),
            "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
            "insert_index": None,
        }
    return None


def _locate_bound_input(search: _Search, selector: Mapping) -> dict | None:
    delivery_pin = selector.get("delivery_event_id")
    observation_pin = selector.get("observation_event_id")
    value_pin = selector.get("original_value")
    if delivery_pin is not None:
        delivery_index = search.index_of(delivery_pin, "delivery_event_id")
        if delivery_index is None:
            return None
        candidates = [delivery_index]
    else:
        candidates = [index for index, event in enumerate(search.events)
                      if _is_a_to_b_delivery(event)]
    for delivery_index in candidates:
        delivery = search.events[delivery_index]
        value = _integer(delivery.get("value"))
        if not _is_a_to_b_delivery(delivery) or value is None:
            result = search.fail(
                "pinned delivery_event_id is not a wide gpio_a.gpio_out to "
                "gpio_b.gpio_in delivery")
            if result is None:
                continue
            return result
        if value_pin is not None and value_pin != value:
            result = search.fail(
                "pinned original_value is not the witnessed delivery value")
            if result is None:
                continue
            return result
        if observation_pin is not None:
            observation_index = search.index_of(observation_pin,
                                                "observation_event_id")
            if observation_index is None:
                return None
            if observation_index <= delivery_index:
                result = search.fail(
                    "pinned gpio_b observation does not follow the delivery")
                if result is None:
                    continue
                return result
            index = observation_index
        else:
            index = next((position for position in range(delivery_index + 1,
                                                         len(search.events))
                          if _gpio_b_input_low(search.events[position]) == value),
                         None)
            if index is None:
                continue
        event = search.events[index]
        if _gpio_b_input_low(event) != value:
            result = search.fail(
                "pinned gpio_b observation does not show the bound value")
            if result is None:
                continue
            return result
        provenance = _provenance(event)
        return {
            "mutation_index": index,
            "observation_event_id": event.get("event_id"),
            "selector_ids": {"delivery_event_id": delivery.get("event_id"),
                             "observation_event_id": event.get("event_id")},
            "related": {"delivery_event_id": delivery.get("event_id")},
            "provenance_index": delivery_index,
            "ticks": {},
            "original_value": value,
            "transaction": None,
            "source_tick": None,
            "origin_status": provenance.get("origin_status"),
            "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
            "insert_index": None,
        }
    return None


def _gpio_b_input_low(event: Mapping) -> int | None:
    if event.get("component") != "gpio_b":
        return None
    inputs = event.get("inputs")
    if not isinstance(inputs, Mapping):
        return None
    value = _integer(inputs.get("gpio_in"))
    return None if value is None else value & 0xff


_LOCATORS: dict[tuple[str, str], Callable] = {
    ("wrong_irq", "observation_irq_level"): _locate_irq_observation,
    ("wrong_irq", "cpu_irq_input_bit"): _locate_cpu_irq_input,
    ("wrong_read_data", "cpu_response_data"):
        lambda search, selector: _locate_read_response(
            search, selector, kind="gpio_b", response_key="response_event_id",
            require_kind_none=False, mutation_target="response"),
    ("wrong_read_data", "delivery_read_data"):
        lambda search, selector: _locate_read_response(
            search, selector, kind="gpio_b", response_key="response_event_id",
            require_kind_none=False, mutation_target="read"),
    ("wrong_read_data", "uart_cpu_response_data"):
        lambda search, selector: _locate_read_response(
            search, selector, kind="uart", response_key="response_event_id",
            require_kind_none=True, mutation_target="response"),
    ("duplicate_submission", "irq_pulse_resubmission"): _locate_pulse_resubmission,
    ("duplicate_submission", "mmio_delivery_replay"):
        lambda search, selector: _locate_read_response(
            search, selector, kind="gpio_b",
            response_key="insert_before_event_id", require_kind_none=False,
            mutation_target="read"),
    ("broken_binding_value", "delivery_value"): _locate_delivery_value,
    ("broken_binding_value", "bound_input_value"): _locate_bound_input,
}


# --------------------------------------------------------------------------
# checker-input perturbation
# --------------------------------------------------------------------------

def _field_value(event: Mapping, field: str) -> int | None:
    if field == "outputs.irq":
        outputs = event.get("outputs")
        if not isinstance(outputs, Mapping):
            return None
        values = [outputs[name] for name in ("irq", "interrupt") if name in outputs]
        if not values or any(type(value) is not int for value in values):
            return None
        if len(set(values)) != 1:
            return None
        return values[0]
    if field == "inputs.irq":
        inputs = event.get("inputs")
        value = inputs.get("irq") if isinstance(inputs, Mapping) else None
        return _integer(value)
    if field == "inputs.gpio_in":
        inputs = event.get("inputs")
        value = inputs.get("gpio_in") if isinstance(inputs, Mapping) else None
        return None if type(value) is not int else value & 0xff
    if field == "outputs.data_rsp_rdata":
        outputs = event.get("outputs")
        value = outputs.get("data_rsp_rdata") if isinstance(outputs, Mapping) else None
        return _integer(value)
    if field in ("read_value", "value"):
        return _integer(event.get(field))
    raise ControlledFaultConfigError(f"unknown controlled fault field {field!r}")


def _write_field(event: dict, field: str, replacement: int) -> int:
    if field == "outputs.irq":
        outputs = event["outputs"]
        for name in ("irq", "interrupt"):
            if name in outputs:
                outputs[name] = replacement
        return replacement
    if field == "inputs.irq":
        event["inputs"]["irq"] = replacement
        return replacement
    if field == "inputs.gpio_in":
        full = event["inputs"]["gpio_in"]
        injected = (full & ~0xff) | (replacement & 0xff)
        event["inputs"]["gpio_in"] = injected
        return injected & 0xff
    if field == "outputs.data_rsp_rdata":
        event["outputs"]["data_rsp_rdata"] = replacement
        return replacement
    if field in ("read_value", "value"):
        event[field] = replacement
        return replacement
    raise ControlledFaultConfigError(f"unknown controlled fault field {field!r}")


def _shift_receipt(events: Sequence[Mapping], delta: int) -> list[dict]:
    """Renumber a receipt that follows an earlier duplicate injection."""
    shifted = []
    for event in events:
        event_id = event.get("event_id")
        if type(event_id) is not int:
            raise ValueError("controlled faults require integer event IDs")
        copied = dict(event)
        copied["event_id"] = event_id + delta
        producer = event.get("producer_event_id")
        if type(producer) is int:
            copied["producer_event_id"] = producer + delta
        shifted.append(copied)
    return shifted


def _inject_rewrite(events: list[dict], spec: _VariantSpec, anchor: Mapping,
                    replacement: int) -> tuple[list[dict], dict]:
    index = anchor["mutation_index"]
    event = copy.deepcopy(events[index])
    original = _field_value(event, spec.field)
    if original is None:
        raise ControlledFaultCalibrationError(
            f"witnessed event has no readable {spec.field} for {spec.variant}")
    injected = _write_field(event, spec.field, replacement)
    if injected == original:
        raise ControlledFaultCalibrationError(
            f"mutation would not change the observed {spec.field} value "
            f"({original}); refusing to claim a calibrated fault")
    perturbed = list(events)
    perturbed[index] = event
    return perturbed, {"original_value": original, "injected_value": injected,
                       "event_id_shift": 0, "duplicated_event_id": None,
                       "inserted_checker_input_event_id": None}


def _inject_duplicate(events: list[dict], spec: _VariantSpec, anchor: Mapping,
                      replacement: int | None) -> tuple[list[dict], dict]:
    source_index = anchor["mutation_index"]
    insert_index = anchor["insert_index"]
    if type(insert_index) is not int or insert_index < 1:
        raise ControlledFaultCalibrationError(
            "duplicate injection needs an event before the insertion point")
    previous_id = events[insert_index - 1].get("event_id")
    first_shifted = events[insert_index].get("event_id")
    if type(previous_id) is not int or type(first_shifted) is not int:
        raise ControlledFaultCalibrationError(
            "duplicate injection requires integer event IDs")
    duplicate = copy.deepcopy(events[source_index])
    original: int | None = None
    injected: int | None = None
    if replacement is None:
        # A pure re-submission changes the claim count, not a payload byte.
        original, injected = 1, 2
    else:
        original = _field_value(duplicate, spec.field)
        if original is None:
            raise ControlledFaultCalibrationError(
                f"witnessed event has no readable {spec.field} for {spec.variant}")
        injected = _write_field(duplicate, spec.field, replacement)
        if injected == original:
            raise ControlledFaultCalibrationError(
                f"duplicate payload would not change the observed {spec.field} "
                "value; refusing to claim a calibrated fault")
    inserted_id = previous_id + 1
    duplicate["event_id"] = inserted_id
    tail = []
    for event in events[insert_index:]:
        copied = dict(event)
        copied["event_id"] = event["event_id"] + 1
        producer = event.get("producer_event_id")
        if type(producer) is int and producer >= first_shifted:
            copied["producer_event_id"] = producer + 1
        tail.append(copied)
    perturbed = list(events[:insert_index]) + [duplicate] + tail
    return perturbed, {"original_value": original, "injected_value": injected,
                       "event_id_shift": 1,
                       "duplicated_event_id": events[source_index].get("event_id"),
                       "inserted_checker_input_event_id": inserted_id}


def _chain_record(entry: Mapping, anchor: Mapping, mutation: Mapping,
                  case_id: str, events: Sequence[Mapping],
                  shift_before: int) -> dict:
    spec = _VARIANTS[(entry["kind"], entry["variant"])]
    selector_ids = {key: value - shift_before
                    for key, value in anchor["selector_ids"].items()}
    observation_id = anchor["observation_event_id"]
    observation_id = (None if observation_id is None
                      else observation_id - shift_before)
    related = {key: value - shift_before
               for key, value in anchor["related"].items()}
    mutation_index = anchor["mutation_index"]
    event = events[mutation_index] if mutation_index < len(events) else {}
    provenance = _provenance(events[anchor.get("provenance_index", mutation_index)])
    selector = {"case_id": case_id}
    selector.update(selector_ids)
    selector.update(anchor["ticks"])
    if spec.replacement == "required" and anchor.get("original_value") is not None:
        selector["original_value"] = anchor["original_value"]
    chain = {
        "case_id": case_id,
        "observation_event_id": observation_id,
        "observation_event_kind": event.get("kind"),
        "observation_component": event.get("component"),
        "observed_local_tick": event.get("local_tick"),
        "mutated_field": spec.field,
        "original_value": mutation["original_value"],
        "injected_value": mutation["injected_value"],
        "related_event_ids": dict(sorted(related.items())),
        "source_tick": anchor.get("source_tick"),
        "transaction": (None if anchor.get("transaction") is None
                        else dict(anchor["transaction"])),
        "case_admission_ids": _source_admission_ids(events),
        "origin_status": provenance.get("origin_status"),
        "origin_admission_ids": list(provenance.get("origin_admission_ids", ())),
        "event_id_shift": mutation["event_id_shift"],
        "inserted_checker_input_event_id":
            mutation["inserted_checker_input_event_id"],
        "value_semantics": ("claim_count" if spec.operation == "duplicate"
                            and entry["mutation"]["replacement"] is None
                            else "payload"),
        "pinned_selector": dict(sorted(selector.items())),
    }
    if spec.operation == "duplicate":
        chain["duplicated_event_id"] = None if mutation["duplicated_event_id"] is None \
            else mutation["duplicated_event_id"] - shift_before
    return chain


def _finding_id(entry: Mapping, chain: Mapping) -> str:
    identity = {
        "kind": entry["kind"],
        "variant": entry["variant"],
        "checker": entry["checker"],
        "expected_finding": entry["expected_finding"],
        "mutated_field": chain["mutated_field"],
        "case_id": chain["case_id"],
        "observation_event_id": chain["observation_event_id"],
        "related_event_ids": chain["related_event_ids"],
        "original_value": chain["original_value"],
        "injected_value": chain["injected_value"],
        "inserted_checker_input_event_id":
            chain["inserted_checker_input_event_id"],
    }
    digest = _canonical_sha256(identity)[:16]
    return f"{_FINDING_PREFIX}_{entry['kind']}_{digest}"


def _finding_document(entry: Mapping, chain: Mapping, findings: Sequence[str],
                      raw_events: Sequence[Mapping],
                      perturbed_events: Sequence[Mapping]) -> dict:
    return {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_id": _finding_id(entry, chain),
        "fault_id": entry["fault_id"],
        "kind": entry["kind"],
        "variant": entry["variant"],
        "checker": entry["checker"],
        "detected_by": entry["expected_finding"],
        "checker_findings": list(findings),
        "calibration_only": True,
        "observation_boundary": _OBSERVATION_BOUNDARY,
        "case_id": chain["case_id"],
        "event_id_shift": chain["event_id_shift"],
        "source_chain": chain,
        "raw_observation_sha256": _canonical_sha256(list(raw_events)),
        "checker_input_sha256": _canonical_sha256(list(perturbed_events)),
    }


# --------------------------------------------------------------------------
# public containers
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlledFaultObservation:
    """One calibrated injection: the finding plus the checker-input copy."""

    fault_id: str
    finding_id: str
    case_id: str
    kind: str
    variant: str
    checker: str
    expected_finding: str
    checker_findings: tuple[str, ...]
    finding: dict
    pinned_entry: dict
    perturbed_events: tuple[dict, ...]


@dataclass(frozen=True)
class ControlledFaultRun:
    """The outcome of feeding one receipt through the family."""

    case_id: str
    violations: tuple[str, ...]
    baseline_findings: tuple[str, ...]
    injected_findings: tuple[str, ...]
    observations: tuple[ControlledFaultObservation, ...]
    skipped: tuple[dict, ...] = ()

    @property
    def finding_documents(self) -> tuple[dict, ...]:
        return tuple(observation.finding for observation in self.observations)


class _RuntimeSlots:
    """Runtime chains live in slots so checker identity stays canonical JSON."""

    __slots__ = ("_entries", "_chains", "_baselines", "_shifts", "_cases",
                 "_observations")


class ControlledFaultFamily(_RuntimeSlots):
    """A checker-callable that injects the configured calibration faults.

    ``__call__`` accepts the same ``OnlineCaseReceipt`` the online session
    checkers receive, so it can be handed to
    ``make_ibex_pulp_online_runtime(checker=...)`` and every other session
    ``checker=`` call site.  ``trace_checker()`` adapts it to the offline
    ``ScenarioRfuzzExecutor(checker=...)`` trace call site.
    """

    def __init__(self, document: Mapping) -> None:
        validated = validate_fault_document(document)
        self.fault_mode = FAULT_SCHEMA_VERSION
        self.fault_document = validated
        self._entries = tuple(validated["faults"])
        self._chains = {}
        self._baselines = {}
        self._shifts = {entry["fault_id"]: 0 for entry in self._entries}
        self._cases = {}
        self._observations = ()

    # -- construction ------------------------------------------------------
    @classmethod
    def from_document(cls, document: object) -> "ControlledFaultFamily":
        return cls(document)

    @classmethod
    def from_faults(cls, faults: Sequence[Mapping]) -> "ControlledFaultFamily":
        return cls({"schema_version": FAULT_SCHEMA_VERSION,
                    "faults": [dict(fault) for fault in faults]})

    def document(self) -> dict:
        document = validate_fault_document(self.fault_document)
        return {"schema_version": document["schema_version"],
                "faults": [dict(entry) for entry in document["faults"]]}

    # -- state -------------------------------------------------------------
    @property
    def observations(self) -> tuple[ControlledFaultObservation, ...]:
        return tuple(self._observations)

    @property
    def finding_documents(self) -> tuple[dict, ...]:
        return tuple(observation.finding for observation in self._observations)

    def reset(self) -> None:
        """Drop runtime chains while keeping the validated configuration."""
        self._chains = {}
        self._baselines = {}
        self._shifts = {entry["fault_id"]: 0 for entry in self._entries}
        self._cases = {}
        self._observations = ()

    def _chain(self, entry: Mapping):
        chain = self._chains.get(entry["fault_id"])
        if chain is None:
            chain = _CHECKER_FACTORIES[entry["checker"]]()
            self._chains[entry["fault_id"]] = chain
        return chain

    def _baseline(self, checker: str):
        chain = self._baselines.get(checker)
        if chain is None:
            chain = _CHECKER_FACTORIES[checker]()
            self._baselines[checker] = chain
        return chain

    # -- injection ---------------------------------------------------------
    def inject(self, receipt: OnlineCaseReceipt) -> ControlledFaultRun:
        if not isinstance(receipt, OnlineCaseReceipt):
            raise ValueError("OnlineCaseReceipt is required")
        raw_events = tuple(receipt.events)
        fingerprint = _canonical_sha256(list(raw_events))
        cached = self._cases.get(receipt.case_id)
        if cached is not None:
            if cached[0] != fingerprint:
                raise ValueError(
                    "online case receipt identity reused with different events")
            return cached[1]
        baseline: dict[str, tuple[str, ...]] = {}
        for checker in sorted({entry["checker"] for entry in self._entries}):
            baseline[checker] = tuple(self._baseline(checker)(receipt))
        observations: list[ControlledFaultObservation] = []
        findings: list[str] = []
        skipped: list[dict] = []
        for entry in self._entries:
            selector = entry["selector"]
            if "case_id" in selector and selector["case_id"] != receipt.case_id:
                continue
            if entry["expected_finding"] in baseline[entry["checker"]]:
                # Never inject where the contradiction already exists without
                # the fault: the injected finding would be indistinguishable
                # from the natural one.  A pinned replay configuration must
                # reproduce its calibration finding, so there it refuses.
                if selector:
                    raise ControlledFaultCalibrationError(
                        "pinned controlled fault cannot reproduce its "
                        "calibration finding: the unperturbed observation "
                        f"already reports {entry['expected_finding']}")
                skipped.append({
                    "fault_id": entry["fault_id"],
                    "kind": entry["kind"],
                    "variant": entry["variant"],
                    "expected_finding": entry["expected_finding"],
                    "reason": "unperturbed_observation_already_reports_expected_finding",
                })
                continue
            chain = self._chain(entry)
            shift = self._shifts[entry["fault_id"]]
            events = _shift_receipt(raw_events, shift) if shift else list(raw_events)
            anchor = _LOCATORS[(entry["kind"], entry["variant"])](
                _Search(events, strict=bool(selector)), selector)
            if anchor is None:
                chain(replace(receipt, events=tuple(events)))
                continue
            spec = _VARIANTS[(entry["kind"], entry["variant"])]
            replacement = entry["mutation"]["replacement"]
            if spec.operation == "duplicate":
                perturbed, mutation = _inject_duplicate(events, spec, anchor,
                                                        replacement)
            else:
                perturbed, mutation = _inject_rewrite(events, spec, anchor,
                                                      replacement)
            chain_findings = tuple(chain(replace(receipt, events=tuple(perturbed))))
            if entry["expected_finding"] not in chain_findings:
                raise ControlledFaultCalibrationError(
                    f"{entry['kind']}/{entry['variant']} perturbed the checker "
                    "input but did not reach "
                    f"{entry['expected_finding']}; refusing to claim a "
                    "calibrated fault")
            chain_record = _chain_record(entry, anchor, mutation, receipt.case_id,
                                         events, shift)
            finding = _finding_document(entry, chain_record, chain_findings,
                                        raw_events, perturbed)
            pinned_entry = {key: entry[key] for key in _ENTRY_KEYS}
            pinned_entry["selector"] = chain_record["pinned_selector"]
            pinned_entry["fault_id"] = _fault_id(pinned_entry)
            validate_fault_document({"schema_version": FAULT_SCHEMA_VERSION,
                                     "faults": [pinned_entry]})
            observation = ControlledFaultObservation(
                fault_id=entry["fault_id"], finding_id=finding["finding_id"],
                case_id=receipt.case_id, kind=entry["kind"],
                variant=entry["variant"], checker=entry["checker"],
                expected_finding=entry["expected_finding"],
                checker_findings=chain_findings, finding=finding,
                pinned_entry=pinned_entry,
                perturbed_events=tuple(perturbed))
            observations.append(observation)
            findings.extend(chain_findings)
            self._shifts[entry["fault_id"]] += mutation["event_id_shift"]
        baseline_order = tuple(dict.fromkeys(
            item for name in sorted(baseline) for item in baseline[name]))
        violations = tuple(dict.fromkeys((*baseline_order, *findings)))
        run = ControlledFaultRun(
            case_id=receipt.case_id, violations=violations,
            baseline_findings=baseline_order,
            injected_findings=tuple(dict.fromkeys(findings)),
            observations=tuple(observations), skipped=tuple(skipped))
        self._observations = self._observations + tuple(observations)
        self._cases[receipt.case_id] = (fingerprint, run)
        return run

    def __call__(self, receipt: OnlineCaseReceipt) -> tuple[str, ...]:
        return self.inject(receipt).violations

    # -- persistence -------------------------------------------------------
    def minimal_replay_document(self) -> dict:
        """Minimal configuration that reproduces exactly the injected findings.

        The returned ``fault_document`` is a valid ``p5_controlled_fault.v1``
        document whose anchors are pinned to the observed case, event IDs,
        ticks and original values.  Re-running it in a new process against the
        same saved observation reproduces the same finding documents; against a
        changed observation it refuses instead of fabricating a finding.
        """
        if not self._observations:
            raise ControlledFaultCalibrationError(
                "no controlled fault was calibrated; there is no minimal "
                "replay input")
        pinned = [observation.pinned_entry for observation in self._observations]
        document = validate_fault_document(
            {"schema_version": FAULT_SCHEMA_VERSION, "faults": pinned})
        return {
            "schema_version": REPLAY_SCHEMA_VERSION,
            "calibration_only": True,
            "observation_boundary": _OBSERVATION_BOUNDARY,
            "fault_document": document,
            "fault_document_sha256": _canonical_sha256(document),
            "findings": [{
                "finding_id": observation.finding_id,
                "fault_id": observation.fault_id,
                "case_id": observation.case_id,
                "expected_finding": observation.expected_finding,
                "detected_by": observation.expected_finding,
                "observation_event_id":
                    observation.finding["source_chain"]["observation_event_id"],
            } for observation in self._observations],
        }

    # -- offline call-site adapter ----------------------------------------
    def trace_checker(self) -> Callable[[object], tuple[str, ...]]:
        """Adapt the family to the offline ``ScenarioTrace`` checker call site."""

        def check(trace: object) -> tuple[str, ...]:
            events = getattr(trace, "events", None)
            genome = getattr(trace, "genome_sha256", None)
            status = getattr(trace, "status", None)
            if not isinstance(events, (list, tuple)) or not isinstance(genome, str):
                raise ValueError("controlled faults require a scenario trace")
            return self(OnlineCaseReceipt(
                genome, 0, len(events), tuple(events), {},
                dict(getattr(trace, "local_ticks", {}) or {}),
                status if isinstance(status, str) else "running"))

        return check


def controlled_fault_checker(document: object) -> ControlledFaultFamily:
    """Build the drop-in checker callable for one fault configuration."""
    return ControlledFaultFamily.from_document(document)
