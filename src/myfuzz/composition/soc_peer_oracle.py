"""Independent, observation-bounded reference checks for peer-model runs.

The generated peer RTL is still the implementation under test.  This module
does not import or execute that RTL and it does not infer an expected result
from an RTL counter.  It implements the frozen peer contract in a separate
Python reference and only compares properties for which the runtime exposes
enough evidence.  Wire-level UART receive, SPI clocking, and GPIO electrical
resolution are therefore reported as ``not_assessed`` until a waveform trace is
available; they are never silently called passing.

A peer offer reaches the peer model through one of two routes, and the
expectation must follow the route that was actually used:

* the declared peer *event plan* (``sample.peer_events``), or
* the per-cycle **raw record** (``sample.raw`` / ``RunResult.trace``), decoded by
  :func:`myfuzz.composition.soc_peer_replay.decode_peer_raw_events`.

A raw-driven frame has no plan entry, so reading only the plan made the oracle
report ``uart-tx-sent-count: mismatch`` for a frame the register readback
proves arrived.  :func:`uart_raw_expectation` closes that gap: the expectation
is the raw input the test itself wrote, decoded under the build's own ABI, and
the check records that provenance in its ``basis``.  When neither source exists
the check is ``not_assessed`` with a named reason -- never a mismatch and never
a pass.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from myfuzz.contracts import canonical_bytes

from .soc_peer_replay import PeerRawReplayError, decode_peer_raw_events


PEER_ORACLE_SCHEMA = "soc_peer_oracle.v1"
_BASIS = "soc_peer_oracle.v1:independent peer contract"
#: The expectation was decoded from the raw ABI record, not from a peer event
#: plan and not from ``peer_applied`` or any peer counter.
_RAW_BASIS = "soc_peer_oracle.v1:raw-decoded"
#: The independent UART frame contract used when no component-side register norm
#: is declared: the declared format decides framing and baud, and the data is
#: only decided against independently declared bytes.
_WIRE_BASIS = "soc_peer_oracle.v1:independent UART frame contract"
#: The UART frame criteria, in the order they are reported.
_UART_WIRE_CHECKS = ("uart-rx-wire", "uart-framing-wire", "uart-baud-wire")


class PeerOracleError(ValueError):
    """The independent peer contract cannot be evaluated."""


def _error(reason: str) -> None:
    raise PeerOracleError(reason)


def _integer(value: object, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _error(reason)
    return int(value)


def _positive(value: object, name: str) -> int:
    number = _integer(value, f"{name}-invalid")
    if number < 1:
        _error(f"{name}-invalid")
    return number


def _event_value(event: object, name: str, default: object = None) -> object:
    if isinstance(event, Mapping):
        return event.get(name, default)
    return getattr(event, name, default)


def uart_tx_expectation(events: Sequence[object], *, cycles: int,
                        data_width: int, baud_div: int,
                        stop_bits: int) -> dict[str, object]:
    """Return the contract-level UART transmitter expectation.

    One accepted offer occupies ``(start + data + stop) * baud_div`` cycles.
    An offer at the completion boundary is still busy and is dropped; this is
    why the declared minimum spacing is ``frame_cycles + 1``.  ``cycles`` is a
    half-open run window, so a frame completing at cycle ``cycles`` is not yet
    observable in that run.
    """
    width = _positive(data_width, "uart-data-width")
    divisor = _positive(baud_div, "uart-baud-div")
    stops = _positive(stop_bits, "uart-stop-bits")
    run_cycles = _integer(cycles, "uart-run-cycles-invalid")
    if run_cycles < 0:
        _error("uart-run-cycles-invalid")
    frame_cycles = (1 + width + stops) * divisor
    normalized: list[tuple[int, int]] = []
    for index, event in enumerate(events):
        cycle = _integer(_event_value(event, "cycle"),
                         f"uart-event-cycle-invalid:{index}")
        payload = _integer(_event_value(event, "payload", 0),
                           f"uart-event-payload-invalid:{index}")
        if cycle < 0:
            _error(f"uart-event-cycle-invalid:{index}:{cycle}")
        if payload < 0 or payload >= (1 << width):
            _error(f"uart-event-payload-out-of-range:{index}:{payload}")
        normalized.append((cycle, payload))
    normalized.sort(key=lambda item: item[0])
    accepted_cycles: list[int] = []
    dropped_cycles: list[int] = []
    busy_until = -1
    for cycle, _payload in normalized:
        if cycle <= busy_until:
            dropped_cycles.append(cycle)
            continue
        accepted_cycles.append(cycle)
        busy_until = cycle + frame_cycles
    completed_cycles = [cycle + frame_cycles for cycle in accepted_cycles
                        if cycle + frame_cycles < run_cycles]
    return {
        "frame_cycles": frame_cycles,
        "minimum_gap_cycles": frame_cycles + 1,
        "accepted_count": len(accepted_cycles),
        "drop_count": len(dropped_cycles),
        "completed_count": len(completed_cycles),
        "accepted_cycles": accepted_cycles,
        "dropped_cycles": dropped_cycles,
        "completed_cycles": completed_cycles,
        "required_completion_cycles": (
            0 if not accepted_cycles else max(accepted_cycles) + frame_cycles + 1),
    }


def uart_raw_expectation(raw_values: Sequence[int], layout: object,
                         slots: Sequence[Mapping[str, object]], *, cycles: int,
                         data_width: int, baud_div: int,
                         stop_bits: int) -> dict[str, object]:
    """Derive the transmitter expectation by decoding the raw record itself.

    ``decode_peer_raw_events`` is the peer contract's own decoder: it turns the
    per-cycle raw words into the payload-carrying records the peer model latches.
    Those records -- not ``peer_applied`` and not a peer counter -- are this
    expectation's source, so a raw-driven frame is judged exactly like an
    event-plan-driven one.  ``slots`` names the slots to decode; when any of them
    declares ``peer_id == "uart"`` only the UART events are used, so a record
    that also drives another peer cannot leak into the busy-window model.

    Spacing is deliberately not validated here.  The raw route's spacing is the
    projection's business, and :func:`uart_tx_expectation` already models a
    too-close offer as a *dropped* one, which is the drop-count criterion.
    """
    events = decode_peer_raw_events(raw_values, layout, slots,
                                    validate_spacing=False)
    peer_ids = {str(item.get("peer_id", "")) for item in slots
                if isinstance(item, Mapping)}
    if "uart" in peer_ids:
        events = tuple(event for event in events
                       if str(event.get("peer_id", "")) == "uart")
    offers = [{"cycle": _integer(event.get("cycle"), "uart-raw-event-cycle-invalid"),
               "payload": _integer(event.get("payload", 0),
                                   "uart-raw-event-payload-invalid")}
              for event in events]
    expectation = uart_tx_expectation(offers, cycles=cycles, data_width=data_width,
                                      baud_div=baud_div, stop_bits=stop_bits)
    expectation["basis"] = _RAW_BASIS
    expectation["source"] = "raw-decoded"
    expectation["decoded_offers"] = offers
    return expectation


def gpio_resolution(*, peer_drive_value: int, peer_drive_valid: int,
                    component_out: int, component_dir: int, pins: int,
                    default_input_level: int,
                    contention_is_error: int,
                    previous_contention: int = 0,
                    previous_error: int = 0) -> dict[str, int]:
    """Resolve one GPIO sample using the independent electrical contract."""
    width = _positive(pins, "gpio-pins")
    mask = (1 << width) - 1
    default = _integer(default_input_level, "gpio-default-input-level-invalid")
    error_policy = _integer(contention_is_error, "gpio-contention-policy-invalid")
    if default not in (0, 1):
        _error("gpio-default-input-level-invalid")
    if error_policy not in (0, 1):
        _error("gpio-contention-policy-invalid")
    values = {
        "peer_drive_value": _integer(peer_drive_value, "gpio-peer-value-invalid") & mask,
        "peer_drive_valid": _integer(peer_drive_valid, "gpio-peer-valid-invalid") & mask,
        "component_out": _integer(component_out, "gpio-component-value-invalid") & mask,
        "component_dir": _integer(component_dir, "gpio-component-dir-invalid") & mask,
        "previous_contention": _integer(previous_contention,
                                          "gpio-previous-contention-invalid") & mask,
    }
    if _integer(previous_error, "gpio-previous-error-invalid") not in (0, 1):
        _error("gpio-previous-error-invalid")
    contention = values["peer_drive_valid"] & values["component_dir"] & (
        values["peer_drive_value"] ^ values["component_out"])
    agreed = ((values["peer_drive_valid"] & values["peer_drive_value"]) |
              (values["component_dir"] & values["component_out"]) |
              ((~(values["peer_drive_valid"] | values["component_dir"])) &
               (mask if default else 0))) & mask
    # A contended pin resolves to the declared contention level and every other
    # pin keeps its agreed value, per pin: the peer RTL computes
    # ``contended ? CONTENTION_LEVEL : agreed`` and its declared level is zero.
    # Zeroing the *whole word* made the reference disagree with the RTL on a
    # partial contention -- with the component driving 0xAA and the peer 0xAB on
    # bit 0, the RTL reports 0xAA and the whole-word form reported 0.
    resolved = ((contention & 0) | (~contention & agreed)) & mask
    contention_rise = contention & (~values["previous_contention"] & mask)
    return {
        "resolved": resolved,
        "contention": contention,
        "contention_rise": contention_rise,
        "contention_count": contention_rise.bit_count(),
        "contention_error": int(bool(previous_error) or
                                 bool(error_policy and contention)),
    }


def spi_wire_expectation(trace: Sequence[Mapping[str, object]], *, bits: int,
                         cpol: int, cpha: int, cs_active_low: int,
                         mosi_words: Sequence[int],
                         miso_words: Sequence[int]) -> dict[str, object]:
    """Decode selected SPI edges from observed wires against external words.

    This decoder deliberately has no access to peer counters or generated
    software.  A missing/unknown sample cannot turn into a passing transfer.
    """
    def outcome(status: str, reason: str, tx: list[int], rx: list[int]) -> dict[str, object]:
        return {"status": status, "reason": reason,
                "observed_mosi_words": tx, "observed_miso_words": rx}

    width = _positive(bits, "spi-bits")
    if width > 32 or cpol not in (0, 1) or cpha not in (0, 1) or \
            cs_active_low not in (0, 1):
        _error("spi-wire-parameters-invalid")
    if not trace:
        return outcome("not_assessed", "spi-wire-trace-missing", [], [])
    rows: list[tuple[int, int, int, int, int]] = []
    for index, item in enumerate(trace):
        if not isinstance(item, Mapping):
            return outcome("not_assessed", f"spi-wire-record-invalid:{index}", [], [])
        values: list[int] = []
        for role in ("sck", "cs", "mosi", "miso"):
            value = item.get(role)
            if value not in (0, 1, "0", "1"):
                return outcome("not_assessed", f"spi-wire-unknown:{index}:{role}", [], [])
            values.append(int(value))
        cycle = item.get("cycle")
        if isinstance(cycle, bool) or not isinstance(cycle, int) or \
                (rows and cycle <= rows[-1][0]):
            return outcome("not_assessed", f"spi-wire-cycle-invalid:{index}", [], [])
        rows.append((cycle, *values))
    inactive = cs_active_low
    if rows[0][2] != inactive or rows[0][1] != cpol:
        return outcome("not_assessed", "spi-wire-initial-idle-missing", [], [])
    tx_words: list[int] = []
    rx_words: list[int] = []
    tx_bits: list[int] = []
    rx_bits: list[int] = []
    selected = False
    for before, after in zip(rows, rows[1:]):
        _cycle, old_sck, old_cs, _old_mosi, _old_miso = before
        _next_cycle, sck, cs, mosi, miso = after
        was_selected = old_cs != inactive
        now_selected = cs != inactive
        if not was_selected and now_selected:
            if old_sck != cpol or sck != cpol:
                return outcome("mismatch", "spi-select-clock-not-idle", tx_words, rx_words)
            selected = True
            tx_bits = []
            rx_bits = []
        elif was_selected and not now_selected:
            if len(tx_bits) != width or len(rx_bits) != width:
                return outcome("mismatch", "spi-incomplete-frame", tx_words, rx_words)
            tx_words.append(int("".join(map(str, tx_bits)), 2))
            rx_words.append(int("".join(map(str, rx_bits)), 2))
            selected = False
            if sck != cpol:
                return outcome("mismatch", "spi-deselect-clock-not-idle", tx_words, rx_words)
        elif not now_selected:
            if sck != cpol or sck != old_sck:
                return outcome("mismatch", "spi-deselected-clock", tx_words, rx_words)
        elif sck != old_sck:
            leading = old_sck == cpol
            if leading == (cpha == 0):
                tx_bits.append(mosi)
                rx_bits.append(miso)
                if len(tx_bits) > width:
                    return outcome("mismatch", "spi-too-many-sample-edges",
                                   tx_words, rx_words)
    if selected:
        return outcome("not_assessed", "spi-selection-not-closed", tx_words, rx_words)
    if tx_words != list(mosi_words) or rx_words != list(miso_words):
        return outcome("mismatch", "spi-transfer-data", tx_words, rx_words)
    return outcome("pass", "spi-transfer-verified", tx_words, rx_words)


def _wire_criterion(check_id: str, status: str, reason: str, *,
                    expected: object = None, observed: object = None) -> dict[str, object]:
    return {"check_id": check_id, "status": status, "reason": reason,
            "expected": expected, "observed": observed}


def _wire_not_assessed(reason: str, expected: list[int] | None = None) -> dict[str, object]:
    """One undecided line-level document: every frame criterion names the gap."""
    return {
        "status": "not_assessed",
        "reason": reason,
        "observed_bytes": [],
        "expected_bytes": None if expected is None else list(expected),
        "criteria": [_wire_criterion(check_id, "not_assessed", reason)
                     for check_id in _UART_WIRE_CHECKS],
    }


def uart_wire_expectation(trace: Sequence[Mapping[str, object]], *,
                          expected_bytes: Sequence[int] | None = None,
                          data_width: int = 8, baud_div: int, stop_bits: int = 1,
                          idle_level: int = 1, parity: str = "none") -> dict[str, object]:
    """Decode a per-cycle component-to-peer UART line against the declared frame.

    ``trace`` holds one level sample per cycle of the line the peer's receiver
    sees (the component's ``uart_tx_o``).  Each declared bit cell is sampled at
    its middle and the frame is reconstructed LSB first:

    * ``uart-rx-wire`` compares the reconstructed bytes with ``expected_bytes``,
      which must come from independent evidence -- an accepted CPU write to the
      component's TXDATA register or a declared register norm -- never from the
      peer's own ``rx_data_o`` or ``rx_count_o``;
    * ``uart-framing-wire`` decides the start and the stop levels;
    * ``uart-baud-wire`` decides that the sampled line holds each declared bit
      cell, which is exactly what a wrong baud or a half-cell phase offset
      breaks.

    A missing sample, an unknown level, a trace that ends inside a frame or a
    trace with no frame at all is ``not_assessed`` with a named reason: missing
    evidence never becomes a pass.  A format this oracle does not model (data
    width other than 8, more than one stop bit, parity) is refused by name so no
    default silently approximates the declared profile.
    """
    width = _integer(data_width, "uart-data-width-invalid")
    divisor = _positive(baud_div, "uart-baud-div")
    stops = _positive(stop_bits, "uart-stop-bits")
    idle = _integer(idle_level, "uart-idle-level-invalid")
    if idle not in (0, 1):
        _error("uart-idle-level-invalid")
    if parity not in ("none", None):
        _error(f"uart-wire-mode-unsupported:parity-{parity}")
    if width != 8 or stops != 1:
        _error(f"uart-wire-mode-unsupported:data-width-{width}:stop-bits-{stops}")
    if divisor < 2:
        _error("uart-wire-baud-div-invalid")
    expected: list[int] | None = None
    if expected_bytes is not None:
        expected = []
        for index, value in enumerate(expected_bytes):
            number = _integer(value, f"uart-wire-expected-byte-invalid:{index}")
            if number < 0 or number >= (1 << width):
                _error(f"uart-wire-expected-byte-out-of-range:{index}:{number}")
            expected.append(number)
    if not trace:
        return _wire_not_assessed("uart-wire-trace-missing", expected)
    rows: list[tuple[int, int]] = []
    for index, item in enumerate(trace):
        if not isinstance(item, Mapping):
            return _wire_not_assessed(f"uart-wire-record-invalid:{index}", expected)
        value = item.get("line", item.get("uart_tx"))
        if isinstance(value, bool) or value not in (0, 1, "0", "1"):
            return _wire_not_assessed(f"uart-wire-unknown:{index}", expected)
        cycle = item.get("cycle")
        if isinstance(cycle, bool) or not isinstance(cycle, int) or \
                (rows and cycle <= rows[-1][0]):
            return _wire_not_assessed(f"uart-wire-cycle-invalid:{index}", expected)
        rows.append((cycle, int(value)))
    levels = {cycle: level for cycle, level in rows}
    cells = 1 + width + stops
    frames: list[int] = []
    framing_reason = ""
    baud_reason = ""
    position = 0
    while position + 1 < len(rows):
        if rows[position][1] != idle or rows[position + 1][1] == idle:
            position += 1
            continue
        start = rows[position + 1][0]
        values: list[int] = []
        for cell in range(cells):
            sample = start + cell * divisor + divisor // 2
            if sample not in levels:
                return _wire_not_assessed(f"uart-wire-frame-incomplete:{start}", expected)
            bit = levels[sample]
            values.append(bit)
            for offset in range(divisor):
                cycle = start + cell * divisor + offset
                if cycle not in levels:
                    return _wire_not_assessed(
                        f"uart-wire-frame-incomplete:{start}", expected)
                if levels[cycle] != bit and not baud_reason:
                    baud_reason = (f"uart-wire-line-changes-inside-bit-cell:"
                                   f"{start}:{cell}")
        if values[0] == idle and not framing_reason:
            framing_reason = f"uart-wire-start-bit-not-idle:{start}"
        for cell in range(1 + width, cells):
            if values[cell] != idle and not framing_reason:
                framing_reason = f"uart-wire-stop-bit-not-idle:{start}:{cell}"
        byte = 0
        for index in range(width):
            byte |= values[1 + index] << index
        frames.append(byte)
        end = start + cells * divisor
        while position < len(rows) and rows[position][0] < end:
            position += 1
    if not frames:
        return _wire_not_assessed("uart-wire-no-frame-observed", expected)
    if expected is None:
        data = _wire_criterion(
            "uart-rx-wire", "not_assessed",
            "uart-wire-expectation-missing: no independent component-side byte "
            "norm is declared", observed=frames)
    elif frames == expected:
        data = _wire_criterion("uart-rx-wire", "pass", "uart-rx-wire-frame-verified",
                               expected=expected, observed=frames)
    else:
        data = _wire_criterion("uart-rx-wire", "mismatch", "uart-rx-wire-data",
                               expected=expected, observed=frames)
    criteria = [
        data,
        _wire_criterion("uart-framing-wire",
                        "mismatch" if framing_reason else "pass",
                        framing_reason or "uart-framing-wire-verified"),
        _wire_criterion("uart-baud-wire", "mismatch" if baud_reason else "pass",
                        baud_reason or "uart-baud-wire-verified"),
    ]
    status = ("mismatch" if any(item["status"] == "mismatch" for item in criteria)
              else "not_assessed" if any(item["status"] == "not_assessed"
                                         for item in criteria) else "pass")
    reason = next((str(item["reason"]) for item in criteria
                   if item["status"] != "pass"), "uart-wire-frame-verified")
    return {
        "status": status,
        "reason": reason,
        "observed_bytes": frames,
        "expected_bytes": None if expected is None else list(expected),
        "criteria": criteria,
    }


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _slot_records(build: object) -> tuple[Mapping[str, object], ...]:
    records = getattr(build, "peer_slots", ()) or ()
    return tuple(item for item in records if isinstance(item, Mapping))


class _RawField:
    """One peer signal's place in the combined raw ABI."""

    __slots__ = ("port", "width", "raw_lo")

    def __init__(self, port: str, width: int, raw_lo: int) -> None:
        self.port = port
        self.width = width
        self.raw_lo = raw_lo


class _RawLayout:
    """The minimum the replay decoder needs: a raw width and port offsets."""

    __slots__ = ("raw_width", "fields")

    def __init__(self, raw_width: int, fields: Sequence[_RawField]) -> None:
        self.raw_width = raw_width
        self.fields = tuple(fields)


#: The rendered testbench assigns a peer port from the raw word only when no
#: peer-plan event drives it.  That one line is the build's own record of the
#: port's bit offset, so it is parsed instead of re-derived from widths.
_RAW_ASSIGN = re.compile(
    r"assign\s+(?P<port>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[A-Za-z_][A-Za-z0-9_]*__event_active\s*\?\s*"
    r"[A-Za-z_][A-Za-z0-9_]*__event\s*:\s*"
    r"raw_bits\[(?P<hi>\d+):(?P<lo>\d+)\]\s*;")


def _raw_width(build: object) -> int | None:
    width = getattr(build, "raw_width", None)
    if isinstance(width, bool) or not isinstance(width, int) or width < 1:
        return None
    return width


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value)


def _signal_port(signal: object) -> str:
    if not isinstance(signal, Mapping):
        return ""
    port = signal.get("top_port", signal.get("port"))
    return port if isinstance(port, str) else ""


def _layout_covers(candidate: object, slots: Sequence[Mapping[str, object]]) -> bool:
    """Whether ``candidate`` places every signal of ``slots`` at its declared width."""
    if candidate is None or not hasattr(candidate, "fields") or \
            not hasattr(candidate, "raw_width"):
        return False
    if _raw_width(candidate) is None:
        return False
    by_port: dict[str, object] = {}
    for field in getattr(candidate, "fields", ()) or ():
        port = getattr(field, "port", None)
        if isinstance(port, str) and port:
            by_port[port] = field
    for slot in slots:
        signals = slot.get("signals", ()) or ()
        if not signals:
            return False
        for signal in signals:
            port = _signal_port(signal)
            field = by_port.get(port)
            if not port or field is None:
                return False
            if _as_int(getattr(field, "width", None)) != _as_int(signal.get("width")):
                return False
            raw_lo = _as_int(getattr(field, "raw_lo", None))
            if raw_lo is None or raw_lo < 0:
                return False
    return True


def _signal_layout(slots: Sequence[Mapping[str, object]],
                   raw_width: int) -> _RawLayout | None:
    fields: list[_RawField] = []
    for slot in slots:
        for signal in slot.get("signals", ()) or ():
            port = _signal_port(signal)
            width = signal.get("width")
            raw_lo = signal.get("raw_lo")
            if not port or isinstance(width, bool) or not isinstance(width, int) or \
                    width < 1 or isinstance(raw_lo, bool) or \
                    not isinstance(raw_lo, int) or raw_lo < 0:
                return None
            fields.append(_RawField(port, width, raw_lo))
    return _RawLayout(raw_width, fields) if fields else None


def _testbench_layout(build: object,
                      slots: Sequence[Mapping[str, object]]) -> _RawLayout | None:
    """Recover the peer offsets from the testbench the build really compiled.

    ``build_profile_runtime`` keeps the compiled testbench and the peer slot
    records, but not the combined input layout.  The testbench's own
    ``raw_bits[hi:lo]`` extraction is the ABI record of the binary that ran, so
    it is read here; a file that is gone, or a port whose declared width does not
    match the span, yields ``None`` and the caller reports the gap instead of
    guessing an offset from signal ordering.
    """
    path = getattr(build, "testbench_path", None)
    if not isinstance(path, (str, Path)):
        return None
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    offsets: dict[str, tuple[int, int]] = {}
    for match in _RAW_ASSIGN.finditer(text):
        offsets.setdefault(str(match.group("port")),
                           (int(match.group("lo")), int(match.group("hi"))))
    if not offsets:
        return None
    raw_width = _raw_width(build)
    if raw_width is None:
        return None
    fields: list[_RawField] = []
    for slot in slots:
        for signal in slot.get("signals", ()) or ():
            port = _signal_port(signal)
            width = _as_int(signal.get("width"))
            span = offsets.get(port)
            if span is None or width is None or width < 1:
                return None
            lo, hi = span
            if hi - lo + 1 != width or hi >= raw_width:
                return None
            fields.append(_RawField(port, width, lo))
    return _RawLayout(raw_width, fields) if fields else None


def _raw_layout(build: object, slots: Sequence[Mapping[str, object]]) -> object | None:
    """The raw ABI the build declares for ``slots``, or ``None`` with no guess."""
    width = _raw_width(build)
    if width is not None:
        layout = _signal_layout(slots, width)
        if layout is not None:
            return layout
    for name in ("peer_raw_layout", "layout", "soc_layout"):
        candidate = getattr(build, name, None)
        if _layout_covers(candidate, slots):
            return candidate
    return _testbench_layout(build, slots)


def _raw_record(sample: object, result: object) -> tuple[int, ...]:
    """The per-cycle raw words the run consumed, from the sample or its trace."""
    values = getattr(sample, "raw", None)
    if isinstance(values, Sequence) and not isinstance(values, (str, bytes)) and values:
        return tuple(int(value) for value in values)
    record: list[int] = []
    for item in getattr(result, "trace", ()) or ():
        if isinstance(item, Mapping) and "raw" in item:
            record.append(int(item["raw"]))
    return tuple(record)


def _uart_expectation_source(build: object, sample: object, result: object,
                             slot: Mapping[str, object],
                             declared: Sequence[object], *, cycles: int,
                             data_width: int, baud_div: int,
                             stop_bits: int) -> tuple[dict[str, object] | None, str, str]:
    """The UART transmitter expectation and the source it was taken from.

    Returns ``(expectation, basis, message)``.  ``message`` is the check's note
    when an expectation was found and the named reason why not otherwise.  The
    raw record is only consulted when the declared plan is empty, so an
    event-plan-driven sample keeps its original expectation exactly.
    """
    if declared:
        expectation = uart_tx_expectation(declared, cycles=cycles,
                                          data_width=data_width,
                                          baud_div=baud_div, stop_bits=stop_bits)
        return (expectation, _BASIS,
                "the declared peer event plan is the expectation source")
    record = _raw_record(sample, result)
    if not record:
        return (None, _BASIS,
                "uart-expectation-source-missing: the sample declares no peer event "
                "and carries no raw record")
    layout = _raw_layout(build, (slot,))
    if layout is None:
        return (None, _BASIS,
                "uart-raw-offsets-unavailable: the build declares no peer raw bit "
                "offsets, so the raw record cannot be decoded")
    try:
        expectation = uart_raw_expectation(record, layout, (slot,), cycles=cycles,
                                           data_width=data_width, baud_div=baud_div,
                                           stop_bits=stop_bits)
    except (PeerRawReplayError, PeerOracleError, TypeError, ValueError) as error:
        return (None, _BASIS, f"uart-raw-decode-refused: {error}")
    return (expectation, _RAW_BASIS,
            "the raw record, decoded by soc_peer_replay.decode_peer_raw_events, "
            "is the expectation source "
            f"({len(expectation['decoded_offers'])} raw offer(s) decoded)")


def _uart_wire_expected_bytes(build: object, result: object, instance: str,
                              width: int) -> tuple[list[int] | None, str, str]:
    """The bytes the component was asked to transmit, from the bus, not the peer.

    Mirrors the SPI criterion: the expectation is the accepted CPU write to the
    component's declared TXDATA address, and the declaration carries its own
    norm as the basis.  Without that declaration the data criterion is
    undecidable, so the caller reports a named ``not_assessed``.
    """
    contract = _mapping(_mapping(getattr(build, "uart_wire_contracts", {}))
                        .get(instance))
    if not contract or not str(contract.get("basis", "")):
        return (None,
                "uart-wire-expectation-missing: no independent component-side TXDATA "
                "register norm is declared", _WIRE_BASIS)
    try:
        address = _integer(contract.get("txdata_address"), "uart-txdata-address-invalid")
    except PeerOracleError as error:
        return None, f"uart-wire-expectation-missing: {error}", _WIRE_BASIS
    cpu_sources = tuple(getattr(build, "cpu_data_sources", ()) or ())
    if not cpu_sources:
        return (None,
                "uart-wire-expectation-missing: CPU data source ownership is not "
                "recorded", _WIRE_BASIS)
    if bool(getattr(result, "requests_truncated", False)):
        return (None,
                "uart-wire-expectation-missing: the accepted CPU write trace is "
                "truncated", _WIRE_BASIS)
    writes = [item for item in getattr(result, "requests", ()) or ()
              if isinstance(item, Mapping) and int(item.get("addr", -1)) == address
              and int(item.get("write", 0)) == 1
              and int(item.get("source", -1)) in cpu_sources]
    if not writes:
        return (None,
                "uart-wire-expectation-missing: no accepted CPU write to the declared "
                "TXDATA address is recorded", _WIRE_BASIS)
    required = (1 << ((width + 7) // 8)) - 1
    if any(int(item.get("be", 0)) & required != required for item in writes):
        return (None,
                "uart-wire-expectation-missing: the TXDATA byte enables do not cover "
                "the word", _WIRE_BASIS)
    return ([int(item["wdata"]) & ((1 << width) - 1) for item in writes], "",
            str(contract["basis"]))


def _uart_wire_checks(build: object, result: object, instance: str,
                      slot: Mapping[str, object]) -> tuple[list[dict[str, object]],
                                                           list[dict[str, object]]]:
    """The UART frame criteria for one slot, or the named gap blocking them."""
    def gap(reason: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        return ([], [{"check_id": check_id, "reason": reason}
                     for check_id in _UART_WIRE_CHECKS] +
                [{"check_id": "uart-timeout-wire",
                  "reason": "no per-cycle component-to-peer UART line samples are "
                            "recorded, so an idle window cannot be measured"}])

    rows = [item for item in getattr(result, "peer_wire_trace", ()) or ()
            if isinstance(item, Mapping) and
            str(item.get("instance_id", "")) == instance and
            ("line" in item or "uart_tx" in item)]
    statuses = [item for item in getattr(result, "peer_wire_status", ()) or ()
                if isinstance(item, Mapping) and
                str(item.get("instance_id", "")) == instance]
    if not rows and not statuses:
        return gap("no per-cycle component-to-peer UART line samples are recorded "
                   "(runtime environment gap)")
    complete = False
    if len(statuses) == 1:
        try:
            complete = (not bool(statuses[0].get("truncated")) and
                        int(statuses[0].get("count", -1)) == len(rows))
        except (TypeError, ValueError):
            complete = False
    if not complete:
        return gap("the UART line trace is missing, truncated or incomplete")
    parameters = _mapping(slot.get("parameters", {}))
    try:
        width = int(parameters["DATA_WIDTH"])
        expected, expectation_reason, expectation_basis = _uart_wire_expected_bytes(
            build, result, instance, width)
    except (KeyError, TypeError, ValueError, PeerOracleError) as error:
        return gap(f"uart-wire-expectation-missing: {error}")
    try:
        verdict = uart_wire_expectation(
            rows, expected_bytes=expected, data_width=width,
            baud_div=int(parameters["BAUD_DIV"]),
            stop_bits=int(parameters["STOP_BITS"]),
            idle_level=int(parameters.get("IDLE_LEVEL", 1)))
    except (KeyError, TypeError, ValueError, PeerOracleError) as error:
        return gap(f"uart-wire-mode-unsupported: {error}")
    checks: list[dict[str, object]] = []
    unassessed: list[dict[str, object]] = []
    for criterion in verdict["criteria"]:
        check_id = str(criterion["check_id"])
        if criterion["status"] == "not_assessed":
            reason = str(criterion["reason"])
            if check_id == "uart-rx-wire" and expected is None and expectation_reason:
                reason = expectation_reason
            unassessed.append({"check_id": check_id, "reason": reason})
            continue
        checks.append(_check(check_id, str(criterion["status"]),
                             expected=criterion["expected"],
                             observed=criterion["observed"],
                             basis=(expectation_basis if check_id == "uart-rx-wire"
                                    else _WIRE_BASIS),
                             note=str(criterion["reason"])))
    unassessed.append({"check_id": "uart-timeout-wire",
                       "reason": "the idle window is not measured against the declared "
                                 "timeout"})
    return checks, unassessed


def _counter_value(build: object, result: object, instance: str,
                   peer_port: str) -> int | None:
    counters = _mapping(getattr(result, "counters", {}))
    key = f"peer.{instance}.{peer_port}"
    value = counters.get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    observations = _mapping(getattr(result, "observations", {}))
    for item in getattr(build, "peer_observations", ()) or ():
        if not isinstance(item, Mapping):
            continue
        if (str(item.get("instance_id", "")) == instance and
                str(item.get("peer_port", "")) == peer_port):
            observed = observations.get(str(item.get("name", "")))
            if isinstance(observed, int) and not isinstance(observed, bool):
                return int(observed)
    return None


def _check(check_id: str, status: str, *, expected: object = None,
           observed: object = None, basis: str = _BASIS,
           note: str = "") -> dict[str, object]:
    return {"check_id": check_id, "status": status, "expected": expected,
            "observed": observed, "basis": basis, "note": note}


def _source_identity(records: Sequence[Mapping[str, object]]) -> tuple[dict[str, object], ...]:
    seen: dict[tuple[str, str], dict[str, object]] = {}
    for item in records:
        key = (str(item.get("instance_id", "")), str(item.get("peer_id", "")))
        if key in seen:
            continue
        record = {
            "instance_id": key[0],
            "peer_id": key[1],
            "module": str(item.get("peer_module", item.get("module", ""))),
            "source": str(item.get("peer_source", item.get("source", ""))),
            "source_hash": item.get("peer_source_hash"),
            "protocol": list(item.get("peer_protocol", item.get("protocol", ())) or ()),
            "parameters": dict(sorted(_mapping(item.get("parameters", {})).items())),
        }
        seen[key] = record
    return tuple(seen[key] for key in sorted(seen))


def _oracle_hash(document: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()


def audit_peer_run(build: object, sample: object, result: object) -> dict[str, object]:
    """Audit the peer portion of one runtime result.

    The audit is fail-closed for the evidence it can see: the applied event
    list and observable UART transmitter drop count must agree.  It is explicit
    about the rest of the peer contract, because the current runtime records
    final counters but not component-to-peer wire waveforms.
    """
    slots = _slot_records(build)
    if not slots:
        document: dict[str, object] = {
            "schema_version": PEER_ORACLE_SCHEMA,
            "status": "not-applicable",
            "models": [], "checks": [], "unassessed": [],
        }
        document["oracle_hash"] = _oracle_hash(document)
        return document
    by_index = {int(item.get("index", index)): item
                for index, item in enumerate(slots)}
    expected_events: list[tuple[int, str, str, int]] = []
    unknown_events: list[dict[str, object]] = []
    for event in getattr(sample, "peer_events", ()) or ():
        index = _integer(_event_value(event, "slot"), "peer-event-slot-invalid")
        cycle = _integer(_event_value(event, "cycle"), "peer-event-cycle-invalid")
        payload = _integer(_event_value(event, "payload", 0),
                           "peer-event-payload-invalid")
        slot = by_index.get(index)
        if slot is None:
            unknown_events.append({"slot": index, "cycle": cycle, "payload": payload})
            continue
        expected_events.append((cycle, str(slot.get("instance_id", "")),
                               str(slot.get("slot", "")), payload))
    expected_events.sort(key=lambda item: (item[0], item[1], item[2]))
    observed_events: list[tuple[int, str, str, int]] = []
    for item in getattr(result, "peer_applied", ()) or ():
        if not isinstance(item, Mapping):
            continue
        observed_events.append((int(item.get("cycle", 0)), str(item.get("instance", "")),
                                str(item.get("slot", "")),
                                int(item.get("value", item.get("payload", 0)))))
    observed_events.sort(key=lambda item: (item[0], item[1], item[2]))
    transport_expected: object = expected_events
    if unknown_events:
        transport_expected = {"known": expected_events, "unknown": unknown_events}
    checks = [_check("peer-event-transport",
                     "pass" if not unknown_events and expected_events == observed_events
                     else "mismatch",
                     expected=transport_expected, observed=observed_events,
                     note="declared payload events must be reported at the same cycle")]
    unassessed: list[dict[str, object]] = []
    result_cycles = _integer(getattr(result, "cycles", 0), "peer-result-cycles-invalid")
    events_by_slot: dict[int, list[dict[str, int]]] = {}
    for event in getattr(sample, "peer_events", ()) or ():
        index = _integer(_event_value(event, "slot"), "peer-event-slot-invalid")
        events_by_slot.setdefault(index, []).append({
            "cycle": _integer(_event_value(event, "cycle"), "peer-event-cycle-invalid"),
            "payload": _integer(_event_value(event, "payload", 0),
                                 "peer-event-payload-invalid"),
        })
    for index, slot in sorted(by_index.items()):
        peer_id = str(slot.get("peer_id", ""))
        instance = str(slot.get("instance_id", ""))
        parameters = _mapping(slot.get("parameters", {}))
        if peer_id == "uart" and str(slot.get("slot", "")) == "uart.tx_byte":
            try:
                width = int(parameters["DATA_WIDTH"])
                divisor = int(parameters["BAUD_DIV"])
                stops = int(parameters["STOP_BITS"])
            except (KeyError, TypeError, ValueError) as error:
                checks.append(_check("uart-contract", "mismatch", observed=str(error),
                                     note="slot parameters are insufficient for the independent contract"))
                continue
            try:
                expectation, basis, message = _uart_expectation_source(
                    build, sample, result, slot, events_by_slot.get(index, ()),
                    cycles=result_cycles, data_width=width, baud_div=divisor,
                    stop_bits=stops)
            except (KeyError, TypeError, ValueError, PeerOracleError) as error:
                checks.append(_check(
                    "uart-contract", "mismatch", observed=str(error),
                    note="the declared plan is insufficient for the independent contract"))
                continue
            if expectation is None:
                unassessed.append({"check_id": "uart-tx-drop-count",
                                   "reason": message})
                unassessed.append({"check_id": "uart-tx-sent-count",
                                   "reason": message})
            else:
                observed_drop = _counter_value(build, result, instance,
                                               "tx_drop_count_o")
                if observed_drop is None:
                    unassessed.append({"check_id": "uart-tx-drop-count",
                                       "reason": "runtime did not expose tx_drop_count_o"})
                else:
                    checks.append(_check(
                        "uart-tx-drop-count",
                        "pass" if observed_drop == expectation["drop_count"] else "mismatch",
                        expected=expectation["drop_count"], observed=observed_drop,
                        basis=basis, note=message))
                sent = _counter_value(build, result, instance, "tx_sent_count_o")
                if sent is None:
                    unassessed.append({"check_id": "uart-tx-sent-count",
                                       "reason": "runtime did not expose tx_sent_count_o"})
                elif result_cycles >= int(expectation["required_completion_cycles"]):
                    checks.append(_check(
                        "uart-tx-sent-count",
                        "pass" if sent == expectation["completed_count"] else "mismatch",
                        expected=expectation["completed_count"], observed=sent,
                        basis=basis, note=message))
                else:
                    unassessed.append({"check_id": "uart-tx-sent-count",
                                       "reason": "run window ends before all accepted frames can complete"})
            frame_checks, frame_unassessed = _uart_wire_checks(build, result,
                                                               instance, slot)
            checks.extend(frame_checks)
            unassessed.extend(frame_unassessed)
        elif peer_id == "spi":
            contract = _mapping(_mapping(getattr(build, "spi_wire_contracts", {}))
                                .get(instance))
            status_rows = [item for item in
                           getattr(result, "peer_wire_status", ()) or ()
                           if isinstance(item, Mapping) and
                           str(item.get("instance_id")) == instance]
            trace = [item for item in getattr(result, "peer_wire_trace", ()) or ()
                     if isinstance(item, Mapping) and
                     str(item.get("instance_id")) == instance]
            if not contract or not str(contract.get("basis", "")):
                unassessed.append({"check_id": "spi-transfer-wire",
                                   "reason": "independent SPI TXDATA register norm is missing"})
                continue
            if len(status_rows) != 1 or bool(status_rows[0].get("truncated")) or \
                    int(status_rows[0].get("count", -1)) != len(trace):
                unassessed.append({"check_id": "spi-transfer-wire",
                                   "reason": "SPI wire trace is missing, truncated or incomplete"})
                continue
            if bool(getattr(result, "requests_truncated", False)):
                unassessed.append({"check_id": "spi-transfer-wire",
                                   "reason": "accepted CPU write trace is truncated"})
                continue
            try:
                address = _integer(contract.get("txdata_address"),
                                   "spi-txdata-address-invalid")
                cpu_sources = tuple(getattr(build, "cpu_data_sources", ()) or ())
                if not cpu_sources:
                    unassessed.append({"check_id": "spi-transfer-wire",
                                       "reason": "CPU data source ownership is not recorded"})
                    continue
                writes = [item for item in getattr(result, "requests", ()) or ()
                          if isinstance(item, Mapping) and
                          int(item.get("addr", -1)) == address and
                          int(item.get("write", 0)) == 1 and
                          int(item.get("source", -1)) in cpu_sources]
                if not writes:
                    unassessed.append({"check_id": "spi-transfer-wire",
                                       "reason": "accepted CPU TXDATA write is not recorded"})
                    continue
                arms = list(events_by_slot.get(index, ()))
                if len(writes) != 1 or len(arms) != 1:
                    unassessed.append({"check_id": "spi-transfer-wire",
                                       "reason": "only one accepted write and one peer arm are supported"})
                    continue
                width = int(parameters["BITS"])
                required_be = (1 << ((width + 7) // 8)) - 1
                if int(writes[0].get("be", 0)) & required_be != required_be:
                    unassessed.append({"check_id": "spi-transfer-wire",
                                       "reason": "CPU TXDATA byte enables do not cover the word"})
                    continue
                inactive = int(parameters["CS_ACTIVE_LOW"])
                selected_cycles = [int(item["cycle"]) for item in trace
                                   if item.get("cs") in (1 - inactive,
                                                         str(1 - inactive))]
                if selected_cycles and (int(writes[0].get("cycle", -1)) >=
                                        min(selected_cycles) or
                                        int(arms[0]["cycle"]) >= min(selected_cycles)):
                    unassessed.append({"check_id": "spi-transfer-wire",
                                       "reason": "CPU write or peer arm did not precede selection"})
                    continue
                expected_mosi = [int(item["wdata"]) & ((1 << width) - 1)
                                 for item in writes]
                expected_miso = [int(item["payload"]) & ((1 << width) - 1)
                                 for item in arms]
                verdict = spi_wire_expectation(
                    trace, bits=width, cpol=int(parameters["CPOL"]),
                    cpha=int(parameters["CPHA"]),
                    cs_active_low=int(parameters["CS_ACTIVE_LOW"]),
                    mosi_words=expected_mosi, miso_words=expected_miso)
            except (KeyError, TypeError, ValueError, PeerOracleError) as error:
                unassessed.append({"check_id": "spi-transfer-wire",
                                   "reason": f"SPI contract evidence invalid: {error}"})
                continue
            if verdict["status"] == "not_assessed":
                unassessed.append({"check_id": "spi-transfer-wire",
                                   "reason": verdict["reason"]})
            else:
                checks.append(_check("spi-transfer-wire", str(verdict["status"]),
                                     expected={"mosi": expected_mosi,
                                               "miso": expected_miso},
                                     observed={"mosi": verdict["observed_mosi_words"],
                                               "miso": verdict["observed_miso_words"]},
                                     basis=str(contract["basis"]),
                                     note=str(verdict["reason"])))
        elif peer_id == "gpio":
            unassessed.append({"check_id": "gpio-resolution-wire",
                               "reason": "component direction/output waveform is not recorded"})
        else:
            unassessed.append({"check_id": f"{peer_id or 'unknown'}-behaviour",
                               "reason": "no independent contract adapter is registered"})
    status = "mismatch" if any(item["status"] == "mismatch" for item in checks) else "pass"
    document = {
        "schema_version": PEER_ORACLE_SCHEMA,
        "status": status,
        "models": list(_source_identity(slots)),
        "checks": checks,
        "unassessed": unassessed,
    }
    document["oracle_hash"] = _oracle_hash(document)
    return document


__all__ = [
    "PEER_ORACLE_SCHEMA",
    "PeerOracleError",
    "audit_peer_run",
    "gpio_resolution",
    "spi_wire_expectation",
    "uart_raw_expectation",
    "uart_tx_expectation",
    "uart_wire_expectation",
]
