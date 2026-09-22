"""Decode the peer portion of the profile RFuzz ABI into replay evidence.

The profile campaign drives peer request ports as ordinary per-cycle raw
fields.  That is the correct input boundary for RFuzz, but a raw integer alone
does not say which declared peer slot fired.  This module is the small,
deterministic bridge between those two views:

* pulse slots become one event at every asserted pulse, with their payload;
* level slots become an event when their packed payload changes (including a
  transition back to zero), because the level is held until the next event;
* the declared minimum spacing is checked before an event record is accepted.

The decoder never schedules or mutates a signal.  It only reads the compiled
layout and slot contract, so the resulting records can be stored beside a raw
corpus and compared during replay.  It deliberately does not model electrical
contention, CDC, framing, or any other peer behaviour.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from myfuzz.contracts import canonical_bytes


PEER_RAW_REPLAY_SCHEMA = "soc_peer_raw_replay.v1"


class PeerRawReplayError(ValueError):
    """The raw peer ABI cannot be decoded under the declared slot contract."""


def _error(reason: str) -> None:
    raise PeerRawReplayError(reason)


def _fields(layout: object) -> dict[str, object]:
    records = getattr(layout, "fields", ())
    result: dict[str, object] = {}
    for field in records:
        port = getattr(field, "port", None)
        if isinstance(port, str) and port:
            result[port] = field
    return result


def _integer(value: object, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _error(reason)
    return int(value)


def _signal_record(signal: object, fields: Mapping[str, object],
                   instance: str, slot: str) -> dict[str, object]:
    if not isinstance(signal, Mapping):
        _error(f"peer-replay-signal-invalid:{instance}:{slot}")
    top_port = signal.get("top_port", signal.get("port"))
    if not isinstance(top_port, str) or not top_port:
        _error(f"peer-replay-signal-port-missing:{instance}:{slot}")
    source = signal.get("source")
    if not isinstance(source, str) or source not in {
            "pulse", "payload", "payload_low", "payload_high"}:
        _error(f"peer-replay-signal-source-invalid:{instance}:{slot}:{source}")
    field = fields.get(top_port)
    if field is None:
        _error(f"peer-replay-layout-field-missing:{instance}:{slot}:{top_port}")
    raw_lo = _integer(signal.get("raw_lo", getattr(field, "raw_lo", -1)),
                      f"peer-replay-raw-offset-invalid:{instance}:{slot}:{top_port}")
    width = _integer(signal.get("width", getattr(field, "width", 0)),
                     f"peer-replay-width-invalid:{instance}:{slot}:{top_port}")
    field_width = _integer(getattr(field, "width", 0),
                           f"peer-replay-layout-width-invalid:{instance}:{slot}:{top_port}")
    if width <= 0 or raw_lo < 0 or width != field_width:
        _error(f"peer-replay-layout-width-mismatch:{instance}:{slot}:{top_port}")
    return {
        "top_port": top_port,
        "peer_port": str(signal.get("peer_port", "")),
        "source": source,
        "width": width,
        "raw_lo": raw_lo,
    }


def _slot_record(slot: object, fields: Mapping[str, object], index: int) -> dict[str, object]:
    if not isinstance(slot, Mapping):
        _error(f"peer-replay-slot-invalid:{index}")
    instance = slot.get("instance_id")
    name = slot.get("slot")
    if not isinstance(instance, str) or not instance or not isinstance(name, str) or not name:
        _error(f"peer-replay-slot-identity-invalid:{index}")
    signals = slot.get("signals", ())
    if isinstance(signals, (str, bytes)) or not isinstance(signals, Sequence):
        _error(f"peer-replay-signals-invalid:{instance}:{name}")
    resolved = [_signal_record(item, fields, instance, name) for item in signals]
    # Older callers passed only pulse_ports to the projector.  Keep decoding
    # fail-closed for those records: spacing validation still works in the
    # projector, but no semantic event can be fabricated without payload bits.
    for port in slot.get("pulse_ports", ()) or ():
        if not any(item["top_port"] == port for item in resolved):
            field = fields.get(str(port))
            if field is None:
                _error(f"peer-replay-layout-field-missing:{instance}:{name}:{port}")
            resolved.append(_signal_record({"top_port": str(port), "source": "pulse",
                                            "width": getattr(field, "width", 0)},
                                           fields, instance, name))
    width = _integer(slot.get("width", 0), f"peer-replay-slot-width-invalid:{instance}:{name}")
    minimum = _integer(slot.get("minimum_gap_cycles", 0),
                       f"peer-replay-minimum-gap-invalid:{instance}:{name}")
    if width < 0 or minimum < 0:
        _error(f"peer-replay-slot-contract-invalid:{instance}:{name}")
    return {
        "index": _integer(slot.get("index", index), f"peer-replay-slot-index-invalid:{instance}:{name}"),
        "instance_id": instance,
        "peer_id": str(slot.get("peer_id", "")),
        "peer_source": str(slot.get("peer_source", "")),
        "peer_source_hash": (None if slot.get("peer_source_hash") in (None, "")
                              else str(slot.get("peer_source_hash"))),
        "peer_module": str(slot.get("peer_module", "")),
        "peer_protocol": tuple(str(item) for item in slot.get("peer_protocol", ()) or ()),
        "slot": name,
        "kind": str(slot.get("kind", "")),
        "width": width,
        "minimum_gap_cycles": minimum,
        "signals": tuple(resolved),
    }


def _value(raw: int, signal: Mapping[str, object]) -> int:
    width = int(signal["width"])
    return (raw >> int(signal["raw_lo"])) & ((1 << width) - 1)


def _payload(slot: Mapping[str, object], raw: int) -> tuple[int, dict[str, int]]:
    values: dict[str, int] = {}
    payload = 0
    low_width = None
    high_width = None
    for signal in slot["signals"]:  # type: ignore[union-attr]
        source = str(signal["source"])
        value = _value(raw, signal)
        values[str(signal["top_port"])] = value
        if source == "payload":
            payload |= value
        elif source == "payload_low":
            payload |= value
            low_width = int(signal["width"])
        elif source == "payload_high":
            high_width = int(signal["width"])
            payload |= value << int(low_width or high_width)
    # A model with only a high half is still unambiguous: its low half is zero.
    if high_width is not None and low_width is None:
        payload = next((value << high_width for signal, value in values.items()
                        if any(item["top_port"] == signal
                               and item["source"] == "payload_high"
                               for item in slot["signals"])), payload)
    return payload, values


def decode_peer_raw_events(values: Sequence[int], layout: object,
                           peer_slots: Sequence[Mapping[str, object]], *,
                           validate_spacing: bool = True) -> tuple[dict[str, object], ...]:
    """Decode a per-cycle raw sequence into declared peer event records.

    The result is sorted by cycle and slot index.  ``validate_spacing=False``
    is useful for the direct-input comparison arm: it records an invalid raw
    sequence without turning that arm into a constrained projection.  The
    constrained arms leave validation enabled and therefore fail before RTL
    execution when a pulse would be dropped by the peer model.
    """
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not values:
        _error("peer-replay-raw-sequence-invalid")
    raw_width = getattr(layout, "raw_width", None)
    if isinstance(raw_width, bool) or not isinstance(raw_width, int) or raw_width < 0:
        _error("peer-replay-layout-width-invalid")
    fields = _fields(layout)
    slots = tuple(_slot_record(item, fields, index)
                  for index, item in enumerate(peer_slots))
    events: list[dict[str, object]] = []
    last: dict[tuple[str, str], int] = {}
    previous_level: dict[tuple[str, str], int] = {}
    for cycle, value in enumerate(values):
        raw = _integer(value, f"peer-replay-raw-value-invalid:{cycle}")
        if raw < 0 or raw >= (1 << raw_width):
            _error(f"peer-replay-raw-value-out-of-range:{cycle}:{raw}")
        for slot in slots:
            payload, signal_values = _payload(slot, raw)
            width = int(slot["width"])
            if width and payload >= (1 << width):
                _error(f"peer-event-payload-out-of-range:{slot['slot']}:{payload}"
                       f"!<{1 << width}")
            signals = slot["signals"]
            pulse = any(str(item["source"]) == "pulse" and
                        signal_values.get(str(item["top_port"]), 0)
                        for item in signals)
            key = (str(slot["instance_id"]), str(slot["slot"]))
            if pulse:
                fire = True
            elif (not any(str(item["source"]) == "pulse" for item in signals)
                  and any(str(item["source"]) in ("payload", "payload_low", "payload_high")
                          for item in signals)):
                # Level slots carry state, not a pulse.  Only transitions need
                # an event record; a cycle-0 nonzero value is the initial drive.
                fire = payload != previous_level.get(key, 0)
            else:
                fire = False
            previous_level[key] = payload
            if not fire:
                continue
            prior = last.get(key)
            minimum = int(slot["minimum_gap_cycles"])
            if validate_spacing and prior is not None and cycle - prior < minimum:
                _error(f"peer-event-gap-violation:{slot['instance_id']}:{slot['slot']}:"
                       f"{cycle}-{prior}<{minimum}")
            last[key] = cycle
            events.append({
                "schema_version": PEER_RAW_REPLAY_SCHEMA,
                "index": int(slot["index"]),
                "instance_id": str(slot["instance_id"]),
                "peer_id": str(slot["peer_id"]),
                "peer_source": str(slot["peer_source"]),
                "peer_source_hash": slot["peer_source_hash"],
                "peer_module": str(slot["peer_module"]),
                "peer_protocol": list(slot["peer_protocol"]),
                "slot": str(slot["slot"]),
                "kind": str(slot["kind"]),
                "cycle": cycle,
                "payload": payload,
                "minimum_gap_cycles": minimum,
                "signals": dict(sorted(signal_values.items())),
            })
    return tuple(sorted(events, key=lambda item: (int(item["cycle"]),
                                                   int(item["index"]))))


def peer_event_hash(events: Sequence[Mapping[str, object]]) -> str:
    """Hash the decoded event records for a replay identity/document."""
    return "sha256:" + hashlib.sha256(canonical_bytes([
        {str(key): value for key, value in sorted(dict(item).items())}
        for item in events])).hexdigest()


__all__ = [
    "PEER_RAW_REPLAY_SCHEMA",
    "PeerRawReplayError",
    "decode_peer_raw_events",
    "peer_event_hash",
]
