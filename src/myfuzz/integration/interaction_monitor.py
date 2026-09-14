"""Observer-only matching for bounded CPU/peripheral interaction chains.

The monitor consumes trace events; it never supplies a value back to RTL.  A
valid interaction is an environment event (A), the corresponding real IRQ,
the CPU ISR marker, and a later accepted CPU-mediated transaction (B).
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Sequence
from typing import Any


EVENT_FIELDS = (
    "test_id",
    "cycle",
    "source_id",
    "target_id",
    "transaction_id",
    "kind",
    "value",
)


class InteractionMonitorError(ValueError):
    """Malformed trace or a required interaction ordering failure."""


@dataclass(frozen=True, slots=True)
class InteractionEvent:
    test_id: str
    cycle: int
    source_id: str
    target_id: str
    transaction_id: str
    kind: str
    value: Any

    def __post_init__(self) -> None:
        for name in ("test_id", "source_id", "target_id", "transaction_id", "kind"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise InteractionMonitorError(f"event:{name}")
        if isinstance(self.cycle, bool) or not isinstance(self.cycle, int) or self.cycle < 0:
            raise InteractionMonitorError("event:cycle")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "InteractionEvent":
        if not isinstance(value, Mapping) or set(value) != set(EVENT_FIELDS):
            raise InteractionMonitorError("event:fields")
        return cls(**{field: value[field] for field in EVENT_FIELDS})

    def as_tuple(self) -> tuple:
        return (
            self.test_id,
            self.cycle,
            self.source_id,
            self.target_id,
            self.transaction_id,
            self.kind,
            self.value,
        )

    def as_mapping(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in EVENT_FIELDS}


def _coerce_events(events: Sequence[InteractionEvent | Mapping[str, object]]) -> list[InteractionEvent]:
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        raise InteractionMonitorError("events:sequence")
    result: list[InteractionEvent] = []
    last_cycle: dict[str, int] = {}
    for value in events:
        event = value if isinstance(value, InteractionEvent) else InteractionEvent.from_mapping(value)
        previous = last_cycle.get(event.test_id)
        if previous is not None and event.cycle < previous:
            raise InteractionMonitorError("cycle:not-monotonic")
        last_cycle[event.test_id] = event.cycle
        result.append(event)
    return result


def evaluate_interactions(
    events: Sequence[InteractionEvent | Mapping[str, object]],
    expectations: Mapping[str, object] | None = None,
    *,
    a_kind: str = "environment",
    irq_kind: str = "irq",
    isr_kind: str = "cpu_isr",
    b_kind: str = "transaction_accepted",
    reset_kind: str = "reset",
    max_latency: int = 64,
    raise_on_error: bool = False,
) -> dict[str, object]:
    """Match all A->IRQ->ISR->B chains without unbounded search."""
    if expectations is not None:
        if not isinstance(expectations, Mapping):
            raise InteractionMonitorError("expectations:mapping")
        aliases = {
            "a": "a_kind", "irq": "irq_kind", "isr": "isr_kind",
            "b": "b_kind", "reset": "reset_kind", "max_cycles": "max_latency",
        }
        values = dict(expectations)
        for short, long_name in aliases.items():
            nested = values.get(short)
            if isinstance(nested, Mapping) and "kind" in nested:
                values[long_name] = nested["kind"]
        for name in ("a_kind", "irq_kind", "isr_kind", "b_kind", "reset_kind"):
            if name in values:
                value = values[name]
                if not isinstance(value, str) or not value:
                    raise InteractionMonitorError(f"expectations:{name}")
                if name == "a_kind":
                    a_kind = value
                elif name == "irq_kind":
                    irq_kind = value
                elif name == "isr_kind":
                    isr_kind = value
                elif name == "b_kind":
                    b_kind = value
                else:
                    reset_kind = value
        if "max_latency" in values:
            max_latency = values["max_latency"]  # validated below
    if not isinstance(max_latency, int) or isinstance(max_latency, bool) or max_latency < 1:
        raise InteractionMonitorError("max_latency")
    try:
        trace = _coerce_events(events)
    except InteractionMonitorError as error:
        if raise_on_error:
            raise
        return {"ok": False, "chains": [], "errors": [str(error)]}

    pending: list[dict[str, object]] = []
    chains: list[dict[str, object]] = []
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    for event in trace:
        if event.kind == reset_kind and bool(event.value):
            affected = [item for item in pending if item["a"].test_id == event.test_id]
            for item in affected:
                fail(f"reset-cleared:{item['a'].transaction_id}")
            pending = [item for item in pending if item["a"].test_id != event.test_id]
            continue
        if event.kind == a_kind:
            pending.append({"a": event, "irq": None, "isr": None})
            continue

        for item in list(pending):
            a = item["a"]
            if event.test_id != a.test_id:
                continue
            last = item["isr"] or item["irq"] or a
            if event.cycle - last.cycle > max_latency:
                fail(f"latency:{a.transaction_id}:{last.kind}->{event.kind}")
                pending.remove(item)
                continue

            if item["irq"] is None and event.kind == irq_kind:
                if event.source_id != a.target_id:
                    fail(f"source:irq:{a.transaction_id}:{event.source_id}")
                    continue
                if event.transaction_id != a.transaction_id:
                    fail(f"transaction:irq:{a.transaction_id}:{event.transaction_id}")
                    continue
                item["irq"] = event
                break

            if item["irq"] is not None and item["isr"] is None and event.kind == isr_kind:
                irq = item["irq"]
                if event.source_id != irq.target_id:
                    fail(f"source:isr:{a.transaction_id}:{event.source_id}")
                    continue
                if event.transaction_id != irq.transaction_id:
                    fail(f"transaction:isr:{a.transaction_id}:{event.transaction_id}")
                    continue
                item["isr"] = event
                break

            if item["isr"] is not None and event.kind == b_kind:
                isr = item["isr"]
                if event.source_id != isr.target_id:
                    fail(f"source:transaction:{a.transaction_id}:{event.source_id}")
                    continue
                completed = {
                    "test_id": a.test_id,
                    "transaction_id": a.transaction_id,
                    "events": [a.as_mapping(), item["irq"].as_mapping(),
                               isr.as_mapping(), event.as_mapping()],
                    "latencies": {
                        "a_to_irq": item["irq"].cycle - a.cycle,
                        "irq_to_isr": isr.cycle - item["irq"].cycle,
                        "isr_to_b": event.cycle - isr.cycle,
                        "total": event.cycle - a.cycle,
                    },
                }
                chains.append(completed)
                pending.remove(item)
                break

    for item in pending:
        a = item["a"]
        if item["irq"] is None:
            fail(f"missing:{irq_kind}:{a.transaction_id}")
        elif item["isr"] is None:
            fail(f"missing:{isr_kind}:{a.transaction_id}")
        else:
            fail(f"missing:{b_kind}:{a.transaction_id}")

    result = {"ok": not errors, "chains": chains, "errors": errors}
    if raise_on_error and errors:
        raise InteractionMonitorError(errors[0])
    return result


def diff_replay(
    baseline: Sequence[InteractionEvent | Mapping[str, object]],
    variant: Sequence[InteractionEvent | Mapping[str, object]],
    expectations: Mapping[str, object] | None = None,
    *,
    a_kind: str = "environment",
    **kwargs: object,
) -> dict[str, object]:
    """Compare two replays while requiring all non-A trace inputs to match."""
    base = _coerce_events(baseline)
    other = _coerce_events(variant)
    base_a = [event.as_tuple() for event in base if event.kind == a_kind]
    other_a = [event.as_tuple() for event in other if event.kind == a_kind]
    base_fixed = [event.as_tuple() for event in base if event.kind != a_kind]
    other_fixed = [event.as_tuple() for event in other if event.kind != a_kind]
    fixed_unchanged = base_fixed == other_fixed
    return {
        "changed": bool(base_a != other_a and fixed_unchanged),
        "fixed_inputs_unchanged": fixed_unchanged,
        "baseline": evaluate_interactions(base, expectations, a_kind=a_kind, **kwargs),
        "variant": evaluate_interactions(other, expectations, a_kind=a_kind, **kwargs),
    }


__all__ = [
    "EVENT_FIELDS",
    "InteractionEvent",
    "InteractionMonitorError",
    "diff_replay",
    "evaluate_interactions",
]
