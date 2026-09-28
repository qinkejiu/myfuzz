"""Bounded pulse mapping for a single observed RTL IRQ source."""

from __future__ import annotations


class IrqPulseDelivery:
    """Map independent source rising edges to fixed CPU-local-tick pulses.

    ``masked`` is an optional observation supplied by the CPU harness. It is
    never inferred from IRQ input or from the absence of an ISR side effect.
    A second edge while the slot is occupied is retained and declared
    unsupported; it does not replace or extend the first pulse.
    """

    def __init__(self, *, width_ticks: int) -> None:
        if isinstance(width_ticks, bool) or not isinstance(width_ticks, int) \
                or not 1 <= width_ticks <= 4096:
            raise ValueError("IRQ pulse width must be in 1..4096 CPU ticks")
        self.width_ticks = width_ticks
        self.events: list[dict] = []
        self.status = "active"
        self.source_level = 0
        self._source_count = 0
        self._source_event_id: int | None = None
        self._active_source_event_id: int | None = None
        self._pulse_start: int | None = None
        self._pulse_end: int | None = None
        self._last_cpu_tick = 0
        self._all_masked = True
        self._masked_tick_count = 0

    def observe_source(self, level: int, *, source_tick: int, cpu_tick: int) -> None:
        if level not in (0, 1) or isinstance(level, bool):
            raise ValueError("IRQ source level must be one bit")
        if source_tick < 0 or cpu_tick < self._last_cpu_tick:
            raise ValueError("IRQ local tick moved backwards")
        if level == self.source_level:
            return
        self.source_level = level
        if level == 0:
            self.events.append({"kind": "source_end", "source_tick": source_tick,
                                "cpu_tick": cpu_tick,
                                "source_event_id": self._source_event_id})
            self._source_event_id = None
            return
        self._source_count += 1
        source_id = self._source_count
        self._source_event_id = source_id
        self.events.append({"kind": "source_start", "source_tick": source_tick,
                            "cpu_tick": cpu_tick, "source_event_id": source_id})
        if self._pulse_end is not None and cpu_tick < self._pulse_end:
            self.status = "unsupported_irq_overrun"
            self.events.append({"kind": "irq_overrun", "source_tick": source_tick,
                                "cpu_tick": cpu_tick,
                                "source_event_id": source_id,
                                "active_source_event_id": self._active_source_event_id,
                                "policy": "terminate_unsupported"})
            return
        if self.status != "active":
            return
        self._active_source_event_id = source_id
        self._pulse_start = cpu_tick + 1
        self._pulse_end = self._pulse_start + self.width_ticks
        self._all_masked = True
        self._masked_tick_count = 0
        self.events.append({"kind": "pulse_start", "source_event_id": source_id,
                            "start_cpu_tick": self._pulse_start,
                            "end_cpu_tick_exclusive": self._pulse_end})

    def input_at(self, cpu_tick: int) -> int:
        if cpu_tick < self._last_cpu_tick:
            raise ValueError("CPU local tick moved backwards")
        return int(self._pulse_start is not None and self._pulse_end is not None
                   and self._pulse_start <= cpu_tick < self._pulse_end)

    @property
    def pending(self) -> bool:
        """Whether a CPU tick is still needed to deliver or expire this pulse."""
        return self._pulse_end is not None

    def sample_cpu(self, cpu_tick: int, *, masked: bool | None = None,
                   accepted: bool | None = None) -> int:
        if cpu_tick <= self._last_cpu_tick:
            raise ValueError("CPU local tick must advance")
        if masked is not None and not isinstance(masked, bool):
            raise ValueError("CPU mask observation must be boolean or unknown")
        if accepted is not None and not isinstance(accepted, bool):
            raise ValueError("CPU acceptance observation must be boolean or unknown")
        value = self.input_at(cpu_tick)
        if value and accepted is True:
            self.events.append({"kind": "cpu_irq_taken", "cpu_tick": cpu_tick,
                                "source_event_id": self._active_source_event_id})
        if self._pulse_end is not None and cpu_tick != self._last_cpu_tick + 1:
            self._all_masked = False
        if value:
            if masked is True:
                self._masked_tick_count += 1
            else:
                self._all_masked = False
        if self._pulse_end is not None and cpu_tick >= self._pulse_end:
            fully_masked = (self._all_masked
                            and self._masked_tick_count == self.width_ticks)
            self.events.append({"kind": "expired_masked" if fully_masked
                                else "pulse_expired",
                                "source_event_id": self._active_source_event_id,
                                "end_cpu_tick_exclusive": self._pulse_end,
                                "mask_observation": "masked" if fully_masked
                                else "unknown_or_unmasked"})
            self._active_source_event_id = None
            self._pulse_start = None
            self._pulse_end = None
        self._last_cpu_tick = cpu_tick
        return value

    def reset(self, *, cpu_tick: int) -> None:
        if self._pulse_end is not None:
            self.events.append({"kind": "pulse_cancelled_by_reset",
                                "source_event_id": self._active_source_event_id,
                                "cpu_tick": cpu_tick})
        self.source_level = 0
        self._source_event_id = None
        self._active_source_event_id = None
        self._pulse_start = None
        self._pulse_end = None
        self._last_cpu_tick = cpu_tick
        self._all_masked = True
        self._masked_tick_count = 0
        self.status = "active"

    def state_document(self) -> dict:
        return {"status": self.status, "source_level": self.source_level,
                "source_event_id": self._source_event_id,
                "active_source_event_id": self._active_source_event_id,
                "pulse_start_cpu_tick": self._pulse_start,
                "pulse_end_cpu_tick_exclusive": self._pulse_end,
                "last_cpu_tick": self._last_cpu_tick}
