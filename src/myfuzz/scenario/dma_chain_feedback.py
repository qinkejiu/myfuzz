"""Bounded event-level DMA chain feedback for the continuous RX search.

Everything here is derived from observed journal records inside one declared
event slice. These are *search features*, never authority: the per-case
``_case_evidence`` joins remain the only completed-chain certificate and the
raw ``fifo_origin`` field stays ``unknown``.

The vocabulary is frozen so a saved search bundle can be recomputed offline:
``DMA_FEATURES`` names the structural witnesses of the pinned attempt6 journal,
``FEATURE_BUCKET_PREFIXES``/``EXTRA_FEATURES`` name the bounded value and
diagnostic buckets a single-boot, single-byte search can actually observe.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Sequence


# Pinned profile facts (third_party/soc-opentitan/hw/ip/uart/rtl): STATUS offset
# 0x14 with RXEMPTY=bit5, RDATA offset 0x18. wbdmac status mcause is the real
# machine-external-interrupt code observed in the saved attempt6 evidence.
UART_STATUS_OFFSET = 0x14
UART_RXEMPTY_MASK = 1 << 5
UART_RDATA_OFFSET = 0x18
DMA_IRQ_MCAUSE = 0x8000000b
DEPTH_BUCKETS = 4

DMA_FEATURES = ("uart_frame_matched", "fifo_push", "fifo_cpu_pop", "fifo_dma_pop",
                "status_nonempty", "dma_master_read", "dma_master_write",
                "dma_irq_pulse", "cpu_irq_take", "isr_mcause", "isr_status",
                "isr_payload", "isr_counter", "env_error", "no_target_effect",
                "ram_commit_cpu", "ram_commit_dma", "tx_capture")

# Bounded bucket families. A key outside DMA_FEATURES must start with one of
# these prefixes, so a foreign key can never be smuggled into feedback.
FEATURE_BUCKET_PREFIXES = ("fifo_push_depth_", "dma_target_", "payload_")

# Diagnostic buckets that are deliberately not coverage claims.
EXTRA_FEATURES = ("fifo_pop_unattributed",)

DMA_TARGETS = ("uart.frame_matched", "uart.fifo_push", "uart.fifo_cpu_pop",
               "uart.fifo_dma_pop", "uart.status_nonempty", "dma.master_read",
               "dma.master_write", "dma.irq_pulse", "cpu.irq_take",
               "isr.mcause", "isr.status", "isr.payload", "isr.counter",
               "dma.env_error", "dma.no_target_effect", "ram.commit_cpu",
               "ram.commit_dma", "uart.tx_capture", "payload.value",
               "payload.class")

_FEATURE_TARGETS = {
    "uart_frame_matched": "uart.frame_matched",
    "fifo_push": "uart.fifo_push",
    "fifo_cpu_pop": "uart.fifo_cpu_pop",
    "fifo_dma_pop": "uart.fifo_dma_pop",
    "status_nonempty": "uart.status_nonempty",
    "dma_master_read": "dma.master_read",
    "dma_master_write": "dma.master_write",
    "dma_irq_pulse": "dma.irq_pulse",
    "cpu_irq_take": "cpu.irq_take",
    "isr_mcause": "isr.mcause",
    "isr_status": "isr.status",
    "isr_payload": "isr.payload",
    "isr_counter": "isr.counter",
    "env_error": "dma.env_error",
    "no_target_effect": "dma.no_target_effect",
    "ram_commit_cpu": "ram.commit_cpu",
    "ram_commit_dma": "ram.commit_dma",
    "tx_capture": "uart.tx_capture",
}


@dataclass(frozen=True)
class DmaChainFeatures:
    """Observed feature counts and chain status for one case slice."""

    features: dict[str, int]
    targets: tuple[str, ...]
    completed_chain: bool
    target_error: bool
    payloads: tuple[int, ...]


def is_declared_feature(key: str) -> bool:
    """Whether a feature key belongs to the frozen declared vocabulary."""
    return key in DMA_FEATURES or key in EXTRA_FEATURES or (
        isinstance(key, str) and key.startswith(FEATURE_BUCKET_PREFIXES))


def _slice(events: Sequence[dict], start: int, end: int) -> list[dict]:
    if not isinstance(events, (tuple, list)):
        raise ValueError("event slice must be a recorded sequence")
    if type(start) is not int or type(end) is not int:
        raise ValueError("event slice bounds must be integers")
    if start < 0 or end < start or end > len(events):
        raise ValueError("event slice bounds are outside the recorded prefix")
    return list(events[start:end])


def _int(value: object) -> bool:
    return type(value) is int


def _bump(counts: Counter, targets: set, key: str) -> None:
    counts[key] += 1
    target = _FEATURE_TARGETS.get(key)
    if target is not None:
        targets.add(target)


def _record_payload(counts: Counter, targets: set, payloads: list, value: object) -> None:
    """Record one observed data value and its bounded value-coverage buckets."""
    if not _int(value) or not 0 <= value <= 0xff:
        return
    payloads.append(value)
    counts[f"payload_{value:02x}"] += 1
    counts[f"payload_hi_nibble_{value >> 4}"] += 1
    counts[f"payload_lo_nibble_{value & 0xf}"] += 1
    counts[f"payload_popcount_{bin(value).count('1')}"] += 1
    if value == 0:
        counts["payload_zero"] += 1
    if value == 0xff:
        counts["payload_all_ones"] += 1
    if value & 0x80:
        counts["payload_high_bit"] += 1
    if 0x20 <= value <= 0x7e:
        counts["payload_ascii"] += 1
    targets.update(("payload.value", "payload.class"))


def _target_bucket(address: object, destination: int, uart_base: int) -> str:
    if not _int(address):
        return "other"
    if address == uart_base + UART_RDATA_OFFSET:
        return "uart_rdata"
    if uart_base <= address < uart_base + 0x1000:
        return "uart_window"
    if destination <= address < destination + 0x1000:
        return "ram"
    return "other"


def _pulse_observed(event: dict) -> bool:
    observations = event.get("payload", {}).get("observations", {})
    physical = observations.get("physical") if isinstance(observations, dict) else None
    return isinstance(physical, dict) and any(bool(value) for value in physical.values())


def _delivery_pop(event: dict, counts: Counter, targets: set,
                  pops: list[tuple], payloads: list) -> None:
    """One DMA-master UART1 RDATA read with a real FIFO pop witness."""
    accepted = event.get("accepted")
    if not isinstance(accepted, dict):
        return
    delivery = accepted.get("target_delivery")
    if not isinstance(delivery, dict):
        return
    transaction = delivery.get("source_transaction") or {}
    if transaction.get("channel_id") != "dma-memory":
        return
    access = delivery.get("target_uart_access")
    if not isinstance(access, dict):
        return
    pre = (access.get("read_capture") or {}).get("pre") or {}
    if pre.get("probe_uart_fifo_rdata_re") != 1:
        return
    _bump(counts, targets, "fifo_dma_pop")
    pops.append((event.get("event_id"), access.get("read_value")))
    _record_payload(counts, targets, payloads, access.get("read_value"))


def dma_chain_features(events: Sequence[dict], *, start: int, end: int,
                       destination: int, uart_base: int) -> DmaChainFeatures:
    """Summarize the declared event slice as bounded DMA chain features."""
    if not _int(destination) or destination < 0:
        raise ValueError("destination must be a nonnegative integer address")
    if not _int(uart_base) or uart_base < 0:
        raise ValueError("uart_base must be a nonnegative integer address")
    rows = _slice(events, start, end)
    counts: Counter = Counter()
    targets: set[str] = set()
    payloads: list[int] = []
    frames: list[dict] = []
    pops: list[tuple] = []
    writes: list[dict] = []
    pulses: list[dict] = []
    takes: list[dict] = []
    source_starts: list[dict] = []
    mcause = status_store = payload_store = counter_store = None
    for event in rows:
        if not isinstance(event, dict):
            raise ValueError("journal records must be objects")
        kind = event.get("kind")
        if kind == "uart_frame_validation":
            if event.get("waveform_matched") is True:
                _bump(counts, targets, "uart_frame_matched")
                frames.append(event)
                _record_payload(counts, targets, payloads, event.get("byte"))
        elif kind == "uart_tick_observation":
            post = event.get("post") or {}
            if (post.get("probe_uart_fifo_wvalid") == 1
                    and post.get("probe_uart_fifo_wready") == 1):
                _bump(counts, targets, "fifo_push")
                depth = post.get("probe_uart_fifo_depth")
                bucket = depth if _int(depth) and 1 <= depth <= DEPTH_BUCKETS else 0
                counts[f"fifo_push_depth_{bucket}"] += 1
                targets.add("uart.fifo_push")
        elif kind == "uart_rdata_access":
            pre = (event.get("read_capture") or {}).get("pre") or {}
            if pre.get("probe_uart_fifo_rdata_re") == 1:
                access = event.get("access") or {}
                transaction = access.get("source_transaction") or {}
                channel = transaction.get("channel_id")
                if channel == "data":
                    _bump(counts, targets, "fifo_cpu_pop")
                elif channel == "dma-memory":
                    _bump(counts, targets, "fifo_dma_pop")
                    _record_payload(counts, targets, payloads, event.get("read_value"))
                else:
                    # The pinned DMA master path reads RDATA without a routed
                    # transaction identity; keep that fact visible instead of
                    # reclassifying it as a CPU or certified DMA pop.
                    _bump(counts, targets, "fifo_pop_unattributed")
        elif kind == "mmio_delivery":
            if (event.get("device_id") == "uart"
                    and event.get("offset") == UART_STATUS_OFFSET
                    and event.get("write") is False
                    and _int(event.get("read_value"))
                    and not event["read_value"] & UART_RXEMPTY_MASK):
                _bump(counts, targets, "status_nonempty")
        elif kind == "dma_edge":
            accepted = event.get("accepted")
            payload = event.get("payload") or {}
            if _pulse_observed(event):
                _bump(counts, targets, "dma_irq_pulse")
                pulses.append(event)
            if _int(payload.get("error")) and payload["error"] == 1:
                _bump(counts, targets, "env_error")
            if isinstance(payload.get("environment_error_receipt"), dict):
                _bump(counts, targets, "env_error")
            if isinstance(accepted, dict):
                write = accepted.get("write")
                if isinstance(accepted.get("target_rejection"), (dict, list, str)):
                    _bump(counts, targets, "no_target_effect")
                elif write is True or write is False:
                    _bump(counts, targets,
                          "dma_master_write" if write is True else "dma_master_read")
                    counts[f"dma_target_{_target_bucket(accepted.get('address'),
                        destination, uart_base)}"] += 1
                    targets.add("dma.master_write" if write is True else "dma.master_read")
                _delivery_pop(event, counts, targets, pops, payloads)
        elif kind == "memory_write":
            component = event.get("component")
            value = event.get("value")
            if component == "dma" and event.get("address") == destination:
                _bump(counts, targets, "ram_commit_dma")
                writes.append(event)
                _record_payload(counts, targets, payloads, value)
            elif component == "cpu":
                _bump(counts, targets, "ram_commit_cpu")
                if mcause is None and value == DMA_IRQ_MCAUSE:
                    mcause = event
                    _bump(counts, targets, "isr_mcause")
                elif mcause is not None and status_store is None:
                    status_store = event
                    _bump(counts, targets, "isr_status")
                elif status_store is not None and payload_store is None:
                    payload_store = event
                    _bump(counts, targets, "isr_payload")
                elif payload_store is not None and counter_store is None:
                    counter_store = event
                    _bump(counts, targets, "isr_counter")
        elif kind == "source_start":
            if (tuple(event.get("source") or ()) == ("dma", "irq")
                    and tuple(event.get("target") or ()) == ("cpu", "irq")):
                source_starts.append(event)
        elif kind == "cpu_irq_taken":
            if (tuple(event.get("source") or ()) == ("dma", "irq")
                    and tuple(event.get("target") or ()) == ("cpu", "irq")):
                takes.append(event)
        elif kind == "uart_serial_tx_capture":
            _bump(counts, targets, "tx_capture")
            _record_payload(counts, targets, payloads, event.get("byte"))
    joined = [take for take in takes
              if any(take.get("source_event_id") == start_event.get("source_event_id")
                     for start_event in source_starts)]
    if joined:
        _bump(counts, targets, "cpu_irq_take")
    completed = _completed_chain(frames, pops, writes, pulses, joined,
                                 mcause, payload_store)
    return DmaChainFeatures(features=dict(sorted(counts.items())),
        targets=tuple(sorted(targets)), completed_chain=completed,
        target_error=bool(counts.get("env_error") or counts.get("no_target_effect")),
        payloads=tuple(payloads))


def _completed_chain(frames, pops, writes, pulses, takes, mcause, payload_store) -> bool:
    """Chain-level witness only; the per-case certificate stays authoritative."""
    if (len(frames) != 1 or len(pops) != 1 or len(writes) != 1
            or len(pulses) != 1 or len(takes) != 1
            or mcause is None or payload_store is None):
        return False
    byte = frames[0].get("byte")
    popped = pops[0][1]
    written = writes[0].get("value")
    if not (_int(byte) and popped == byte and written == byte):
        return False
    if payload_store.get("value") != byte:
        return False
    order = [frames[0].get("event_id"), pops[0][0],
             writes[0].get("event_id"), pulses[0].get("event_id"),
             takes[0].get("event_id"), mcause.get("event_id"),
             payload_store.get("event_id")]
    if any(not _int(value) for value in order):
        return False
    return order == sorted(order) and len(set(order)) == len(order)


def new_features(seen: frozenset[str], current: DmaChainFeatures) -> tuple[str, ...]:
    """Features of this case that the run has not observed before."""
    if not isinstance(seen, frozenset):
        raise ValueError("the seen feature set must be a frozenset")
    if not isinstance(current, DmaChainFeatures):
        raise ValueError("DmaChainFeatures is required")
    return tuple(sorted(key for key in current.features if key not in seen))
