"""Address/data delivery from accepted CPU beats to independent real IP RTL."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from .ledger import TransactionKey, TransactionLedger


class RegisterTarget(Protocol):
    def write_register(self, offset: int, value: int, *, be: int = 15) -> None: ...
    def read_register(self, offset: int) -> int: ...


@dataclass(frozen=True)
class DeviceWindow:
    device_id: str
    base: int
    size: int
    target: RegisterTarget

    def __post_init__(self) -> None:
        if (not self.device_id or isinstance(self.base, bool)
                or not isinstance(self.base, int) or self.base < 0
                or self.base % 0x1000 or isinstance(self.size, bool)
                or not isinstance(self.size, int) or self.size < 4
                or self.size % 4 or self.base + self.size > 1 << 64):
            raise ValueError("device window is invalid")


class DataflowRouter:
    """One MMIO target per address, with a frozen receipt per source handshake.

    A target must run actual RTL. The router transforms width and address only;
    it never calculates what a register read *should* return.
    """

    def __init__(self, windows: tuple[DeviceWindow, ...]) -> None:
        if not windows or not isinstance(windows, tuple):
            raise ValueError("at least one device window is required")
        for index, window in enumerate(windows):
            if not isinstance(window, DeviceWindow):
                raise ValueError("windows must contain DeviceWindow records")
            if any(window.base < other.base + other.size
                   and other.base < window.base + window.size
                   for other in windows[:index]):
                raise ValueError("overlapping device windows")
        self.windows = windows
        self.acceptances: list[dict] = []
        self.deliveries: list[dict] = []
        self._target_delivery_counts: dict[str, int] = {}
        self._queued: list[tuple[TransactionLedger, TransactionKey, dict,
                                 DeviceWindow, int, int, int, bool,
                                 Callable[[tuple[int, int]], None]]] = []

    @property
    def pending_targets(self) -> tuple[str, ...]:
        return tuple(sorted({item[3].device_id for item in self._queued}))

    @property
    def ready_targets(self) -> tuple[str, ...]:
        """Targets whose oldest queued request can execute this step."""
        first: dict[str, bool] = {}
        for ledger, key, _, window, *_ in self._queued:
            if window.device_id not in first:
                first[window.device_id] = ledger.target_ready(key)
        return tuple(sorted(target for target, ready in first.items() if ready))

    @property
    def pending_target_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self._queued:
            target = item[3].device_id
            counts[target] = counts.get(target, 0) + 1
        return counts

    def _window(self, address: int) -> DeviceWindow | None:
        for window in self.windows:
            if window.base <= address < window.base + window.size:
                return window
        return None

    def owns(self, address: int) -> bool:
        return self._window(address) is not None

    def _prepare(self, *, address: int, write: bool, wdata: int, be: int,
                 beat_bytes: int) -> tuple[DeviceWindow, int, int, int, bool, dict]:
        window = self._window(address)
        if window is None:
            raise ValueError("MMIO address has no declared real target")
        if beat_bytes not in (4, 8) or address % 4 or address + 4 > window.base + window.size:
            raise ValueError("unsupported MMIO access shape")
        if isinstance(be, bool) or not isinstance(be, int) or be < 0 \
                or be >= (1 << beat_bytes):
            raise ValueError("byte enables are invalid")
        high_lane = beat_bytes == 8 and bool(address & 4)
        lane_be = be >> 4 if high_lane else be & 15
        if write and (not lane_be or (beat_bytes == 8 and
                                     ((be & 15) if high_lane else (be >> 4)))):
            raise ValueError("MMIO byte lanes do not match address")
        data32 = (wdata >> 32 if high_lane else wdata) & 0xffffffff
        offset = address - window.base
        payload = {"device_id": window.device_id, "address": address,
                   "write": bool(write), "wdata": wdata, "be": be,
                   "beat_bytes": beat_bytes}
        return window, lane_be, data32, offset, high_lane, payload

    def enqueue(self, ledger: TransactionLedger, key: TransactionKey, *,
                address: int, write: bool, wdata: int, be: int,
                beat_bytes: int,
                callback: Callable[[tuple[int, int]], None]) -> bool:
        """Accept a CPU request; execute its target on a later target step."""
        if not callable(callback):
            raise ValueError("queued MMIO requires a completion callback")
        window, lane_be, data32, offset, high_lane, payload = self._prepare(
            address=address, write=write, wdata=wdata, be=be,
            beat_bytes=beat_bytes)
        fresh = ledger.accept(key, payload)
        if fresh:
            self._queued.append((ledger, key, payload, window, lane_be,
                                 data32, offset, bool(write), callback))
            self.acceptances.append({"source_transaction": key,
                                     "device_id": window.device_id,
                                     "source_sequence": key.source_sequence,
                                     "acceptance_order": len(self.acceptances) + 1,
                                     "address": address, "offset": offset,
                                     "beat_bytes": beat_bytes,
                                     "write": bool(write),
                                     "byte_enable": lane_be,
                                     "write_value": data32 if write else None})
        return fresh

    def drain_one(self, device_id: str) -> bool:
        """Execute one accepted request at its declared real RTL target."""
        index = next((i for i, item in enumerate(self._queued)
                      if item[3].device_id == device_id), None)
        if index is None:
            return False
        ledger, key, payload, window, lane_be, data32, offset, write, callback = (
            self._queued[index])
        if not ledger.target_ready(key):
            return False

        def deliver() -> tuple[int, int]:
            if write:
                window.target.write_register(offset, data32, be=lane_be)
                response = (0, 0)
            else:
                readback = window.target.read_register(offset)
                response = (readback << (32 if payload["beat_bytes"] == 8
                                         and bool(payload["address"] & 4) else 0), 0)
            target_order = self._target_delivery_counts.get(window.device_id, 0) + 1
            self._target_delivery_counts[window.device_id] = target_order
            self.deliveries.append({"source_transaction": key,
                                    "device_id": window.device_id,
                                    "source_sequence": key.source_sequence,
                                    "delivery_order": len(self.deliveries) + 1,
                                    "target_delivery_order": target_order,
                                    "address": payload["address"],
                                    "beat_bytes": payload["beat_bytes"],
                                    "offset": offset, "write": write,
                                    "byte_enable": lane_be,
                                    "write_value": data32 if write else None,
                                    "read_value": response[0] if not write else None})
            return response

        try:
            response = ledger.complete_accepted(key, payload, deliver)
        except BaseException:
            if key in ledger.uncertain_keys:
                self._queued.pop(index)
            raise
        self._queued.pop(index)
        callback(response)
        return True

    def cancel_for_ledger(self, ledger: TransactionLedger) -> tuple[TransactionKey, ...]:
        """Drop requests never sent to a target at a source reset barrier."""
        cancelled = []
        remaining = []
        for item in self._queued:
            if item[0] is ledger:
                ledger.cancel_accepted(item[1], item[2])
                cancelled.append(item[1])
            else:
                remaining.append(item)
        self._queued = remaining
        return tuple(cancelled)

    def transact(self, ledger: TransactionLedger, key: TransactionKey, *,
                 address: int, write: bool, wdata: int, be: int,
                 beat_bytes: int) -> tuple[int, int]:
        window, lane_be, data32, offset, high_lane, payload = self._prepare(
            address=address, write=write, wdata=wdata, be=be,
            beat_bytes=beat_bytes)

        def deliver() -> tuple[int, int]:
            if write:
                window.target.write_register(offset, data32, be=lane_be)
                response = (0, 0)
            else:
                readback = window.target.read_register(offset)
                response = (readback << (32 if high_lane else 0), 0)
            target_order = self._target_delivery_counts.get(window.device_id, 0) + 1
            self._target_delivery_counts[window.device_id] = target_order
            self.deliveries.append({"source_transaction": key, "device_id": window.device_id,
                                    "source_sequence": key.source_sequence,
                                    "delivery_order": len(self.deliveries) + 1,
                                    "target_delivery_order": target_order,
                                    "address": address,
                                    "beat_bytes": beat_bytes,
                                    "offset": offset, "write": write,
                                    "byte_enable": lane_be,
                                    "write_value": data32 if write else None,
                                    "read_value": response[0] if not write else None})
            return response

        return ledger.execute_once(key, payload, deliver)
