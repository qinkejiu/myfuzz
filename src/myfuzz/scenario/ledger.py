"""Logical transaction identity and in-process at-most-once delivery."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Callable, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class TransactionKey:
    execution_id: str
    testcase_id: str
    source_component: str
    source_epoch: int
    channel_id: str
    source_sequence: int

    def __post_init__(self) -> None:
        if not all((self.execution_id, self.testcase_id,
                    self.source_component, self.channel_id)):
            raise ValueError("transaction identity fields must be nonempty")
        for name in ("source_epoch", "source_sequence"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be nonnegative")


@dataclass
class _Entry:
    payload_digest: str
    status: str
    receipt: object = None


class TransactionLedger:
    """Cache the full result under source identity before target execution.

    A process crash after target acceptance cannot be resolved by this ledger;
    callers must replay the whole testcase from its initial state.
    """

    def __init__(self) -> None:
        self._entries: dict[TransactionKey, _Entry] = {}
        self._next_channel_sequence: dict[tuple[str, str, str, int, str], int] = {}
        self._next_target_sequence: dict[tuple[str, str, str, int, str], int] = {}

    @staticmethod
    def _channel(key: TransactionKey) -> tuple[str, str, str, int, str]:
        return (key.execution_id, key.testcase_id, key.source_component,
                key.source_epoch, key.channel_id)

    @staticmethod
    def _digest(payload: dict) -> str:
        if not isinstance(payload, dict):
            raise ValueError("transaction payload is required")
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("transaction payload is not canonical JSON") from exc
        return hashlib.sha256(encoded).hexdigest()

    @property
    def pending_keys(self) -> tuple[TransactionKey, ...]:
        """Accepted requests still waiting for their target operation."""
        return tuple(key for key, entry in self._entries.items()
                     if entry.status == "target_pending")

    @property
    def uncertain_keys(self) -> tuple[TransactionKey, ...]:
        """Requests whose target may have acted without a confirmed receipt."""
        return tuple(key for key, entry in self._entries.items()
                     if entry.status in ("target_inflight", "uncertain_effect"))

    def target_ready(self, key: TransactionKey) -> bool:
        """Whether an accepted request is next on its source channel."""
        entry = self._entries.get(key)
        return (entry is not None and entry.status == "target_pending"
                and key.source_sequence ==
                self._next_target_sequence.get(self._channel(key), 1))

    @property
    def unresolved_keys(self) -> tuple[TransactionKey, ...]:
        """Accepted transactions whose target effect cannot be certified complete."""
        return tuple(key for key, entry in self._entries.items()
                     if entry.status not in ("complete", "cancelled"))

    def accept(self, key: TransactionKey, payload: dict) -> bool:
        """Accept a source handshake without executing its real target yet."""
        if not isinstance(key, TransactionKey):
            raise ValueError("transaction key is required")
        digest = self._digest(payload)
        previous = self._entries.get(key)
        if previous is not None:
            if previous.payload_digest != digest:
                raise ValueError("identity_conflict: same key, different payload")
            if previous.status in ("target_pending", "complete"):
                return False
            raise RuntimeError(f"{previous.status}: target result is not available")
        channel = self._channel(key)
        expected = self._next_channel_sequence.get(channel, 1)
        if key.source_sequence != expected:
            raise ValueError("out_of_order_transaction: source channel sequence "
                             f"{key.source_sequence} expected {expected}")
        self._entries[key] = _Entry(digest, "target_pending")
        self._next_channel_sequence[channel] = expected + 1
        return True

    def complete_accepted(self, key: TransactionKey, payload: dict,
                          operation: Callable[[], T]) -> T:
        """Run a queued target once, in source-channel order, and freeze receipt."""
        if not isinstance(key, TransactionKey):
            raise ValueError("transaction key is required")
        digest = self._digest(payload)
        entry = self._entries.get(key)
        if entry is None:
            raise ValueError("transaction was not accepted")
        if entry.payload_digest != digest:
            raise ValueError("identity_conflict: same key, different payload")
        if entry.status == "complete":
            return entry.receipt  # type: ignore[return-value]
        if entry.status != "target_pending":
            raise RuntimeError(f"{entry.status}: target result is not available")
        channel = self._channel(key)
        expected = self._next_target_sequence.get(channel, 1)
        if key.source_sequence != expected:
            raise ValueError("out_of_order_target_delivery: source channel sequence "
                             f"{key.source_sequence} expected {expected}")
        entry.status = "target_inflight"
        try:
            receipt = operation()
        except BaseException:
            entry.status = "uncertain_effect"
            raise
        entry.receipt = receipt
        entry.status = "complete"
        self._next_target_sequence[channel] = expected + 1
        return receipt

    def cancel_accepted(self, key: TransactionKey, payload: dict) -> None:
        """Cancel a known-undelivered request at an explicit reset barrier."""
        if not isinstance(key, TransactionKey):
            raise ValueError("transaction key is required")
        digest = self._digest(payload)
        entry = self._entries.get(key)
        if entry is None or entry.payload_digest != digest:
            raise ValueError("transaction identity does not match accepted request")
        if entry.status != "target_pending":
            raise RuntimeError("only an undelivered target request can be cancelled")
        channel = self._channel(key)
        expected = self._next_target_sequence.get(channel, 1)
        if key.source_sequence != expected:
            raise ValueError("out_of_order_target_delivery: cancellation order changed")
        entry.status = "cancelled"
        self._next_target_sequence[channel] = expected + 1

    def execute_once(self, key: TransactionKey, payload: dict,
                     operation: Callable[[], T]) -> T:
        if not isinstance(key, TransactionKey):
            raise ValueError("transaction key and payload are required")
        digest = self._digest(payload)
        previous = self._entries.get(key)
        if previous is not None:
            if previous.payload_digest != digest:
                raise ValueError("identity_conflict: same key, different payload")
            if previous.status != "complete":
                raise RuntimeError("uncertain_effect: target result is not known")
            return previous.receipt  # type: ignore[return-value]
        channel = self._channel(key)
        expected_sequence = self._next_channel_sequence.get(channel, 1)
        if key.source_sequence != expected_sequence:
            raise ValueError("out_of_order_transaction: source channel sequence "
                             f"{key.source_sequence} expected {expected_sequence}")
        expected_target = self._next_target_sequence.get(channel, 1)
        if key.source_sequence != expected_target:
            raise ValueError("out_of_order_target_delivery: source channel sequence "
                             f"{key.source_sequence} expected {expected_target}")
        entry = _Entry(digest, "target_pending")
        self._entries[key] = entry
        self._next_channel_sequence[channel] = expected_sequence + 1
        entry.status = "target_inflight"
        try:
            result = operation()
        except BaseException:
            entry.status = "uncertain_effect"
            raise
        entry.receipt = result
        entry.status = "complete"
        self._next_target_sequence[channel] = expected_target + 1
        return result
