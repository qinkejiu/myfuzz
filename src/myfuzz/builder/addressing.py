"""Deterministic address allocation with separate intent and resolved layers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .input_model import AddressMode, AddressRequest, InputValidationError


@dataclass(frozen=True)
class AddressIntent:
    module: str
    request: AddressRequest


@dataclass(frozen=True)
class AddressWindow:
    module: str
    base: int
    size: int
    upper: int
    source: str
    reason: str
    confidence: str

    def contains(self, address: int) -> bool:
        return self.base <= address < self.upper


@dataclass(frozen=True)
class AddressPlanEntry:
    intent: AddressIntent
    window: AddressWindow


@dataclass(frozen=True)
class AddressPlan:
    address_width: int
    entries: tuple[AddressPlanEntry, ...]

    @property
    def windows(self) -> tuple[AddressWindow, ...]:
        return tuple(entry.window for entry in self.entries)


def allocate_addresses(
    intents: Iterable[AddressIntent], *, address_width: int = 32
) -> AddressPlan:
    if isinstance(address_width, bool) or not isinstance(address_width, int) or address_width <= 0:
        raise InputValidationError("address_width: expected an integer greater than zero")
    limit = 1 << address_width
    intent_list = list(intents)
    names = [intent.module for intent in intent_list]
    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise InputValidationError("address intent module names must be non-empty strings")
    if len(names) != len(set(names)):
        raise InputValidationError("address intent module names must be unique")

    occupied: list[AddressWindow] = []
    entries: list[AddressPlanEntry] = []
    fixed = sorted(
        (intent for intent in intent_list if intent.request.mode is AddressMode.FIXED),
        key=lambda intent: (intent.request.base, intent.module),
    )
    automatic = sorted(
        (intent for intent in intent_list if intent.request.mode is AddressMode.AUTO),
        key=lambda intent: (-_alignment(intent.request), -intent.request.size, intent.module),
    )

    for intent in fixed:
        request = intent.request
        if request.base is None:
            raise InputValidationError(f"{intent.module}: fixed address request has no base")
        window = _make_window(
            intent.module,
            request.base,
            request.size,
            limit,
            source="user_fixed",
            reason="base and size were fixed by the user",
            confidence="declared",
        )
        _reject_overlap(window, occupied)
        occupied.append(window)
        entries.append(AddressPlanEntry(intent=intent, window=window))

    for intent in automatic:
        request = intent.request
        alignment = _alignment(request)
        base = _first_fit(request.size, alignment, occupied, limit)
        if base is None:
            raise InputValidationError(
                f"{intent.module}: cannot place {request.size:#x}-byte window aligned to "
                f"{alignment:#x} in {address_width}-bit address space"
            )
        window = _make_window(
            intent.module,
            base,
            request.size,
            limit,
            source="system_auto",
            reason=f"first deterministic free interval aligned to {alignment:#x}",
            confidence="planned",
        )
        occupied.append(window)
        entries.append(AddressPlanEntry(intent=intent, window=window))

    entries.sort(key=lambda entry: (entry.window.base, entry.window.module))
    return AddressPlan(address_width=address_width, entries=tuple(entries))


def _first_fit(size: int, alignment: int, occupied: list[AddressWindow], limit: int) -> int | None:
    candidate = 0
    for window in sorted(occupied, key=lambda item: (item.base, item.module)):
        candidate = _align_up(candidate, alignment)
        if candidate + size <= window.base:
            return candidate
        if candidate < window.upper:
            candidate = window.upper
    candidate = _align_up(candidate, alignment)
    return candidate if candidate + size <= limit else None


def _make_window(
    module: str,
    base: int,
    size: int,
    limit: int,
    *,
    source: str,
    reason: str,
    confidence: str,
) -> AddressWindow:
    upper = base + size
    if base < 0 or size <= 0:
        raise InputValidationError(f"{module}: address base and size must form a positive interval")
    if upper > limit:
        raise InputValidationError(
            f"{module}: address window [{base:#x}, {upper:#x}) exceeds address space limit {limit:#x}"
        )
    return AddressWindow(
        module=module,
        base=base,
        size=size,
        upper=upper,
        source=source,
        reason=reason,
        confidence=confidence,
    )


def _reject_overlap(candidate: AddressWindow, occupied: list[AddressWindow]) -> None:
    for existing in occupied:
        if candidate.base < existing.upper and existing.base < candidate.upper:
            raise InputValidationError(
                f"address windows overlap: {candidate.module} [{candidate.base:#x}, {candidate.upper:#x}) "
                f"and {existing.module} [{existing.base:#x}, {existing.upper:#x})"
            )


def _alignment(request: AddressRequest) -> int:
    if request.alignment is not None:
        return request.alignment
    return 1 << (request.size - 1).bit_length()


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment
