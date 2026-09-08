"""Sparse, per-test coherent memory for RFuzz composition runs."""

from __future__ import annotations

from collections.abc import Callable, Hashable


class CoherentMemoryState:
    """Keep little-endian bytes coherent within and isolated across domains."""

    _ADDRESS_BITS = 64
    _MAX_ADDRESS = (1 << _ADDRESS_BITS) - 1

    def __init__(self) -> None:
        self._bytes: dict[tuple[Hashable, int], int] = {}

    def read(
        self,
        domain: Hashable,
        address: int,
        width_bytes: int,
        initializer: Callable[[], int],
    ) -> int:
        self._validate_span(domain, address, width_bytes)
        if not callable(initializer):
            raise ValueError("initializer must be callable")

        missing = [
            index
            for index in range(width_bytes)
            if (domain, address + index) not in self._bytes
        ]
        if missing:
            initial_value = initializer()
            self._validate_value(initial_value, width_bytes)
            for index in missing:
                self._bytes[(domain, address + index)] = (
                    initial_value >> (8 * index)
                ) & 0xFF

        return sum(
            self._bytes[(domain, address + index)] << (8 * index)
            for index in range(width_bytes)
        )

    def write(
        self,
        domain: Hashable,
        address: int,
        value: int,
        byte_enable: int,
        width_bytes: int,
    ) -> None:
        self._validate_span(domain, address, width_bytes)
        self._validate_value(value, width_bytes)
        if (
            isinstance(byte_enable, bool)
            or not isinstance(byte_enable, int)
            or byte_enable < 0
            or byte_enable >= 1 << width_bytes
        ):
            raise ValueError("byte_enable must fit width_bytes")
        for index in range(width_bytes):
            if byte_enable >> index & 1:
                self._bytes[(domain, address + index)] = (value >> (8 * index)) & 0xFF

    def seed(self, domain: Hashable, address: int, value: int, width_bytes: int) -> None:
        """Seed every byte in a span without invoking an initializer."""
        self.write(domain, address, value, (1 << width_bytes) - 1, width_bytes)

    def reset_test(self) -> None:
        """Discard all state accumulated for the current test."""
        self._bytes.clear()

    @classmethod
    def _validate_span(cls, domain: Hashable, address: int, width_bytes: int) -> None:
        try:
            hash(domain)
        except TypeError as exc:
            raise ValueError("domain must be hashable") from exc
        if (
            isinstance(address, bool)
            or not isinstance(address, int)
            or address < 0
            or address > cls._MAX_ADDRESS
        ):
            raise ValueError("address must be a bounded nonnegative integer")
        if isinstance(width_bytes, bool) or not isinstance(width_bytes, int) or width_bytes <= 0:
            raise ValueError("width_bytes must be positive")
        if width_bytes - 1 > cls._MAX_ADDRESS - address:
            raise ValueError("address span exceeds address bounds")

    @staticmethod
    def _validate_value(value: int, width_bytes: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("value must be a nonnegative integer")
        if value >= 1 << (8 * width_bytes):
            raise ValueError("value exceeds width_bytes")
