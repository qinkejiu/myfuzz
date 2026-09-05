"""Immutable records used by the CPU/ISA profile catalog."""

from __future__ import annotations

from dataclasses import dataclass


class CpuDefinitionError(ValueError):
    """Raised when a CPU profile declaration is invalid or unavailable."""


@dataclass(frozen=True, slots=True)
class CpuProfile:
    """A closed, metadata-only description of one CPU/ISA configuration."""

    cpu_id: str
    vendor: str
    xlen: tuple[int, ...]
    extensions: tuple[str, ...]
    core_native_protocols: tuple[tuple[str, str], ...]
    integration_protocols: tuple[tuple[str, str], ...]
    source_status: str
    source_paths: tuple[str, ...]
    implemented: bool

    def __post_init__(self) -> None:
        """Copy collection inputs so the frozen record is transitively stable."""
        object.__setattr__(self, "xlen", tuple(self.xlen))
        object.__setattr__(self, "extensions", tuple(self.extensions))
        object.__setattr__(
            self,
            "core_native_protocols",
            tuple((protocol_id, version) for protocol_id, version in self.core_native_protocols),
        )
        object.__setattr__(
            self,
            "integration_protocols",
            tuple((protocol_id, version) for protocol_id, version in self.integration_protocols),
        )
        object.__setattr__(self, "source_paths", tuple(self.source_paths))
