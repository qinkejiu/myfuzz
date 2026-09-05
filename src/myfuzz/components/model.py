"""Immutable records used by the peripheral capability catalog."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


class ComponentDefinitionError(ValueError):
    """Raised when a peripheral profile cannot be used safely."""


@dataclass(frozen=True, slots=True)
class PeripheralProfile:
    component_type: str
    module_name: str
    protocols: tuple[tuple[str, str], ...]
    address_alignment: int
    default_size: int
    irq_capable: bool
    requires: tuple[str, ...]
    source_status: str
    source_paths: tuple[str, ...]
    implemented: bool
    parameter_limits: Mapping[str, tuple[int, int]]

    def __post_init__(self) -> None:
        """Copy collection inputs so the frozen record is transitively stable."""
        object.__setattr__(
            self,
            "protocols",
            tuple((protocol_id, version) for protocol_id, version in self.protocols),
        )
        object.__setattr__(self, "requires", tuple(self.requires))
        object.__setattr__(self, "source_paths", tuple(self.source_paths))
        object.__setattr__(
            self,
            "parameter_limits",
            MappingProxyType(
                {
                    name: (bounds[0], bounds[1])
                    for name, bounds in self.parameter_limits.items()
                }
            ),
        )
