"""Controlled registry for the Ibex protocol-composition components."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ComponentRegistration:
    component_type: str
    module_name: str
    source_files: tuple[str, ...]
    supported_protocols: tuple[tuple[str, str], ...]
    parameter_defaults: Mapping[str, int]
    parameter_limits: Mapping[str, tuple[int, int]]
    irq_capable: bool


class ComponentRegistry:
    """A closed set of component definitions rooted at one checked-out design."""

    def __init__(self, registrations: tuple[ComponentRegistration, ...], root: Path) -> None:
        self._root = root
        self._registrations = {item.component_type: item for item in registrations}
        if len(self._registrations) != len(registrations):
            raise ValueError("duplicate component registration")

    def require(self, component_type: str) -> ComponentRegistration:
        try:
            return self._registrations[component_type]
        except KeyError as error:
            raise KeyError(component_type) from error

    def missing_source(self, registration: ComponentRegistration) -> str | None:
        for source_file in registration.source_files:
            if not (self._root / source_file).is_file():
                return source_file
        return None


def _registration(
    component_type: str,
    module_name: str,
    source_file: str,
    supported_protocol: tuple[str, str],
    *,
    parameter_defaults: Mapping[str, int] | None = None,
    parameter_limits: Mapping[str, tuple[int, int]] | None = None,
    irq_capable: bool,
) -> ComponentRegistration:
    return ComponentRegistration(
        component_type=component_type,
        module_name=module_name,
        source_files=(source_file,),
        supported_protocols=(supported_protocol,),
        parameter_defaults=MappingProxyType(dict(parameter_defaults or {})),
        parameter_limits=MappingProxyType(dict(parameter_limits or {})),
        irq_capable=irq_capable,
    )


def default_component_registry(root: Path) -> ComponentRegistry:
    """Return the only first-stage component registrations.

    Source paths are relative to *root*, keeping manifest and generated IR data
    independent of the local checkout path.
    """
    rtl = "configs/designs/ibex_multicomponent_ip/rtl/"
    return ComponentRegistry(
        (
            _registration(
                "ram", "ibex_mcip_ram", rtl + "ibex_mcip_ram.sv", ("tl-ul", "1"),
                parameter_defaults={"WORDS": 64},
                parameter_limits={"WORDS": (4, 16_384)},
                irq_capable=False,
            ),
            _registration("timer", "ibex_mcip_timer", rtl + "ibex_mcip_timer.sv", ("apb", "4"), irq_capable=True),
            _registration("gpio", "ibex_mcip_gpio", rtl + "ibex_mcip_gpio.sv", ("apb", "4"), irq_capable=True),
            _registration("uart", "ibex_mcip_uart", rtl + "ibex_mcip_uart.sv", ("axi4-lite", "1"), irq_capable=True),
            _registration("spi", "ibex_mcip_spi", rtl + "ibex_mcip_spi.sv", ("axi4-lite", "1"), irq_capable=True),
        ),
        root,
    )


__all__ = ["ComponentRegistration", "ComponentRegistry", "default_component_registry"]
