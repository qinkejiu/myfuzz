"""Typed, identifier-opaque view of ``hdl_facts.v2`` documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from myfuzz.contracts import validate_contract


@dataclass(frozen=True)
class HdlModule:
    id: int
    port_ids: tuple[int, ...]
    instance_ids: tuple[int, ...]


@dataclass(frozen=True)
class HdlPort:
    id: int
    module_id: int
    direction: str
    width: int
    signed: bool
    declared_role: str


@dataclass(frozen=True)
class HdlFacts:
    """Structural facts available to composition search.

    Names, paths and source-symbol records are intentionally not represented.
    They remain available only at frontend/emitter diagnostic boundaries.
    """

    modules: tuple[HdlModule, ...]
    ports: tuple[HdlPort, ...]
    structural_sections: tuple[tuple[str, tuple[object, ...]], ...]

    def module(self, module_id: int) -> HdlModule:
        for module in self.modules:
            if module.id == module_id:
                return module
        raise KeyError(module_id)

    def ports_for_module(self, module_id: int) -> tuple[HdlPort, ...]:
        return tuple(port for port in self.ports if port.module_id == module_id)

    def port(self, port_id: int) -> HdlPort:
        for port in self.ports:
            if port.id == port_id:
                return port
        raise KeyError(port_id)


_STRUCTURAL_SECTIONS = (
    "parameters",
    "instances",
    "pin_bindings",
    "expressions",
    "dataflow_edges",
    "control_edges",
    "clock_reset_checks",
    "local_address_facts",
)
VALID_STRUCTURAL_SECTIONS = frozenset(_STRUCTURAL_SECTIONS)
_ANNOTATION_KEYS = frozenset(
    (
        "name",
        "module_name",
        "instance_name",
        "port_name",
        "net_name",
        "file",
        "filename",
        "path",
        "source",
        "source_symbol",
        "source_location",
    )
)


def _without_annotations(value: object) -> object:
    if isinstance(value, Mapping):
        return tuple(
            (str(key), _without_annotations(item))
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if key not in _ANNOTATION_KEYS
        )
    if isinstance(value, list):
        return tuple(_without_annotations(item) for item in value)
    return value


def canonical_structural_value(value: object) -> object:
    """Canonicalize structural records, including tuple-pair mappings."""
    if isinstance(value, Mapping):
        return tuple(
            (str(key), canonical_structural_value(item))
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        )
    if isinstance(value, (list, tuple)):
        items = tuple(value)
        if all(isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str) for item in items):
            return tuple(
                (key, canonical_structural_value(item))
                for key, item in sorted(items, key=lambda pair: pair[0])
            )
        return tuple(canonical_structural_value(item) for item in items)
    return value


def _integer_tuple(value: object, path: str) -> tuple[int, ...]:
    if not isinstance(value, list) or any(not isinstance(item, int) or isinstance(item, bool) for item in value):
        raise ValueError(f"{path}:type")
    return tuple(sorted(value))


def normalize_facts(raw: object) -> HdlFacts:
    """Validate and normalize facts without exposing identifier annotations."""
    validate_contract(raw, "hdl_facts.v2")
    if not isinstance(raw, Mapping):  # Defensive after contract validation.
        raise ValueError("document:type")

    modules: list[HdlModule] = []
    for index, value in enumerate(raw["modules"]):
        if not isinstance(value, Mapping):
            raise ValueError(f"modules[{index}]:type")
        modules.append(
            HdlModule(
                id=int(value["id"]),
                port_ids=_integer_tuple(value["ports"], f"modules[{index}].ports"),
                instance_ids=_integer_tuple(value["instances"], f"modules[{index}].instances"),
            )
        )

    ports: list[HdlPort] = []
    for index, value in enumerate(raw["ports"]):
        if not isinstance(value, Mapping):
            raise ValueError(f"ports[{index}]:type")
        ports.append(
            HdlPort(
                id=int(value["id"]),
                module_id=int(value["module_id"]),
                direction=str(value["direction"]),
                width=int(value["width"]),
                signed=bool(value["signed"]),
                declared_role=str(value["declared_role"]),
            )
        )

    sections = tuple(
        (section, tuple(_without_annotations(item) for item in raw[section]))
        for section in _STRUCTURAL_SECTIONS
    )
    return HdlFacts(
        modules=tuple(sorted(modules, key=lambda module: module.id)),
        ports=tuple(sorted(ports, key=lambda port: port.id)),
        structural_sections=sections,
    )
