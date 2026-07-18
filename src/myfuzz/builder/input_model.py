"""Validated user input model for the protocol-driven system builder."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, NoReturn


class InputValidationError(ValueError):
    """A structural error in a system specification."""


class AddressMode(str, Enum):
    AUTO = "auto"
    FIXED = "fixed"


class AddressAliasPolicy(str, Enum):
    REJECT = "reject"
    ALLOW_MIRROR = "allow_mirror"


class ModuleKind(str, Enum):
    CPU = "cpu"
    BUS_MASTER = "bus_master"
    DMA = "dma"
    INTERCONNECT = "interconnect"
    MEMORY = "memory"
    ROM = "rom"
    RAM = "ram"
    BUS_SLAVE = "bus_slave"
    PERIPHERAL = "peripheral"
    BRIDGE = "bridge"
    INTERRUPT_CONTROLLER = "interrupt_controller"
    CLOCK_RESET = "clock_reset"
    DEBUG = "debug"
    OBSERVATION = "observation"
    TEST = "test"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class PortDirection(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    INOUT = "inout"


@dataclass(frozen=True)
class AddressRequest:
    mode: AddressMode
    size: int
    base: int | None = None
    alignment: int | None = None
    alias_policy: AddressAliasPolicy = AddressAliasPolicy.REJECT


@dataclass(frozen=True)
class PortAnnotation:
    direction: PortDirection
    port_type: str
    width: int | None = None


@dataclass(frozen=True)
class UnknownPortPolicySpec:
    action: str
    reason: str
    value: int | None = None
    constraint: str | None = None
    reset_behavior: str | None = None
    connect_to: str | None = None


@dataclass(frozen=True)
class InterfaceSpec:
    name: str
    protocol: str
    role: str
    ports: Mapping[str, str]


@dataclass(frozen=True)
class ClockDomain:
    name: str
    source: str
    frequency_hz: int | None = None


@dataclass(frozen=True)
class ResetDomain:
    name: str
    source: str
    active_low: bool
    synchronous: bool


@dataclass(frozen=True)
class SourceSet:
    name: str
    rtl_files: tuple[str, ...]
    filelists: tuple[str, ...]


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    kind: ModuleKind
    source_set: str
    ports: Mapping[str, PortAnnotation]
    rtl_module: str | None = None
    component_id: str | None = None
    address: AddressRequest | None = None
    interfaces: tuple[InterfaceSpec, ...] = ()
    parameters: Mapping[str, int | str] = field(default_factory=dict)
    clock_domain: str | None = None
    reset_domain: str | None = None
    top_candidate: bool = False
    unknown_ports: Mapping[str, UnknownPortPolicySpec] = field(default_factory=dict)


@dataclass(frozen=True)
class SystemSpec:
    schema_version: int
    name: str
    sources: tuple[SourceSet, ...]
    modules: tuple[ModuleSpec, ...]
    clock_domains: tuple[ClockDomain, ...] = ()
    reset_domains: tuple[ResetDomain, ...] = ()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SystemSpec":
        root = _mapping(
            value, "$",
            allowed={"schema_version", "name", "sources", "modules", "clock_domains", "reset_domains"},
        )
        version = _integer(root.get("schema_version", 1), "$.schema_version")
        if version != 1:
            _fail("$.schema_version", f"unsupported schema version {version}; expected 1")

        name = _nonempty_string(root.get("name"), "$.name")
        source_values = _list(root.get("sources"), "$.sources", nonempty=True)
        sources = tuple(_parse_source(item, f"$.sources[{index}]") for index, item in enumerate(source_values))
        _require_unique((source.name for source in sources), "$.sources", "source-set name")

        module_values = _list(root.get("modules"), "$.modules", nonempty=True)
        modules = tuple(_parse_module(item, f"$.modules[{index}]") for index, item in enumerate(module_values))
        _require_unique((module.name for module in modules), "$.modules", "module name")

        clock_domains = tuple(
            _parse_clock_domain(item, f"$.clock_domains[{index}]")
            for index, item in enumerate(_list(root.get("clock_domains", []), "$.clock_domains"))
        )
        reset_domains = tuple(
            _parse_reset_domain(item, f"$.reset_domains[{index}]")
            for index, item in enumerate(_list(root.get("reset_domains", []), "$.reset_domains"))
        )
        _require_unique((domain.name for domain in clock_domains), "$.clock_domains", "clock domain")
        _require_unique((domain.name for domain in reset_domains), "$.reset_domains", "reset domain")

        source_names = {source.name for source in sources}
        for index, module in enumerate(modules):
            if module.source_set not in source_names:
                _fail(f"$.modules[{index}].source_set", f"unknown source set {module.source_set!r}")
            if module.clock_domain and module.clock_domain not in {domain.name for domain in clock_domains}:
                _fail(f"$.modules[{index}].clock_domain", f"unknown clock domain {module.clock_domain!r}")
            if module.reset_domain and module.reset_domain not in {domain.name for domain in reset_domains}:
                _fail(f"$.modules[{index}].reset_domain", f"unknown reset domain {module.reset_domain!r}")
        return cls(
            schema_version=version, name=name, sources=sources, modules=modules,
            clock_domains=clock_domains, reset_domains=reset_domains,
        )


def load_system_spec(path: str | Path) -> SystemSpec:
    input_path = Path(path)
    try:
        value = json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputValidationError(f"{input_path}: cannot read specification: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputValidationError(
            f"{input_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}"
        ) from exc
    if not isinstance(value, Mapping):
        _fail("$", "expected an object")
    return SystemSpec.from_dict(value)


def _parse_source(value: Any, path: str) -> SourceSet:
    item = _mapping(value, path, allowed={"name", "rtl_files", "filelists"})
    name = _nonempty_string(item.get("name"), f"{path}.name")
    rtl_files = _string_list(item.get("rtl_files", []), f"{path}.rtl_files")
    filelists = _string_list(item.get("filelists", []), f"{path}.filelists")
    if not rtl_files and not filelists:
        _fail(path, "source set must contain at least one rtl_files or filelists entry")
    return SourceSet(name=name, rtl_files=rtl_files, filelists=filelists)


def _parse_module(value: Any, path: str) -> ModuleSpec:
    item = _mapping(
        value, path,
        allowed={
            "name", "kind", "source_set", "ports", "address", "interfaces", "parameters",
            "clock_domain", "reset_domain", "top_candidate",
            "unknown_ports", "rtl_module", "component_id",
        },
    )
    name = _nonempty_string(item.get("name"), f"{path}.name")
    rtl_module = _optional_string(item.get("rtl_module"), f"{path}.rtl_module")
    component_id = _optional_string(item.get("component_id"), f"{path}.component_id")
    kind = _enum(ModuleKind, item.get("kind"), f"{path}.kind")
    source_set = _nonempty_string(item.get("source_set"), f"{path}.source_set")
    raw_ports = _mapping(item.get("ports", {}), f"{path}.ports")
    ports = {
        _nonempty_string(port_name, f"{path}.ports key"): _parse_port(port, f"{path}.ports.{port_name}")
        for port_name, port in raw_ports.items()
    }
    address = None if "address" not in item else _parse_address(item["address"], f"{path}.address")
    interfaces = tuple(
        _parse_interface(interface, f"{path}.interfaces[{index}]")
        for index, interface in enumerate(_list(item.get("interfaces", []), f"{path}.interfaces"))
    )
    _require_unique((interface.name for interface in interfaces), f"{path}.interfaces", "interface name")
    parameters = _parse_parameters(item.get("parameters", {}), f"{path}.parameters")
    clock_domain = _optional_string(item.get("clock_domain"), f"{path}.clock_domain")
    reset_domain = _optional_string(item.get("reset_domain"), f"{path}.reset_domain")
    top_candidate = item.get("top_candidate", False)
    if not isinstance(top_candidate, bool):
        _fail(f"{path}.top_candidate", "expected a boolean")
    unknown_ports = {
        _nonempty_string(port, f"{path}.unknown_ports key"): _parse_unknown_policy(
            policy, f"{path}.unknown_ports.{port}"
        )
        for port, policy in _mapping(item.get("unknown_ports", {}), f"{path}.unknown_ports").items()
    }
    return ModuleSpec(
        name=name, kind=kind, source_set=source_set, ports=ports, address=address,
        rtl_module=rtl_module, component_id=component_id,
        interfaces=interfaces, parameters=parameters, clock_domain=clock_domain,
        reset_domain=reset_domain, top_candidate=top_candidate,
        unknown_ports=unknown_ports,
    )


def _parse_port(value: Any, path: str) -> PortAnnotation:
    item = _mapping(value, path, allowed={"direction", "type", "width"})
    width = None if "width" not in item else _positive_integer(item["width"], f"{path}.width")
    return PortAnnotation(
        direction=_enum(PortDirection, item.get("direction"), f"{path}.direction"),
        port_type=_nonempty_string(item.get("type"), f"{path}.type"),
        width=width,
    )


def _parse_interface(value: Any, path: str) -> InterfaceSpec:
    item = _mapping(value, path, allowed={"name", "protocol", "role", "ports"})
    raw_ports = _mapping(item.get("ports"), f"{path}.ports")
    if not raw_ports:
        _fail(f"{path}.ports", "expected a non-empty object")
    ports = {
        _nonempty_string(semantic, f"{path}.ports key"): _nonempty_string(port, f"{path}.ports.{semantic}")
        for semantic, port in raw_ports.items()
    }
    if len(ports.values()) != len(set(ports.values())):
        _fail(f"{path}.ports", "a physical port may not have multiple interface roles")
    return InterfaceSpec(
        name=_nonempty_string(item.get("name"), f"{path}.name"),
        protocol=_nonempty_string(item.get("protocol"), f"{path}.protocol").lower(),
        role=_nonempty_string(item.get("role"), f"{path}.role").lower(),
        ports=ports,
    )


def _parse_parameters(value: Any, path: str) -> Mapping[str, int | str]:
    item = _mapping(value, path)
    result: dict[str, int | str] = {}
    for name, parameter in item.items():
        name = _nonempty_string(name, f"{path} key")
        if isinstance(parameter, bool) or not isinstance(parameter, (int, str)):
            _fail(f"{path}.{name}", "expected an integer or string expression")
        if isinstance(parameter, str) and not parameter.strip():
            _fail(f"{path}.{name}", "expected a non-empty string expression")
        result[name] = parameter
    return result


def _parse_unknown_policy(value: Any, path: str) -> UnknownPortPolicySpec:
    item = _mapping(
        value, path,
        allowed={"action", "reason", "value", "constraint", "reset_behavior", "connect_to"},
    )
    raw_value = item.get("value")
    if raw_value is not None and (isinstance(raw_value, bool) or not isinstance(raw_value, int)):
        _fail(f"{path}.value", "expected an integer")
    return UnknownPortPolicySpec(
        action=_nonempty_string(item.get("action"), f"{path}.action"),
        reason=_nonempty_string(item.get("reason"), f"{path}.reason"),
        value=raw_value,
        constraint=_optional_string(item.get("constraint"), f"{path}.constraint"),
        reset_behavior=_optional_string(item.get("reset_behavior"), f"{path}.reset_behavior"),
        connect_to=_optional_string(item.get("connect_to"), f"{path}.connect_to"),
    )


def _parse_clock_domain(value: Any, path: str) -> ClockDomain:
    item = _mapping(value, path, allowed={"name", "source", "frequency_hz"})
    frequency = None if "frequency_hz" not in item else _positive_integer(item["frequency_hz"], f"{path}.frequency_hz")
    return ClockDomain(
        name=_nonempty_string(item.get("name"), f"{path}.name"),
        source=_nonempty_string(item.get("source"), f"{path}.source"),
        frequency_hz=frequency,
    )


def _parse_reset_domain(value: Any, path: str) -> ResetDomain:
    item = _mapping(value, path, allowed={"name", "source", "active_low", "synchronous"})
    active_low = item.get("active_low")
    synchronous = item.get("synchronous")
    if not isinstance(active_low, bool):
        _fail(f"{path}.active_low", "expected a boolean")
    if not isinstance(synchronous, bool):
        _fail(f"{path}.synchronous", "expected a boolean")
    return ResetDomain(
        name=_nonempty_string(item.get("name"), f"{path}.name"),
        source=_nonempty_string(item.get("source"), f"{path}.source"),
        active_low=active_low,
        synchronous=synchronous,
    )


def _parse_address(value: Any, path: str) -> AddressRequest:
    item = _mapping(value, path, allowed={"mode", "size", "base", "alignment", "alias_policy"})
    mode = _enum(AddressMode, item.get("mode"), f"{path}.mode")
    size = _positive_integer(item.get("size"), f"{path}.size")
    base = None
    if mode is AddressMode.FIXED:
        if "base" not in item:
            _fail(f"{path}.base", "required for a fixed address request")
        base = _nonnegative_integer(item.get("base"), f"{path}.base")
    elif "base" in item:
        _fail(f"{path}.base", "base is only valid for a fixed address request")

    alignment = None
    if "alignment" in item:
        alignment = _positive_integer(item["alignment"], f"{path}.alignment")
        if alignment & (alignment - 1):
            _fail(f"{path}.alignment", "expected a power of two")
    if base is not None and alignment is not None and base % alignment:
        _fail(f"{path}.base", f"must be aligned to {alignment:#x}")
    alias_policy = _enum(
        AddressAliasPolicy, item.get("alias_policy", AddressAliasPolicy.REJECT.value),
        f"{path}.alias_policy",
    )
    return AddressRequest(
        mode=mode, size=size, base=base, alignment=alignment, alias_policy=alias_policy,
    )


def _mapping(value: Any, path: str, allowed: set[str] | None = None) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, "expected an object")
    if allowed is not None:
        unknown = sorted(set(value) - allowed)
        if unknown:
            _fail(path, f"unknown field(s): {', '.join(unknown)}")
    return value


def _list(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "expected an array")
    if nonempty and not value:
        _fail(path, "expected a non-empty array")
    return value


def _string_list(value: Any, path: str) -> tuple[str, ...]:
    return tuple(_nonempty_string(item, f"{path}[{index}]") for index, item in enumerate(_list(value, path)))


def _nonempty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "expected a non-empty string")
    return value


def _optional_string(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _nonempty_string(value, path)


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(path, "expected an integer")
    return value


def _positive_integer(value: Any, path: str) -> int:
    result = _integer(value, path)
    if result <= 0:
        _fail(path, "expected an integer greater than zero")
    return result


def _nonnegative_integer(value: Any, path: str) -> int:
    result = _integer(value, path)
    if result < 0:
        _fail(path, "expected a non-negative integer")
    return result


def _enum(enum_type: type[Enum], value: Any, path: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        choices = ", ".join(repr(item.value) for item in enum_type)
        _fail(path, f"expected one of: {choices}")


def _require_unique(values: Any, path: str, label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            _fail(path, f"duplicate {label} {value!r}")
        seen.add(value)


def _fail(path: str, message: str) -> NoReturn:
    raise InputValidationError(f"{path}: {message}")
