"""Reusable protocol/interface/port knowledge and deterministic matching."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from .input_model import InputValidationError, PortAnnotation, PortDirection


class InterfaceRole(str, Enum):
    INITIATOR = "initiator"
    TARGET = "target"
    MONITOR = "monitor"


class MatchSource(str, Enum):
    USER = "user"
    PROFILE = "profile"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class PortRule:
    semantic: str
    direction: PortDirection
    aliases: tuple[str, ...]
    required: bool = True


@dataclass(frozen=True)
class ChannelRule:
    name: str
    signals: tuple[str, ...]


@dataclass(frozen=True)
class ProfileAddressRule:
    requires_window: bool
    default_size: int | None = None
    alignment: int | None = None


@dataclass(frozen=True)
class ProtocolProfile:
    name: str
    protocol: str
    interface_role: InterfaceRole
    ports: tuple[PortRule, ...]
    priority: int = 0
    channels: tuple[ChannelRule, ...] = ()
    address_rule: ProfileAddressRule | None = None
    constraints: tuple[str, ...] = ()
    version: str = "1"
    capabilities: tuple[str, ...] = ()
    width_rules: tuple[str, ...] = ()
    handshake: tuple[str, ...] = ()
    responses: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProtocolProfile":
        item = _mapping(
            value,
            "$",
            allowed={
                "name", "protocol", "interface_role", "priority", "ports", "channels",
                "address_rule", "constraints",
                "version", "capabilities", "width_rules", "handshake", "responses",
            },
        )
        name = _string(item.get("name"), "$.name")
        protocol = _canonical(_string(item.get("protocol"), "$.protocol"))
        role = _enum(InterfaceRole, item.get("interface_role"), "$.interface_role")
        priority = _integer(item.get("priority", 0), "$.priority")
        raw_ports = item.get("ports")
        if not isinstance(raw_ports, list) or not raw_ports:
            _fail("$.ports", "expected a non-empty array")
        ports = tuple(_parse_port_rule(port, f"$.ports[{index}]") for index, port in enumerate(raw_ports))
        semantics = [port.semantic for port in ports]
        if len(semantics) != len(set(semantics)):
            _fail("$.ports", "port semantics must be unique within a profile")
        channels = tuple(
            _parse_channel(channel, f"$.channels[{index}]")
            for index, channel in enumerate(_array(item.get("channels", []), "$.channels"))
        )
        known_semantics = set(semantics)
        for index, channel in enumerate(channels):
            missing = set(channel.signals) - known_semantics
            if missing:
                _fail(f"$.channels[{index}].signals", f"unknown port semantic(s): {', '.join(sorted(missing))}")
        address_rule = None
        if "address_rule" in item:
            address_rule = _parse_address_rule(item["address_rule"], "$.address_rule")
        constraints = tuple(
            _string(constraint, f"$.constraints[{index}]")
            for index, constraint in enumerate(_array(item.get("constraints", []), "$.constraints"))
        )
        version = _string(item.get("version", "1"), "$.version")
        capabilities = _string_array(item.get("capabilities", []), "$.capabilities")
        width_rules = _string_array(item.get("width_rules", []), "$.width_rules")
        handshake = _string_array(item.get("handshake", []), "$.handshake")
        responses = _string_array(item.get("responses", []), "$.responses")
        return cls(
            name=name, protocol=protocol, interface_role=role, ports=ports, priority=priority,
            channels=channels, address_rule=address_rule, constraints=constraints,
            version=version, capabilities=capabilities, width_rules=width_rules,
            handshake=handshake, responses=responses,
        )


@dataclass(frozen=True)
class PortResolution:
    annotation: PortAnnotation | None
    source: MatchSource
    reason: str
    profile_name: str | None = None
    confidence: str = "unknown"


class ProfileRegistry:
    def __init__(self, profiles: Iterable[ProtocolProfile] = ()) -> None:
        self._profiles: list[ProtocolProfile] = []
        for profile in profiles:
            self.register(profile)

    def register(self, profile: ProtocolProfile) -> None:
        if any(existing.name == profile.name for existing in self._profiles):
            raise InputValidationError(f"duplicate protocol profile name {profile.name!r}")
        self._profiles.append(profile)

    def query(self, protocol: str, interface_role: InterfaceRole | str) -> tuple[ProtocolProfile, ...]:
        canonical_protocol = _canonical(_string(protocol, "protocol"))
        role = _enum(InterfaceRole, interface_role, "interface_role")
        matches = [
            profile
            for profile in self._profiles
            if profile.protocol == canonical_protocol and profile.interface_role is role
        ]
        return tuple(sorted(matches, key=lambda profile: (-profile.priority, profile.name)))

    def resolve_port(
        self,
        *,
        protocol: str,
        interface_role: InterfaceRole | str,
        port_name: str,
        direction: PortDirection | str,
        user_annotation: PortAnnotation | None = None,
    ) -> PortResolution:
        if user_annotation is not None:
            return PortResolution(
                annotation=user_annotation,
                source=MatchSource.USER,
                reason="user-provided port type is authoritative",
                confidence="declared",
            )

        name = _canonical(_string(port_name, "port_name"))
        port_direction = _enum(PortDirection, direction, "direction")
        candidates: list[tuple[ProtocolProfile, PortRule]] = []
        for profile in self.query(protocol, interface_role):
            for rule in profile.ports:
                if port_direction is rule.direction and name in rule.aliases:
                    candidates.append((profile, rule))
        if not candidates:
            return PortResolution(
                annotation=None,
                source=MatchSource.UNRESOLVED,
                reason="no protocol port rule matched name and direction",
            )

        top_priority = max(profile.priority for profile, _ in candidates)
        best = [(profile, rule) for profile, rule in candidates if profile.priority == top_priority]
        semantics = {rule.semantic for _, rule in best}
        if len(semantics) != 1:
            names = ", ".join(sorted(profile.name for profile, _ in best))
            raise InputValidationError(
                f"ambiguous profile match for port {port_name!r} at priority {top_priority}: {names}"
            )
        profile, rule = sorted(best, key=lambda pair: pair[0].name)[0]
        return PortResolution(
            annotation=PortAnnotation(direction=port_direction, port_type=rule.semantic),
            source=MatchSource.PROFILE,
            reason=f"matched protocol alias {port_name!r}",
            profile_name=profile.name,
            confidence="profile",
        )


def _parse_port_rule(value: Any, path: str) -> PortRule:
    item = _mapping(value, path, allowed={"semantic", "direction", "aliases", "required"})
    semantic = _canonical(_string(item.get("semantic"), f"{path}.semantic"))
    direction = _enum(PortDirection, item.get("direction"), f"{path}.direction")
    raw_aliases = item.get("aliases")
    if not isinstance(raw_aliases, list) or not raw_aliases:
        _fail(f"{path}.aliases", "expected a non-empty array")
    aliases = tuple(_canonical(_string(alias, f"{path}.aliases[{index}]")) for index, alias in enumerate(raw_aliases))
    if len(aliases) != len(set(aliases)):
        _fail(f"{path}.aliases", "aliases must be unique")
    required = item.get("required", True)
    if not isinstance(required, bool):
        _fail(f"{path}.required", "expected a boolean")
    return PortRule(semantic=semantic, direction=direction, aliases=aliases, required=required)


def _parse_channel(value: Any, path: str) -> ChannelRule:
    item = _mapping(value, path, allowed={"name", "signals"})
    signals = tuple(
        _canonical(_string(signal, f"{path}.signals[{index}]"))
        for index, signal in enumerate(_array(item.get("signals"), f"{path}.signals", nonempty=True))
    )
    return ChannelRule(name=_canonical(_string(item.get("name"), f"{path}.name")), signals=signals)


def _parse_address_rule(value: Any, path: str) -> ProfileAddressRule:
    item = _mapping(value, path, allowed={"requires_window", "default_size", "alignment"})
    requires_window = item.get("requires_window")
    if not isinstance(requires_window, bool):
        _fail(f"{path}.requires_window", "expected a boolean")
    default_size = _optional_positive(item.get("default_size"), f"{path}.default_size")
    alignment = _optional_positive(item.get("alignment"), f"{path}.alignment")
    if alignment is not None and alignment & (alignment - 1):
        _fail(f"{path}.alignment", "expected a power of two")
    return ProfileAddressRule(requires_window, default_size, alignment)


def _mapping(value: Any, path: str, allowed: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, "expected an object")
    unknown = sorted(set(value) - allowed)
    if unknown:
        _fail(path, f"unknown field(s): {', '.join(unknown)}")
    return value


def _array(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "expected an array")
    if nonempty and not value:
        _fail(path, "expected a non-empty array")
    return value


def _string_array(value: Any, path: str) -> tuple[str, ...]:
    result = tuple(
        _string(item, f"{path}[{index}]")
        for index, item in enumerate(_array(value, path))
    )
    if len(result) != len(set(result)):
        _fail(path, "values must be unique")
    return result


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "expected a non-empty string")
    return value


def _canonical(value: str) -> str:
    return value.strip().lower()


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(path, "expected an integer")
    return value


def _optional_positive(value: Any, path: str) -> int | None:
    if value is None:
        return None
    result = _integer(value, path)
    if result <= 0:
        _fail(path, "expected an integer greater than zero")
    return result


def _enum(enum_type: type[Enum], value: Any, path: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        choices = ", ".join(repr(item.value) for item in enum_type)
        _fail(path, f"expected one of: {choices}")


def _fail(path: str, message: str) -> None:
    raise InputValidationError(f"{path}: {message}")
