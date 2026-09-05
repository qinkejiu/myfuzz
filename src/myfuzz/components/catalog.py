"""Load and safely query declared peripheral capability profiles."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .model import ComponentDefinitionError, PeripheralProfile


_PROFILE_FIELDS = frozenset(
    {
        "component_type",
        "module_name",
        "protocols",
        "address_alignment",
        "default_size",
        "irq_capable",
        "requires",
        "source_status",
        "source_paths",
        "implemented",
        "parameter_limits",
    }
)
_SOURCE_STATUSES = frozenset(("implemented", "reference"))
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
_PROTOCOL_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*\Z")
_PROTOCOL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_RUNTIME_PROTOCOLS = frozenset(
    {
        ("apb", "4"),
        ("axi4-lite", "1"),
        ("tl-ul", "1"),
    }
)


def _error(source: Path, message: str) -> ComponentDefinitionError:
    return ComponentDefinitionError(f"{source}: {message}")


def _require_string(value: object, label: str, source: Path) -> str:
    if not isinstance(value, str) or not value:
        raise _error(source, f"{label} must be a non-empty string")
    return value


def _require_identifier(value: object, label: str, source: Path) -> str:
    result = _require_string(value, label, source)
    if _IDENTIFIER.fullmatch(result) is None:
        raise _error(source, f"{label} must be an identifier")
    return result


def _require_positive_integer(value: object, label: str, source: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _error(source, f"{label} must be a positive integer")
    return value


def _parse_protocols(value: object, source: Path) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise _error(source, "protocols must be a non-empty list")
    protocols: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, list) or len(item) != 2:
            raise _error(source, f"protocols[{index}] must be a two-item list")
        protocol_id = _require_string(item[0], f"protocols[{index}][0]", source)
        version = _require_string(item[1], f"protocols[{index}][1]", source)
        if _PROTOCOL_ID.fullmatch(protocol_id) is None:
            raise _error(source, f"protocols[{index}][0] is invalid")
        if _PROTOCOL_VERSION.fullmatch(version) is None:
            raise _error(source, f"protocols[{index}][1] is invalid")
        protocol = (protocol_id, version)
        if protocol in seen:
            raise _error(source, f"duplicate protocol: {protocol_id}@{version}")
        seen.add(protocol)
        protocols.append(protocol)
    return tuple(protocols)


def _parse_source_path(value: object, label: str, source: Path) -> str:
    result = _require_string(value, label, source)
    if "\x00" in result:
        raise _error(source, f"{label} must not contain NUL bytes")
    posix = PurePosixPath(result)
    windows = PureWindowsPath(result)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or "\\" in result
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise _error(source, f"{label} must be a normalized relative path")
    if posix.as_posix() != result:
        raise _error(source, f"{label} must be a normalized relative path")
    return result


def _parse_source_paths(value: object, source: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise _error(source, "source_paths must be a non-empty list")
    paths = tuple(
        _parse_source_path(item, f"source_paths[{index}]", source)
        for index, item in enumerate(value)
    )
    if len(paths) != len(set(paths)):
        raise _error(source, "source_paths must be unique")
    return paths


def _parse_requires(value: object, source: Path) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _error(source, "requires must be a list")
    requires = tuple(
        _require_identifier(item, f"requires[{index}]", source)
        for index, item in enumerate(value)
    )
    if len(requires) != len(set(requires)):
        raise _error(source, "requires must contain unique component types")
    return requires


def _parse_parameter_limits(
    value: object, source: Path
) -> dict[str, tuple[int, int]]:
    if not isinstance(value, dict):
        raise _error(source, "parameter_limits must be an object")
    limits: dict[str, tuple[int, int]] = {}
    for name, bounds in value.items():
        parameter_name = _require_identifier(name, "parameter_limits key", source)
        if not isinstance(bounds, list) or len(bounds) != 2:
            raise _error(source, f"parameter_limits.{parameter_name} must be a two-item list")
        lower = bounds[0]
        upper = bounds[1]
        if (
            isinstance(lower, bool)
            or not isinstance(lower, int)
            or isinstance(upper, bool)
            or not isinstance(upper, int)
            or lower > upper
        ):
            raise _error(source, f"parameter_limits.{parameter_name} must be an integer range")
        limits[parameter_name] = (lower, upper)
    return limits


def _parse_profile(document: object, source: Path) -> PeripheralProfile:
    if not isinstance(document, dict):
        raise _error(source, "profile document must be an object")
    unknown = sorted(set(document) - _PROFILE_FIELDS)
    if unknown:
        raise _error(source, f"unknown profile fields: {', '.join(unknown)}")
    missing = sorted(_PROFILE_FIELDS - set(document))
    if missing:
        raise _error(source, f"missing profile fields: {', '.join(missing)}")

    component_type = _require_identifier(document["component_type"], "component_type", source)
    module_name = _require_identifier(document["module_name"], "module_name", source)
    protocols = _parse_protocols(document["protocols"], source)
    address_alignment = _require_positive_integer(
        document["address_alignment"], "address_alignment", source
    )
    if address_alignment & (address_alignment - 1):
        raise _error(source, "address_alignment must be a power of two")
    default_size = _require_positive_integer(document["default_size"], "default_size", source)
    if default_size % address_alignment:
        raise _error(source, "default_size must be aligned to address_alignment")
    irq_capable = document["irq_capable"]
    if not isinstance(irq_capable, bool):
        raise _error(source, "irq_capable must be boolean")
    requires = _parse_requires(document["requires"], source)
    source_status = _require_string(document["source_status"], "source_status", source)
    if source_status not in _SOURCE_STATUSES:
        raise _error(source, f"unsupported source_status: {source_status}")
    source_paths = _parse_source_paths(document["source_paths"], source)
    implemented = document["implemented"]
    if not isinstance(implemented, bool):
        raise _error(source, "implemented must be boolean")
    if implemented != (source_status == "implemented"):
        raise _error(source, "implemented and source_status disagree")
    parameter_limits = _parse_parameter_limits(document["parameter_limits"], source)

    return PeripheralProfile(
        component_type=component_type,
        module_name=module_name,
        protocols=protocols,
        address_alignment=address_alignment,
        default_size=default_size,
        irq_capable=irq_capable,
        requires=requires,
        source_status=source_status,
        source_paths=source_paths,
        implemented=implemented,
        parameter_limits=parameter_limits,
    )


class _DuplicateJsonKey(ValueError):
    def __init__(self, key: object) -> None:
        super().__init__(str(key))
        self.key = key


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _load_profile(source: Path) -> PeripheralProfile:
    try:
        document = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except _DuplicateJsonKey as error:
        raise _error(source, f"duplicate JSON field: {error.key}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise _error(source, f"invalid JSON: {error}") from error
    return _parse_profile(document, source)


class ComponentCatalog:
    """A deterministic, closed set of peripheral capability profiles."""

    def __init__(self, profiles: tuple[PeripheralProfile, ...]) -> None:
        records = tuple(profiles)
        if not all(isinstance(profile, PeripheralProfile) for profile in records):
            raise ComponentDefinitionError("catalog profiles must be PeripheralProfile records")
        by_type: dict[str, PeripheralProfile] = {}
        for profile in records:
            if profile.component_type in by_type:
                raise ComponentDefinitionError(
                    f"duplicate component type: {profile.component_type}"
                )
            by_type[profile.component_type] = profile
        if not records:
            raise ComponentDefinitionError("catalog contains no profiles")
        for profile in records:
            unknown = sorted(set(profile.requires) - set(by_type))
            if unknown:
                raise ComponentDefinitionError(
                    f"{profile.component_type}: unknown dependency: {unknown[0]}"
                )
        self._profiles = tuple(sorted(records, key=lambda profile: profile.component_type))
        self._by_type = by_type

    def require(self, component_type: str) -> PeripheralProfile:
        if not isinstance(component_type, str) or not component_type:
            raise ComponentDefinitionError("component_type must be a non-empty string")
        try:
            return self._by_type[component_type]
        except KeyError as error:
            raise ComponentDefinitionError(
                f"unsupported component type: {component_type}"
            ) from error

    @property
    def profiles(self) -> tuple[PeripheralProfile, ...]:
        return self._profiles

    def available(
        self,
        component_type: str,
        *,
        root: Path,
        protocol: tuple[str, str] | None = None,
    ) -> PeripheralProfile:
        profile = self.require(component_type)
        selected_protocol: tuple[str, str] | None = None
        if protocol is not None:
            if (
                not isinstance(protocol, tuple)
                or len(protocol) != 2
                or not all(isinstance(item, str) and item for item in protocol)
            ):
                raise ComponentDefinitionError("protocol must be a (protocol_id, version) tuple")
            selected_protocol = protocol
            if selected_protocol not in profile.protocols:
                raise ComponentDefinitionError(
                    f"unsupported protocol version for {component_type}: "
                    f"{selected_protocol[0]}@{selected_protocol[1]}"
                )
        if not profile.implemented or profile.source_status != "implemented":
            raise ComponentDefinitionError(
                f"component is reference-only: {component_type}"
            )
        root_path = Path(root)
        if not root_path.is_dir():
            raise ComponentDefinitionError(f"repository root does not exist: {root_path}")
        resolved_root = root_path.resolve()
        for source_path in profile.source_paths:
            resolved_source = (resolved_root / source_path).resolve()
            try:
                resolved_source.relative_to(resolved_root)
            except ValueError as error:
                raise ComponentDefinitionError(
                    f"source path escapes repository root: {source_path}"
                ) from error
            if not resolved_source.is_file():
                raise ComponentDefinitionError(
                    f"missing component source: {source_path}"
                )
        if selected_protocol is None:
            has_runtime_protocol = any(
                pair in _RUNTIME_PROTOCOLS for pair in profile.protocols
            )
        else:
            has_runtime_protocol = selected_protocol in _RUNTIME_PROTOCOLS
        if not has_runtime_protocol:
            selected_label = "any" if selected_protocol is None else (
                f"{selected_protocol[0]}@{selected_protocol[1]}"
            )
            raise ComponentDefinitionError(
                f"runtime protocol is not implemented: {selected_label}"
            )
        return profile


def load_component_catalog(path: str | Path) -> ComponentCatalog:
    """Load every JSON profile in *path* using deterministic filename order."""
    directory = Path(path)
    if not directory.is_dir():
        raise ComponentDefinitionError(f"profile directory does not exist: {directory}")
    sources = tuple(sorted(directory.glob("*.json")))
    if not sources:
        raise ComponentDefinitionError(f"profile directory contains no JSON profiles: {directory}")
    profiles = tuple(_load_profile(source) for source in sources)
    return ComponentCatalog(profiles)


@lru_cache(maxsize=1)
def load_builtin_component_catalog() -> ComponentCatalog:
    """Return the cached catalog shipped with MyFuzz."""
    return load_component_catalog(Path(__file__).with_name("profiles"))


__all__ = [
    "ComponentCatalog",
    "ComponentDefinitionError",
    "load_builtin_component_catalog",
    "load_component_catalog",
]
