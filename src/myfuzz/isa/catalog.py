"""Load and query the strict CPU/ISA profile catalog."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType

from .model import CpuDefinitionError, CpuProfile


_PROFILE_FIELDS = frozenset(
    {
        "cpu_id",
        "vendor",
        "xlen",
        "extensions",
        "core_native_protocols",
        "integration_protocols",
        "source_status",
        "source_paths",
        "implemented",
    }
)
_SOURCE_STATUSES = frozenset({"implemented", "reference"})
_PROTOCOL_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*\Z")
_PROTOCOL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_RUNTIME_PROTOCOLS = frozenset(
    {
        ("apb", "4"),
        ("axi4-lite", "1"),
        ("tl-ul", "1"),
    }
)


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _DuplicateJsonKey(key)
        document[key] = value
    return document


class CpuCatalog:
    """An immutable, exact-ID index of CPU profiles."""

    __slots__ = ("_profiles", "_by_id")

    def __init__(self, profiles: tuple[CpuProfile, ...]) -> None:
        ordered = tuple(sorted(profiles, key=lambda profile: profile.cpu_id))
        if not ordered:
            raise CpuDefinitionError("catalog contains no profiles")
        by_id: dict[str, CpuProfile] = {}
        for profile in ordered:
            if not isinstance(profile, CpuProfile):
                raise CpuDefinitionError("catalog profiles must be CpuProfile records")
            if profile.cpu_id in by_id:
                raise CpuDefinitionError(f"duplicate declared cpu_id: {profile.cpu_id}")
            by_id[profile.cpu_id] = profile
        self._profiles = ordered
        self._by_id = MappingProxyType(by_id)

    def require(self, cpu_id: str) -> CpuProfile:
        if not isinstance(cpu_id, str) or not cpu_id:
            raise CpuDefinitionError("cpu_id must be a non-empty string")
        try:
            return self._by_id[cpu_id]
        except KeyError as error:
            raise CpuDefinitionError(f"unsupported CPU profile: {cpu_id}") from error

    @property
    def profiles(self) -> tuple[CpuProfile, ...]:
        return self._profiles

    def compatible_protocols(
        self,
        cpu_id: str,
        *,
        runtime_only: bool = True,
    ) -> tuple[tuple[str, str], ...]:
        """Return declared protocols, restricted to tested runtime bindings by default."""
        profile = self.require(cpu_id)
        if runtime_only and (
            not profile.implemented or profile.source_status != "implemented"
        ):
            return ()

        protocols: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for protocol in profile.core_native_protocols + profile.integration_protocols:
            if runtime_only and protocol not in _RUNTIME_PROTOCOLS:
                continue
            if protocol not in seen:
                seen.add(protocol)
                protocols.append(protocol)
        return tuple(protocols)


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CpuDefinitionError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise CpuDefinitionError(f"{label} must not have surrounding whitespace")
    return value


def _require_boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise CpuDefinitionError(f"{label} must be boolean")
    return value


def _parse_xlen(value: object, source: Path) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise CpuDefinitionError(f"{source}: xlen must be a non-empty list")
    result: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item not in {32, 64}:
            raise CpuDefinitionError(f"{source}: xlen values must be 32 or 64")
        if item in result:
            raise CpuDefinitionError(f"{source}: duplicate xlen: {item}")
        result.append(item)
    return tuple(result)


def _parse_extensions(value: object, source: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise CpuDefinitionError(f"{source}: extensions must be a non-empty list")
    result: list[str] = []
    for item in value:
        extension = _require_string(item, "extension")
        if extension in result:
            raise CpuDefinitionError(f"{source}: duplicate extension: {extension}")
        result.append(extension)
    return tuple(result)


def _parse_protocols(value: object, label: str, source: Path) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise CpuDefinitionError(f"{source}: {label} must be a list")
    result: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, list) or len(item) != 2:
            raise CpuDefinitionError(f"{source}: {label}[{index}] must be a [protocol, version] pair")
        protocol_id = _require_string(item[0], f"{label}[{index}].protocol_id")
        version = _require_string(item[1], f"{label}[{index}].version")
        if _PROTOCOL_ID.fullmatch(protocol_id) is None:
            raise CpuDefinitionError(f"{source}: {label}[{index}].protocol_id is invalid")
        if _PROTOCOL_VERSION.fullmatch(version) is None:
            raise CpuDefinitionError(f"{source}: {label}[{index}].version is invalid")
        pair = (protocol_id, version)
        if pair in seen:
            raise CpuDefinitionError(f"{source}: duplicate {label} pair: {protocol_id}@{version}")
        seen.add(pair)
        result.append(pair)
    return tuple(result)


def _safe_source_path(value: object, label: str, source: Path) -> str:
    path = _require_string(value, label)
    if "\x00" in path or "\\" in path:
        raise CpuDefinitionError(f"{source}: {label} must use a safe relative path")
    if PurePosixPath(path).is_absolute():
        raise CpuDefinitionError(f"{source}: {label} must be relative")
    windows_path = PureWindowsPath(path)
    if windows_path.is_absolute() or windows_path.drive:
        raise CpuDefinitionError(f"{source}: {label} must be relative")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CpuDefinitionError(f"{source}: {label} contains an unsafe path component")
    return path


def _source_root(catalog_dir: Path) -> Path:
    resolved = catalog_dir.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / "src" / "myfuzz").is_dir():
            return candidate
    return resolved


def _source_paths_exist(source_paths: tuple[str, ...], root: Path, source: Path) -> bool:
    resolved_root = root.resolve()
    all_exist = True
    for source_path in source_paths:
        candidate = root / source_path
        try:
            resolved_candidate = candidate.resolve(strict=False)
            resolved_candidate.relative_to(resolved_root)
        except (OSError, ValueError) as error:
            raise CpuDefinitionError(f"{source}: source path escapes supplied root: {source_path}") from error
        if not candidate.exists():
            all_exist = False
    return all_exist


def _parse_profile(document: object, source: Path, root: Path) -> CpuProfile:
    if not isinstance(document, dict):
        raise CpuDefinitionError(f"{source}: profile document must be an object")
    unknown = set(document) - _PROFILE_FIELDS
    missing = _PROFILE_FIELDS - set(document)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise CpuDefinitionError(f"{source}: unknown profile field(s): {names}")
    if missing:
        names = ", ".join(sorted(missing))
        raise CpuDefinitionError(f"{source}: missing profile field(s): {names}")

    cpu_id = _require_string(document["cpu_id"], "cpu_id")
    vendor = _require_string(document["vendor"], "vendor")
    xlen = _parse_xlen(document["xlen"], source)
    extensions = _parse_extensions(document["extensions"], source)
    core_native_protocols = _parse_protocols(document["core_native_protocols"], "core_native_protocols", source)
    integration_protocols = _parse_protocols(document["integration_protocols"], "integration_protocols", source)
    source_status = _require_string(document["source_status"], "source_status")
    if source_status not in _SOURCE_STATUSES:
        raise CpuDefinitionError(f"{source}: invalid source_status: {source_status}")

    source_paths_raw = document["source_paths"]
    if not isinstance(source_paths_raw, list) or not source_paths_raw:
        raise CpuDefinitionError(f"{source}: source_paths must be a non-empty list")
    source_paths: list[str] = []
    for index, item in enumerate(source_paths_raw):
        source_path = _safe_source_path(item, f"source_paths[{index}]", source)
        if source_path in source_paths:
            raise CpuDefinitionError(f"{source}: duplicate source path: {source_path}")
        source_paths.append(source_path)

    declared_implemented = _require_boolean(document["implemented"], "implemented")
    if declared_implemented != (source_status == "implemented"):
        raise CpuDefinitionError(f"{source}: implemented and source_status disagree")
    implemented = (
        declared_implemented
        and source_status == "implemented"
        # `implemented` is effective availability: every declared source,
        # including upstream dependencies, must exist below the source root.
        and _source_paths_exist(tuple(source_paths), root, source)
    )
    return CpuProfile(
        cpu_id=cpu_id,
        vendor=vendor,
        xlen=xlen,
        extensions=extensions,
        core_native_protocols=core_native_protocols,
        integration_protocols=integration_protocols,
        source_status=source_status,
        source_paths=tuple(source_paths),
        implemented=implemented,
    )


def _catalog_directory(path: str | Path) -> tuple[Path, Path]:
    supplied = Path(path)
    if not supplied.is_dir():
        raise CpuDefinitionError(f"CPU profile directory does not exist: {supplied}")

    direct_profiles = tuple(supplied.glob("*.json"))
    if direct_profiles:
        catalog_dir = supplied.resolve()
        return catalog_dir, _source_root(catalog_dir)

    repository_profiles = supplied / "src" / "myfuzz" / "isa" / "profiles"
    if repository_profiles.is_dir():
        return repository_profiles.resolve(), supplied.resolve()

    nested_profiles = supplied / "profiles"
    if nested_profiles.is_dir():
        return nested_profiles.resolve(), supplied.resolve()

    return supplied.resolve(), _source_root(supplied)


def load_cpu_catalog(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> CpuCatalog:
    """Load every JSON profile below *path* using strict fail-closed parsing.

    ``root`` overrides the source root used to calculate effective
    implementation availability.  This is useful when the profile catalog is
    packaged separately from the checkout containing its declared sources.
    """
    catalog_dir, inferred_root = _catalog_directory(path)
    source_root = inferred_root if root is None else Path(root)
    if not source_root.is_dir():
        raise CpuDefinitionError(f"CPU source root does not exist: {source_root}")
    source_root = source_root.resolve()
    profiles: list[CpuProfile] = []
    for source in sorted(catalog_dir.glob("*.json")):
        try:
            document = json.loads(
                source.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except _DuplicateJsonKey as error:
            raise CpuDefinitionError(f"{source}: duplicate JSON key: {error}") from error
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CpuDefinitionError(f"{source}: cannot read profile: {error}") from error
        profiles.append(_parse_profile(document, source, source_root))
    return CpuCatalog(tuple(profiles))


@lru_cache(maxsize=1)
def _load_default_builtin_cpu_catalog() -> CpuCatalog:
    return load_cpu_catalog(Path(__file__).with_name("profiles"))


def load_builtin_cpu_catalog(root: str | Path | None = None) -> CpuCatalog:
    """Load the built-in profiles, optionally evaluating sources under *root*.

    The no-argument form retains the historical package-root cache.  A
    supplied root deliberately bypasses that cache so effective availability
    reflects the checkout being planned.
    """
    if root is None:
        return _load_default_builtin_cpu_catalog()
    return load_cpu_catalog(Path(__file__).with_name("profiles"), root=root)


__all__ = ["CpuCatalog", "load_builtin_cpu_catalog", "load_cpu_catalog"]
