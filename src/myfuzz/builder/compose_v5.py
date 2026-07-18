"""Strict Slice 0 contracts and qualification for compose-v5-auto."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import json
from pathlib import Path
import re
from typing import Iterable, Mapping

from .contracts import ManifestError, build_elaboration_manifest, canonical_json, content_digest
from .input_model import InputValidationError


COMPOSE_V5_MANIFEST_SCHEMA = "myfuzz.compose-v5-manifest/v1"
COMPOSE_V5_QUALIFICATION_SCHEMA = "myfuzz.compose-v5-qualification/v1"
COMPOSE_V5_TARGET_AUDIT_SCHEMA = "myfuzz.compose-v5-target-audit/v1"


class ComposeV5Role(str, Enum):
    CPU = "cpu"
    RAM = "ram"
    IP = "ip"


class ComposeV5Failure(str, Enum):
    TARGET_UNAVAILABLE = "target_unavailable"
    SOURCE_UNTRUSTED = "source_untrusted"
    ELABORATION_FAILED = "elaboration_failed"
    TOP_ABSENT = "top_absent"
    FRONTEND_UNAVAILABLE = "frontend_unavailable"


@dataclass(frozen=True)
class ComposeV5SourceSet:
    id: str
    rtl_files: tuple[str, ...]
    filelists: tuple[str, ...]


@dataclass(frozen=True)
class ComposeV5Component:
    id: str
    role: ComposeV5Role
    module: str
    source_set: str
    parameters: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ComposeV5Manifest:
    name: str
    sources: tuple[ComposeV5SourceSet, ...]
    components: tuple[ComposeV5Component, ...]
    digest: str = ""
    schema: str = COMPOSE_V5_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        _text(self.name, "manifest.name")
        if self.schema != COMPOSE_V5_MANIFEST_SCHEMA:
            raise InputValidationError(f"unsupported compose-v5 manifest schema: {self.schema}")
        source_ids = [item.id for item in self.sources]
        component_ids = [item.id for item in self.components]
        _unique(source_ids, "manifest.sources", "source id")
        _unique(component_ids, "manifest.components", "component id")
        if not self.sources:
            raise InputValidationError("manifest.sources must not be empty")
        for source in self.sources:
            _text(source.id, "manifest source id")
            if not source.rtl_files and not source.filelists:
                raise InputValidationError(
                    f"manifest source set {source.id!r} needs rtl_files or filelists"
                )
            _relative_paths(source.rtl_files, f"manifest.sources[{source.id}].rtl_files")
            _relative_paths(source.filelists, f"manifest.sources[{source.id}].filelists")
        source_id_set = set(source_ids)
        roles = [item.role for item in self.components]
        if roles.count(ComposeV5Role.CPU) != 1 or roles.count(ComposeV5Role.RAM) != 1:
            raise InputValidationError("compose-v5 requires exactly one CPU and one RAM")
        if roles.count(ComposeV5Role.IP) < 2:
            raise InputValidationError("compose-v5 coverage experiment requires at least two IPs")
        for component in self.components:
            _text(component.id, "manifest component id")
            _text(component.module, f"manifest.components[{component.id}].module")
            if component.source_set not in source_id_set:
                raise InputValidationError(
                    f"component {component.id!r} references unknown source set {component.source_set!r}"
                )
            names = [name for name, _value in component.parameters]
            _unique(names, f"manifest.components[{component.id}].parameters", "parameter")
        expected = content_digest(self.payload())
        if self.digest and self.digest != expected:
            raise InputValidationError("compose-v5 manifest digest mismatch")

    def payload(self) -> dict[str, object]:
        value = self.to_dict()
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "sources": [asdict(item) for item in self.sources],
            "components": [
                {
                    "id": item.id,
                    "role": item.role.value,
                    "module": item.module,
                    "source_set": item.source_set,
                    "parameters": {name: value for name, value in item.parameters},
                }
                for item in self.components
            ],
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ComposeV5ComponentQualification:
    component_id: str
    role: str
    top_module: str
    source_set: str
    status: str
    failure_code: str
    reason: str
    elaboration_digest: str
    frontend_schema: str
    source_count: int


@dataclass(frozen=True)
class ComposeV5Qualification:
    manifest_digest: str
    eligible: bool
    components: tuple[ComposeV5ComponentQualification, ...]
    failure_codes: tuple[str, ...]
    digest: str = ""
    schema: str = COMPOSE_V5_QUALIFICATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != COMPOSE_V5_QUALIFICATION_SCHEMA:
            raise InputValidationError("unsupported compose-v5 qualification schema")
        _digest(self.manifest_digest, "qualification.manifest_digest")
        identifiers = [item.component_id for item in self.components]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            raise InputValidationError("qualification components must be unique and sorted")
        expected_eligible = bool(self.components) and all(item.status == "qualified" for item in self.components)
        if self.eligible != expected_eligible:
            raise InputValidationError("qualification eligible flag does not match component results")
        expected_codes = tuple(sorted({item.failure_code for item in self.components if item.failure_code}))
        if self.failure_codes != expected_codes:
            raise InputValidationError("qualification failure codes do not match component results")
        expected = content_digest(self.payload())
        if self.digest and self.digest != expected:
            raise InputValidationError("compose-v5 qualification digest mismatch")

    def payload(self) -> dict[str, object]:
        value = self.to_dict()
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ComposeV5TargetResult:
    target_id: str
    manifest_path: str
    status: str
    failure_code: str
    reason: str
    manifest_digest: str
    qualification_digest: str


@dataclass(frozen=True)
class ComposeV5TargetAudit:
    targets: tuple[ComposeV5TargetResult, ...]
    all_eligible: bool
    digest: str = ""
    schema: str = COMPOSE_V5_TARGET_AUDIT_SCHEMA

    def __post_init__(self) -> None:
        identifiers = [item.target_id for item in self.targets]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            raise InputValidationError("target audit entries must be unique and sorted")
        if self.all_eligible != (bool(self.targets) and all(item.status == "qualified" for item in self.targets)):
            raise InputValidationError("target audit all_eligible flag mismatch")
        expected = content_digest(self.payload())
        if self.digest and self.digest != expected:
            raise InputValidationError("compose-v5 target audit digest mismatch")

    def payload(self) -> dict[str, object]:
        value = self.to_dict()
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compose_v5_manifest_from_dict(value: Mapping[str, object]) -> ComposeV5Manifest:
    _fields(value, {"schema", "name", "sources", "components", "digest"}, "manifest")
    if value.get("schema") != COMPOSE_V5_MANIFEST_SCHEMA:
        raise InputValidationError("compose-v5 manifest schema mismatch")
    sources = []
    for index, raw in enumerate(_objects(value.get("sources"), "manifest.sources")):
        path = f"manifest.sources[{index}]"
        _fields(raw, {"id", "rtl_files", "filelists"}, path)
        sources.append(ComposeV5SourceSet(
            id=_text(raw.get("id"), f"{path}.id"),
            rtl_files=tuple(_strings(raw.get("rtl_files"), f"{path}.rtl_files")),
            filelists=tuple(_strings(raw.get("filelists"), f"{path}.filelists")),
        ))
    components = []
    for index, raw in enumerate(_objects(value.get("components"), "manifest.components")):
        path = f"manifest.components[{index}]"
        _fields(raw, {"id", "role", "module", "source_set", "parameters"}, path)
        try:
            role = ComposeV5Role(raw.get("role"))
        except ValueError as exc:
            raise InputValidationError(f"{path}.role: expected cpu, ram, or ip") from exc
        parameters = raw.get("parameters")
        if not isinstance(parameters, Mapping):
            raise InputValidationError(f"{path}.parameters: expected an object")
        normalized_parameters = []
        for name, parameter in parameters.items():
            parameter_name = _text(name, f"{path}.parameters key")
            if isinstance(parameter, bool) or not isinstance(parameter, (int, str)):
                raise InputValidationError(f"{path}.parameters.{parameter_name}: expected integer or string")
            normalized_parameters.append((parameter_name, str(parameter)))
        components.append(ComposeV5Component(
            id=_text(raw.get("id"), f"{path}.id"), role=role,
            module=_text(raw.get("module"), f"{path}.module"),
            source_set=_text(raw.get("source_set"), f"{path}.source_set"),
            parameters=tuple(sorted(normalized_parameters)),
        ))
    manifest = ComposeV5Manifest(
        name=_text(value.get("name"), "manifest.name"),
        sources=tuple(sorted(sources, key=lambda item: item.id)),
        components=tuple(sorted(components, key=lambda item: item.id)),
        digest=_digest(value.get("digest"), "manifest.digest", allow_empty=True),
    )
    return manifest if manifest.digest else replace(manifest, digest=content_digest(manifest.payload()))


def load_compose_v5_manifest(path: str | Path) -> ComposeV5Manifest:
    manifest_path = Path(path)
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"cannot read compose-v5 manifest {manifest_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise InputValidationError("compose-v5 manifest must contain an object")
    return compose_v5_manifest_from_dict(raw)


def qualify_compose_v5_manifest(
    manifest: ComposeV5Manifest,
    *,
    project_root: str | Path,
    allow_roots: Iterable[str | Path] | None = None,
    verify_elaboration: bool = False,
    frontend_library: str | Path | None = None,
) -> ComposeV5Qualification:
    root = Path(project_root).resolve(strict=True)
    roots = tuple(allow_roots) if allow_roots is not None else (root,)
    by_source = {item.id: item for item in manifest.sources}
    results: list[ComposeV5ComponentQualification] = []
    for component in manifest.components:
        source = by_source[component.source_set]
        try:
            elaboration = build_elaboration_manifest(
                top_module=component.module,
                rtl_files=(root / item for item in source.rtl_files),
                filelists=(root / item for item in source.filelists),
                allow_roots=roots,
                parameters=dict(component.parameters),
                tools={"frontend": "myfuzz-verilator-ast"},
            )
            _reject_unsafe_rtl(Path(item.path) for item in elaboration.sources)
            frontend_schema = "not-run"
            if verify_elaboration:
                from .rtl_analysis import analyze_elaboration

                analysis = analyze_elaboration(
                    elaboration, project_root=root, frontend_library=frontend_library,
                )
                frontend_schema = analysis.frontend_schema
                if not any(
                    item.original_name == component.module or item.name == component.module
                    for item in analysis.modules
                ):
                    raise _QualificationFailure(
                        ComposeV5Failure.TOP_ABSENT,
                        f"top module {component.module!r} is absent from frontend output",
                    )
            results.append(ComposeV5ComponentQualification(
                component.id, component.role.value, component.module, component.source_set,
                "qualified", "", "qualified", elaboration.digest, frontend_schema,
                len(elaboration.sources),
            ))
        except _QualificationFailure as exc:
            results.append(_failed_component(component, exc.code, str(exc)))
        except ManifestError as exc:
            results.append(_failed_component(component, ComposeV5Failure.TARGET_UNAVAILABLE, str(exc)))
        except InputValidationError as exc:
            code = (
                ComposeV5Failure.FRONTEND_UNAVAILABLE
                if "frontend library does not exist" in str(exc)
                else ComposeV5Failure.ELABORATION_FAILED
            )
            results.append(_failed_component(component, code, str(exc)))
        except OSError as exc:
            results.append(_failed_component(component, ComposeV5Failure.TARGET_UNAVAILABLE, str(exc)))
    ordered = tuple(sorted(results, key=lambda item: item.component_id))
    report = ComposeV5Qualification(
        manifest_digest=manifest.digest,
        eligible=bool(ordered) and all(item.status == "qualified" for item in ordered),
        components=ordered,
        failure_codes=tuple(sorted({item.failure_code for item in ordered if item.failure_code})),
    )
    return replace(report, digest=content_digest(report.payload()))


def audit_compose_v5_targets(
    targets: Mapping[str, str | Path],
    *,
    project_root: str | Path,
    allow_roots: Iterable[str | Path] | None = None,
    verify_elaboration: bool = False,
    frontend_library: str | Path | None = None,
) -> ComposeV5TargetAudit:
    root = Path(project_root).resolve(strict=True)
    results: list[ComposeV5TargetResult] = []
    for target_id, value in sorted(targets.items()):
        _text(target_id, "target id")
        path = Path(value)
        path = path if path.is_absolute() else root / path
        display = _display_path(path, root)
        try:
            manifest = load_compose_v5_manifest(path)
            qualification = qualify_compose_v5_manifest(
                manifest, project_root=root, allow_roots=allow_roots,
                verify_elaboration=verify_elaboration, frontend_library=frontend_library,
            )
            first_failure = next((item for item in qualification.components if item.status != "qualified"), None)
            results.append(ComposeV5TargetResult(
                target_id, display, "qualified" if qualification.eligible else "rejected",
                "" if qualification.eligible else first_failure.failure_code,
                "qualified" if qualification.eligible else first_failure.reason,
                manifest.digest, qualification.digest,
            ))
        except InputValidationError as exc:
            results.append(ComposeV5TargetResult(
                target_id, display, "unavailable", ComposeV5Failure.TARGET_UNAVAILABLE.value,
                str(exc), "", "",
            ))
    ordered = tuple(results)
    audit = ComposeV5TargetAudit(ordered, bool(ordered) and all(item.status == "qualified" for item in ordered))
    return replace(audit, digest=content_digest(audit.payload()))


def write_compose_v5_json(value: object, path: str | Path) -> Path:
    if not hasattr(value, "to_dict"):
        raise InputValidationError("compose-v5 artifact must provide to_dict()")
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json(value.to_dict()) + b"\n")
    return output


class _QualificationFailure(ValueError):
    def __init__(self, code: ComposeV5Failure, reason: str) -> None:
        super().__init__(reason)
        self.code = code


_UNSAFE_TASKS = re.compile(
    r"\$(?:system|shell|fopen|fclose|fread|fwrite|fdisplay|fmonitor|fstrobe)\b",
    re.IGNORECASE,
)
_UNSAFE_DPI = re.compile(
    r"\bimport\s+\"DPI(?:-C)?\"",
    re.IGNORECASE,
)


def _reject_unsafe_rtl(paths: Iterable[Path]) -> None:
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise _QualificationFailure(ComposeV5Failure.TARGET_UNAVAILABLE, str(exc)) from exc
        comment_free = _without_comments(text)
        match = _UNSAFE_TASKS.search(_without_strings(comment_free))
        if match is None:
            match = _UNSAFE_DPI.search(comment_free)
        if match:
            raise _QualificationFailure(
                ComposeV5Failure.SOURCE_UNTRUSTED,
                f"{path}: forbidden host-effect RTL construct {match.group(0)!r}",
            )


def _without_comments(text: str) -> str:
    result: list[str] = []
    index = 0
    state = "code"
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if current == "/" and following == "/":
                result.extend("  "); index += 2; state = "line"
            elif current == "/" and following == "*":
                result.extend("  "); index += 2; state = "block"
            else:
                result.append(current); index += 1
        elif state == "line":
            if current == "\n":
                result.append("\n"); state = "code"
            else:
                result.append(" ")
            index += 1
        elif state == "block":
            if current == "*" and following == "/":
                result.extend("  "); index += 2; state = "code"
            else:
                result.append("\n" if current == "\n" else " "); index += 1
    return "".join(result)


def _without_strings(text: str) -> str:
    result: list[str] = []
    index = 0
    in_string = False
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if not in_string:
            if current == '"':
                result.append(" ")
                in_string = True
            else:
                result.append(current)
            index += 1
        elif current == "\\" and following:
            result.extend("  ")
            index += 2
        elif current == '"':
            result.append(" ")
            in_string = False
            index += 1
        else:
            result.append("\n" if current == "\n" else " ")
            index += 1
    return "".join(result)


def _failed_component(
    component: ComposeV5Component, code: ComposeV5Failure, reason: str,
) -> ComposeV5ComponentQualification:
    return ComposeV5ComponentQualification(
        component.id, component.role.value, component.module, component.source_set,
        "rejected", code.value, reason, "", "", 0,
    )


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _relative_paths(values: Iterable[str], path: str) -> None:
    for index, value in enumerate(values):
        candidate = Path(value)
        if not value or candidate.is_absolute() or ".." in candidate.parts:
            raise InputValidationError(f"{path}[{index}]: expected a relative non-escaping path")


def _objects(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, Mapping) for item in value):
        raise InputValidationError(f"{path}: expected an array of objects")
    return tuple(value)


def _strings(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise InputValidationError(f"{path}: expected an array of strings")
    return tuple(value)


def _fields(value: Mapping[str, object], expected: set[str], path: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        raise InputValidationError(
            f"{path}: field mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _digest(value: object, path: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
    return value


def _unique(values: Iterable[str], path: str, label: str) -> None:
    items = list(values)
    if len(items) != len(set(items)):
        raise InputValidationError(f"{path}: duplicate {label}")
