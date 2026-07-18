"""Shared, read-only RTL analysis backed exclusively by the Verilator AST frontend."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from myfuzz.scripts.frontend_api import default_frontend_library, isolated_frontend_manifest

from .contracts.manifest import ElaborationManifest
from .input_model import InputValidationError, PortDirection


class EvidenceState(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    NON_PROVABLE = "non_provable"


FRONTEND_SUPPORT_MATRIX = {
    "generate": EvidenceState.KNOWN,
    "parameter_override": EvidenceState.KNOWN,
    "package_import": EvidenceState.KNOWN,
    "macro_definition": EvidenceState.KNOWN,
    "packed_port": EvidenceState.KNOWN,
    "fixed_unpacked_port": EvidenceState.KNOWN,
    "fixed_unpacked_memory": EvidenceState.KNOWN,
    "black_box": EvidenceState.NON_PROVABLE,
    "dpi": EvidenceState.NON_PROVABLE,
    "tri_state": EvidenceState.NON_PROVABLE,
    "force_release": EvidenceState.NON_PROVABLE,
    "timing_control": EvidenceState.NON_PROVABLE,
    "behavioral_memory": EvidenceState.NON_PROVABLE,
}


@dataclass(frozen=True)
class Evidence:
    state: EvidenceState
    source: str
    reason: str


@dataclass(frozen=True)
class RTLPort:
    name: str
    direction: PortDirection
    width: int
    packed_width: int
    unpacked_ranges: tuple[tuple[int, int], ...]
    signed: bool | None
    evidence: Evidence


@dataclass(frozen=True)
class RTLPinBinding:
    port: str
    direction: PortDirection
    width: int
    expression_kind: str
    signals: tuple[str, ...]
    evidence: Evidence


@dataclass(frozen=True)
class RTLInstance:
    name: str
    module_type: str
    pins: tuple[RTLPinBinding, ...]
    evidence: Evidence


@dataclass(frozen=True)
class RTLMemory:
    name: str
    word_width: int
    depth: int
    unpacked_ranges: tuple[tuple[int, int], ...]
    evidence: Evidence


@dataclass(frozen=True)
class SignalDependency:
    target: str
    sources: tuple[str, ...]
    kind: str
    evidence: Evidence


@dataclass(frozen=True)
class AnalysisLimitation:
    module: str
    signals: tuple[str, ...]
    construct: str
    evidence: Evidence


@dataclass(frozen=True)
class RTLModule:
    name: str
    original_name: str
    source_file: str
    top: bool
    level: int
    parameters: tuple[tuple[str, str], ...]
    ports: tuple[RTLPort, ...]
    instances: tuple[RTLInstance, ...]
    memories: tuple[RTLMemory, ...]
    dependencies: tuple[SignalDependency, ...]
    evidence: Evidence


@dataclass(frozen=True)
class RTLAnalysis:
    schema: str
    manifest_digest: str
    frontend_schema: str
    top_module: str
    modules: tuple[RTLModule, ...]
    limitations: tuple[AnalysisLimitation, ...]

    def require_provable(
        self, purpose: str, *, module: str | None = None, signals: tuple[str, ...] = (),
    ) -> None:
        requested = set(signals)
        requested_is_tainted = False
        if module is not None and requested:
            selected = next((item for item in self.modules if item.name == module or item.original_name == module), None)
            if selected is None:
                raise InputValidationError(f"{purpose}: unknown analyzed module {module!r}")
            requested_is_tainted = any(
                port.name in requested and port.evidence.state is EvidenceState.NON_PROVABLE
                for port in selected.ports
            ) or any(
                dependency.target in requested and dependency.evidence.state is EvidenceState.NON_PROVABLE
                for dependency in selected.dependencies
            )
        failures = [
            item for item in self.limitations
            if (module is None or item.module == module)
            and (
                not requested or not item.signals or bool(requested.intersection(item.signals))
                or requested_is_tainted
            )
        ]
        if failures:
            reasons = "; ".join(item.evidence.reason for item in failures)
            raise InputValidationError(f"{purpose}: analysis is non-provable: {reasons}")


def analyze_elaboration(
    manifest: ElaborationManifest,
    *,
    project_root: str | Path,
    frontend_library: str | Path | None = None,
) -> RTLAnalysis:
    analysis, _raw = analyze_elaboration_with_frontend(
        manifest, project_root=project_root, frontend_library=frontend_library,
    )
    return analysis


def analyze_elaboration_with_frontend(
    manifest: ElaborationManifest,
    *,
    project_root: str | Path,
    frontend_library: str | Path | None = None,
) -> tuple[RTLAnalysis, Mapping[str, Any]]:
    """Return normalized analysis together with the exact shared frontend manifest."""
    root = Path(project_root).resolve()
    repository_root = Path(__file__).resolve().parents[3]
    library_path = Path(frontend_library) if frontend_library else default_frontend_library(repository_root)
    if not library_path.is_file():
        raise InputValidationError(f"Verilator frontend library does not exist: {library_path}")
    args = ["--lint-only", "-Wno-fatal"]
    args.extend(f"-I{path}" for path in manifest.include_dirs)
    args.extend(f"-D{definition}" for definition in manifest.defines)
    args.extend(f"-G{name}={value}" for name, value in manifest.parameters)
    args.extend(item.path for item in manifest.sources)
    args.extend(("--top-module", manifest.top_module))
    vendor_root = repository_root / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
    try:
        raw = isolated_frontend_manifest(
            library_path, args, root,
            environment={"MYFUZZ_FRONTEND_VERILATOR_ROOT": str(vendor_root)},
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise InputValidationError(f"Verilator frontend analysis failed: {exc}") from exc
    return normalize_frontend_manifest(raw, manifest.digest), raw


def normalize_frontend_manifest(raw: Mapping[str, Any], manifest_digest: str) -> RTLAnalysis:
    schema = raw.get("schema")
    if schema != "myfuzz.frontend.v1":
        raise InputValidationError(f"frontend schema mismatch: expected 'myfuzz.frontend.v1', got {schema!r}")
    if raw.get("source") != "verilator-frontend-ast":
        raise InputValidationError("frontend result is not backed by the Verilator AST")
    limitations = tuple(
        AnalysisLimitation(
            _text(item.get("module"), "frontend limitation module"),
            tuple(sorted(_strings(item.get("signals", []), "frontend limitation signals"))),
            _text(item.get("construct", "unsupported"), "frontend limitation construct"),
            Evidence(
                EvidenceState.NON_PROVABLE, str(item.get("source", "verilator_ast")),
                _text(item.get("reason"), "limitation reason"),
            ),
        )
        for item in _objects(raw.get("limitations", []), "frontend.limitations")
    )
    limitations_by_module: dict[str, list[AnalysisLimitation]] = {}
    for limitation in limitations:
        limitations_by_module.setdefault(limitation.module, []).append(limitation)

    modules: list[RTLModule] = []
    seen: set[str] = set()
    for index, item in enumerate(_objects(raw.get("modules"), "frontend.modules")):
        name = _text(item.get("name"), f"frontend.modules[{index}].name")
        if name in seen:
            raise InputValidationError(f"frontend returned duplicate elaborated module {name!r}")
        seen.add(name)
        raw_dependencies = _objects(item.get("dependencies", []), f"frontend.modules[{index}].dependencies")
        dependency_values = [
            (
                _text(value.get("target"), "frontend dependency target"),
                tuple(sorted(_strings(value.get("sources"), "frontend dependency sources"))),
                _text(value.get("kind"), "frontend dependency kind"),
            )
            for value in raw_dependencies
        ]
        module_limitations = limitations_by_module.get(name, [])
        tainted = {signal for limitation in module_limitations for signal in limitation.signals}
        whole_module_tainted = any(not limitation.signals for limitation in module_limitations)
        changed = True
        while changed:
            changed = False
            for target, sources, _kind in dependency_values:
                if target not in tainted and (whole_module_tainted or tainted.intersection(sources)):
                    tainted.add(target)
                    changed = True
        ports = tuple(
            _port(value, index, port_index, non_provable=_text(value.get("name"), "frontend port name") in tainted or whole_module_tainted)
            for port_index, value in enumerate(_objects(item.get("ports"), f"frontend.modules[{index}].ports"))
        )
        instances = tuple(
            RTLInstance(
                _text(value.get("name"), f"frontend.modules[{index}].instances[{instance_index}].name"),
                _text(
                    value.get("childOrig") or value.get("child"),
                    f"frontend.modules[{index}].instances[{instance_index}].child",
                ),
                tuple(sorted(
                    (
                        RTLPinBinding(
                            _text(pin.get("port"), "frontend instance pin port"),
                            _direction(pin.get("direction"), "frontend instance pin direction"),
                            _positive_integer(pin.get("width"), "frontend instance pin width"),
                            _text(pin.get("expressionKind"), "frontend instance pin expressionKind"),
                            tuple(sorted(_strings(pin.get("signals", []), "frontend instance pin signals"))),
                            Evidence(EvidenceState.KNOWN, "verilator_ast", "elaborated instance pin binding"),
                        )
                        for pin in _objects(value.get("pins", []), "frontend instance pins")
                    ),
                    key=lambda pin: pin.port,
                )),
                Evidence(EvidenceState.KNOWN, "verilator_ast", "elaborated instance edge"),
            )
            for instance_index, value in enumerate(
                _objects(item.get("instances"), f"frontend.modules[{index}].instances")
            )
        )
        memories = tuple(
            _memory(value, index, memory_index)
            for memory_index, value in enumerate(
                _objects(item.get("memories", []), f"frontend.modules[{index}].memories")
            )
        )
        dependencies = tuple(
            SignalDependency(
                target, sources, kind,
                Evidence(
                    EvidenceState.NON_PROVABLE if whole_module_tainted or target in tainted else EvidenceState.KNOWN,
                    "verilator_ast",
                    "dependency reaches an unsupported construct" if whole_module_tainted or target in tainted
                    else "elaborated signal dependency",
                ),
            )
            for target, sources, kind in dependency_values
        )
        parameters = tuple(sorted(
            (
                _text(value.get("name"), f"frontend.modules[{index}].parameters.name"),
                _text(value.get("value"), f"frontend.modules[{index}].parameters.value"),
            )
            for value in _objects(item.get("parameters", []), f"frontend.modules[{index}].parameters")
        ))
        modules.append(RTLModule(
            name, str(item.get("origName") or name), _text(item.get("file"), f"frontend.modules[{index}].file"),
            bool(item.get("top")), _integer(item.get("level"), f"frontend.modules[{index}].level"),
            parameters,
            tuple(sorted(ports, key=lambda port: port.name)),
            tuple(sorted(instances, key=lambda instance: (instance.name, instance.module_type))),
            tuple(sorted(memories, key=lambda memory: memory.name)),
            tuple(sorted(dependencies, key=lambda dependency: (dependency.target, dependency.kind))),
            Evidence(EvidenceState.KNOWN, "verilator_ast", "module survived elaboration and width resolution"),
        ))
    top = _text(raw.get("topModule"), "frontend.topModule")
    if not any(module.top or module.name == top or module.original_name == top for module in modules):
        raise InputValidationError(f"frontend top module {top!r} is missing from elaborated modules")
    return RTLAnalysis(
        "myfuzz.rtl-analysis/v1", manifest_digest, str(schema), top,
        tuple(sorted(modules, key=lambda module: module.name)), limitations,
    )


def _port(
    value: Mapping[str, Any], module_index: int, port_index: int, *, non_provable: bool = False,
) -> RTLPort:
    path = f"frontend.modules[{module_index}].ports[{port_index}]"
    try:
        direction = PortDirection(value.get("direction"))
    except ValueError as exc:
        raise InputValidationError(f"{path}.direction: unsupported direction {value.get('direction')!r}") from exc
    width = _positive_integer(value.get("width"), f"{path}.width")
    packed_width = _positive_integer(value.get("packedWidth"), f"{path}.packedWidth")
    ranges = tuple(
        (_integer(item[0], f"{path}.unpackedRanges"), _integer(item[1], f"{path}.unpackedRanges"))
        for item in value.get("unpackedRanges", [])
        if isinstance(item, (list, tuple)) and len(item) == 2
    )
    signed = value.get("signed")
    signed = signed if isinstance(signed, bool) else None
    return RTLPort(
        _text(value.get("name"), f"{path}.name"), direction, width, packed_width, ranges, signed,
        Evidence(
            EvidenceState.NON_PROVABLE if non_provable else EvidenceState.KNOWN,
            "verilator_ast",
            "signal reaches an unsupported construct" if non_provable
            else "direction and shape resolved after elaboration",
        ),
    )


def _direction(value: object, path: str) -> PortDirection:
    try:
        return PortDirection(value)
    except ValueError as exc:
        raise InputValidationError(f"{path}: unsupported direction {value!r}") from exc


def _memory(value: Mapping[str, Any], module_index: int, memory_index: int) -> RTLMemory:
    path = f"frontend.modules[{module_index}].memories[{memory_index}]"
    ranges = tuple(
        (_integer(item[0], f"{path}.unpackedRanges"), _integer(item[1], f"{path}.unpackedRanges"))
        for item in value.get("unpackedRanges", [])
        if isinstance(item, (list, tuple)) and len(item) == 2
    )
    return RTLMemory(
        _text(value.get("name"), f"{path}.name"),
        _positive_integer(value.get("wordWidth"), f"{path}.wordWidth"),
        _positive_integer(value.get("depth"), f"{path}.depth"),
        ranges,
        Evidence(EvidenceState.KNOWN, "verilator_ast", "fixed unpacked memory shape resolved after elaboration"),
    )


def _objects(value: object, path: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise InputValidationError(f"{path}: expected an array of objects")
    return tuple(value)


def _strings(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InputValidationError(f"{path}: expected an array")
    return tuple(_text(item, path) for item in value)


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError(f"{path}: expected an integer")
    return value


def _positive_integer(value: object, path: str) -> int:
    result = _integer(value, path)
    if result <= 0:
        raise InputValidationError(f"{path}: expected an integer greater than zero")
    return result
