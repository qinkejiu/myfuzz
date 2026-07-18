"""Project independently elaborated logical components into proven discovery facts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Mapping

from .contracts import ElaborationManifest, build_elaboration_manifest, canonical_json
from .discovery import DiscoveredInstance, DiscoveredModule, DiscoveredPort, DiscoveryResult
from .input_model import InputValidationError, ModuleKind, SystemSpec
from .rtl_analysis import EvidenceState, RTLAnalysis, RTLModule, analyze_elaboration


@dataclass(frozen=True)
class AnalyzedDiscoveryV2:
    source_manifest: ElaborationManifest
    discovery: DiscoveryResult
    analysis_manifest_digest: str
    component_analysis_digests: Mapping[str, str]
    source_digests: Mapping[str, str]


def analyze_declared_components_v2(
    spec: SystemSpec,
    project_root: str | Path,
) -> AnalyzedDiscoveryV2:
    """Elaborate every declared component as a top and retain only proven facts."""
    root = Path(project_root).resolve(strict=True)
    rtl_files, filelists = _source_inputs(spec, root)
    cpu_modules = [module for module in spec.modules if module.kind is ModuleKind.CPU]
    source_top_spec = (cpu_modules or list(spec.modules))[0]
    source_top = source_top_spec.rtl_module or source_top_spec.name
    source_manifest = build_elaboration_manifest(
        top_module=source_top,
        rtl_files=rtl_files,
        filelists=filelists,
        allow_roots=(root,),
    )
    source_digest = hashlib.sha256(canonical_json({
        "sources": [
            {"path": _relative(item.path, root), "sha256": item.sha256, "size": item.size}
            for item in source_manifest.sources
        ],
        "include_dirs": [_relative(path, root) for path in source_manifest.include_dirs],
        "defines": list(source_manifest.defines),
    })).hexdigest()

    modules = []
    analysis_digests: dict[str, str] = {}
    for module_spec in sorted(spec.modules, key=lambda item: item.name):
        rtl_module = module_spec.rtl_module or module_spec.name
        manifest = build_elaboration_manifest(
            top_module=rtl_module,
            rtl_files=rtl_files,
            filelists=filelists,
            allow_roots=(root,),
            parameters=module_spec.parameters,
        )
        analysis = analyze_elaboration(manifest, project_root=root)
        analyzed = _declared_module(analysis, rtl_module)
        _require_critical_ports(module_spec, analysis, analyzed)
        modules.append(DiscoveredModule(
            module_spec.name,
            analyzed.source_file,
            module_spec.source_set,
            {key: _parameter_value(value) for key, value in analyzed.parameters},
            tuple(DiscoveredPort(port.name, port.direction, port.width, None)
                  for port in analyzed.ports),
            tuple(DiscoveredInstance(instance.name, instance.module_type)
                  for instance in analyzed.instances),
            True,
            f"independent Verilator AST elaboration of RTL module {rtl_module}",
        ))
        analysis_digests[module_spec.name] = manifest.digest

    aggregate = hashlib.sha256(canonical_json({
        "schema": "myfuzz.component-analysis-set/v2",
        "components": dict(sorted(analysis_digests.items())),
    })).hexdigest()
    return AnalyzedDiscoveryV2(
        source_manifest,
        DiscoveryResult(
            tuple(item.path for item in source_manifest.sources),
            tuple(modules),
        ),
        aggregate,
        analysis_digests,
        {module.name: source_digest for module in spec.modules},
    )


def _source_inputs(spec: SystemSpec, root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    rtl_files = []
    filelists = []
    for source in spec.sources:
        rtl_files.extend(_resolve(root, path) for path in source.rtl_files)
        filelists.extend(_resolve(root, path) for path in source.filelists)
    return tuple(rtl_files), tuple(filelists)


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _relative(value: str, root: Path) -> str:
    return Path(value).resolve().relative_to(root).as_posix()


def _declared_module(analysis: RTLAnalysis, name: str) -> RTLModule:
    matches = [module for module in analysis.modules
               if module.original_name == name or module.name == name]
    if len(matches) != 1:
        raise InputValidationError(
            f"{name}: expected one elaborated component module, found {len(matches)}"
        )
    return matches[0]


def _require_critical_ports(module_spec, analysis: RTLAnalysis, module: RTLModule) -> None:
    by_name = {port.name: port for port in module.ports}
    critical = set(module_spec.ports)
    critical.update(port for interface in module_spec.interfaces for port in interface.ports.values())
    for name in sorted(critical):
        port = by_name.get(name)
        if port is None:
            raise InputValidationError(
                f"{module_spec.name}.{name}: critical port is absent from Verilator analysis"
            )
        if port.evidence.state is not EvidenceState.KNOWN:
            analysis.require_provable(
                "SoCIR v2 protocol planning", module=module.name, signals=(name,),
            )
            raise InputValidationError(
                f"{module_spec.name}.{name}: critical fact is {port.evidence.state.value}"
            )


def _parameter_value(value: str) -> int | str:
    try:
        return int(value, 0)
    except ValueError:
        return value
