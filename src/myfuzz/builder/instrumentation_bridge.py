"""Bridge planned observations to the existing source instrumentation."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import shutil
import tempfile
from typing import Any

from myfuzz.instrumentation.source_branch_instrumenter import instrument_project

from .discovery import DiscoveryResult
from .contracts import (
    CoverageABI, ElaborationManifest, ResolvedFile,
    derive_rewritten_elaboration_manifest,
)
from .input_model import InputValidationError
from .coverage_v2 import (
    build_common_coverage_abi_v2,
    infer_hierarchy_component_ids,
    infer_hierarchy_component_paths,
)
from .planner import SystemPlan
from .unknown_ports import UnknownPortAction


def run_instrumentation(
    plan: SystemPlan,
    discovery: DiscoveryResult,
    project_root: str | Path,
    output_dir: str | Path,
    *,
    filelist: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    out = Path(output_dir).resolve()
    tops = [module.name for module in discovery.modules if module.top_candidate]
    manifest = instrument_project(
        Path(project_root).resolve(),
        out,
        flist=Path(filelist).resolve() if filelist else None,
        top_module=",".join(tops) if tops else None,
        force=force,
    )
    observations = [
        {
            "module": item.module,
            "port": item.port,
            "width": item.width,
            "reason": item.reason,
            "instrumentation_role": "observable_output",
        }
        for item in plan.unknown_ports
        if item.action is UnknownPortAction.OBSERVE
    ]
    result = {
        "manifest": (out / "instrumentation.json").as_posix(),
        "file_count": manifest["file_count"],
        "coverage_point_count": manifest["coverage_point_count"],
        "top_modules": manifest["top_modules"],
        "observed_outputs": observations,
    }
    (out / "builder_instrumentation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def update_generation_report(report_dir: str | Path, instrumentation: dict[str, Any]) -> None:
    path = Path(report_dir) / "generation_report.json"
    if not path.exists():
        return
    report = json.loads(path.read_text(encoding="utf-8"))
    report["instrumentation"] = instrumentation
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_soc_instrumentation(
    manifest: ElaborationManifest,
    project_root: str | Path,
    output_dir: str | Path,
    *,
    required_modules: tuple[str, ...] | list[str] | set[str],
    optional_modules: tuple[str, ...] | list[str] | set[str] = (),
    frontend_manifest: dict[str, Any] | None = None,
    coverage_abi_version: int = 1,
    hierarchy_component_ids: dict[str, str] | None = None,
    hierarchy_component_roots: dict[str, tuple[str, ...] | list[str] | set[str]] | None = None,
    coverage_epoch_width: int = 16,
    force: bool = False,
) -> dict[str, Any]:
    """Instrument exactly one verified full-SoC elaboration manifest."""
    root = Path(project_root).resolve()
    out = Path(output_dir).resolve()
    if manifest.top_module not in set(required_modules):
        raise InputValidationError("instrumentation required_modules must include the SoC top")
    for source in manifest.sources:
        path = Path(source.path).resolve()
        if not path.is_relative_to(root):
            raise InputValidationError(f"manifest source escapes project root: {path}")
        if not path.is_file():
            raise InputValidationError(f"manifest source is missing: {path}")
        data = path.read_bytes()
        if len(data) != source.size or hashlib.sha256(data).hexdigest() != source.sha256:
            raise InputValidationError(f"manifest source content changed after analysis: {path}")
    for include_dir in manifest.include_dirs:
        path = Path(include_dir).resolve()
        if not path.is_relative_to(root):
            raise InputValidationError(f"manifest include directory escapes project root: {path}")

    filelist_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".f", delete=False, encoding="utf-8") as handle:
            filelist_path = Path(handle.name)
            for include_dir in manifest.include_dirs:
                handle.write(f"+incdir+{include_dir}\n")
            for definition in manifest.defines:
                handle.write(f"+define+{definition}\n")
            for source in manifest.sources:
                handle.write(f"{source.path}\n")
        try:
            if coverage_abi_version not in {1, 2}:
                raise InputValidationError("coverage_abi_version must be 1 or 2")
            if hierarchy_component_ids and hierarchy_component_roots:
                raise InputValidationError(
                    "CoverageABI v2 accepts hierarchy_component_ids or hierarchy_component_roots, not both"
                )
            if coverage_abi_version == 2 and not (hierarchy_component_ids or hierarchy_component_roots):
                raise InputValidationError(
                    "CoverageABI v2 requires hierarchy_component_ids or hierarchy_component_roots"
                )
            raw = instrument_project(
                root, out, flist=filelist_path, frontend_manifest=frontend_manifest,
                top_module=manifest.top_module,
                required_modules=set(required_modules), optional_modules=set(optional_modules),
                coverage_epoch_width=coverage_epoch_width if coverage_abi_version == 2 else None,
                force=force,
            )
        except SystemExit as exc:
            raise InputValidationError(f"whole-SoC instrumentation failed: {exc}") from exc
    finally:
        if filelist_path is not None:
            filelist_path.unlink(missing_ok=True)

    abi_value = raw.get("coverage_abi")
    if not isinstance(abi_value, dict) or int(abi_value.get("width", 0)) <= 0:
        raise InputValidationError("whole-SoC instrumentation produced no CoverageABI")
    transport_abi = CoverageABI(
        str(abi_value["manifest_digest"]), str(abi_value["port_name"]),
        int(abi_value["width"]), tuple(abi_value["points"]),
    )
    resolved_component_ids = hierarchy_component_ids
    resolved_component_paths = None
    if coverage_abi_version == 2 and hierarchy_component_roots:
        resolved_component_ids = infer_hierarchy_component_ids(
            transport_abi.points, hierarchy_component_roots,
        )
        resolved_component_paths = infer_hierarchy_component_paths(
            transport_abi.points, hierarchy_component_roots,
        )
    coverage_abi = (
        build_common_coverage_abi_v2(
            transport_abi, resolved_component_ids or {},
            hierarchy_component_paths=resolved_component_paths,
            epoch_width=coverage_epoch_width,
        )
        if coverage_abi_version == 2 else transport_abi
    )
    rewritten_sources = []
    for source in manifest.sources:
        relative = Path(source.path).resolve().relative_to(root)
        path = out / relative
        data = path.read_bytes()
        rewritten_sources.append(ResolvedFile(
            path.as_posix(), hashlib.sha256(data).hexdigest(), len(data),
        ))
    rewritten_includes = []
    for include_dir in manifest.include_dirs:
        source_dir = Path(include_dir).resolve()
        rewritten_dir = out / source_dir.relative_to(root)
        rewritten_dir.mkdir(parents=True, exist_ok=True)
        for source in sorted(source_dir.rglob("*")):
            if not source.is_file():
                continue
            destination = rewritten_dir / source.relative_to(source_dir)
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        rewritten_includes.append(rewritten_dir.as_posix())
    instrumented_manifest = derive_rewritten_elaboration_manifest(
        manifest, stage="instrumented-soc", sources=rewritten_sources,
        include_dirs=tuple(rewritten_includes),
    )
    result = {
        "source_manifest_digest": manifest.digest,
        "coverage_abi": coverage_abi.to_dict(),
        "coverage_transport_abi": transport_abi.to_dict() if coverage_abi_version == 2 else None,
        "instrumented_manifest": instrumented_manifest.to_dict(),
        "instrumentation_manifest": (out / "instrumentation.json").as_posix(),
        "instrumented_filelist": raw["instrumented_flist"],
        "coverage_point_count": coverage_abi.width,
    }
    (out / "builder_soc_instrumentation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return result
