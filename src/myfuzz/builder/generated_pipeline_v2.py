"""End-to-end builder for an emitted SoCIR v2 RawBits v3 target."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shlex
import shutil
from typing import Iterable, Mapping

from .atomic_target import BuiltTarget, _validated_include_files, _validated_sources
from .constraint_synthesis import SynthesizedConstraints
from .contracts import CoverageABIV2, ElaborationManifest, ResolvedFile, build_elaboration_manifest
from .control_plane import GeneratedControlPlane
from .generated_harness_v2 import EmittedGeneratedHarnessV2, emit_generated_harness_v2
from .generated_soc_v2 import EmittedSocIRV2
from .generated_target_v2 import build_generated_verilator_target_v2
from .input_model import InputValidationError
from .instrumentation_bridge import run_soc_instrumentation
from .rtl_analysis import analyze_elaboration_with_frontend


PIPELINE_SCHEMA = "myfuzz.generated-pipeline/v2"


@dataclass(frozen=True)
class GeneratedPipelineV2:
    output_dir: str
    project_dir: str
    instrumented_dir: str
    soc_manifest: ElaborationManifest
    instrumented_manifest: ElaborationManifest
    coverage_abi: CoverageABIV2
    harness: EmittedGeneratedHarnessV2
    target: BuiltTarget
    report_path: str


def build_generated_pipeline_v2(
    output_dir: str | Path,
    *,
    source_manifest: ElaborationManifest,
    source_root: str | Path,
    soc: EmittedSocIRV2,
    control: GeneratedControlPlane,
    constraints: SynthesizedConstraints,
    hierarchy_component_roots: Mapping[str, Iterable[str]],
    required_modules: Iterable[str] = (),
    optional_modules: Iterable[str] = (),
    boot_rom_hex: str | Path | None = None,
    harness_module_name: str = "myfuzz_generated_harness_v2",
    coverage_epoch_width: int = 16,
    reset_cycles: int = 2,
    drain_cycles: int = 4,
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> GeneratedPipelineV2:
    """Compose source freezing, SoC instrumentation, harness emission, and target build."""
    _validate_contracts(soc, control, constraints)
    roots = {
        str(component): tuple(str(path) for path in paths)
        for component, paths in hierarchy_component_roots.items()
    }
    if not roots or any(not component or not paths or any(not path for path in paths)
                        for component, paths in roots.items()):
        raise InputValidationError("generated pipeline requires non-empty component hierarchy roots")
    if coverage_epoch_width <= 1:
        raise InputValidationError("generated pipeline coverage epoch width must exceed one")

    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"generated pipeline output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    project = output / "project"
    instrumented = output / "instrumented"
    project.mkdir()

    frozen_root = Path(source_root).resolve(strict=True)
    sources = _validated_sources(source_manifest, frozen_root)
    include_files = _validated_include_files(source_manifest, frozen_root)
    copied_sources: list[Path] = []
    for source, relative in sources:
        destination = project / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(source.path), destination)
        copied_sources.append(destination)
    for include, relative in include_files:
        destination = project / relative
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(include, destination)

    generated_dir = project / "generated"
    generated_dir.mkdir()
    soc_path = generated_dir / f"{soc.module_name}.sv"
    soc_path.write_text(soc.rtl, encoding="utf-8")
    filelist = project / "sources.f"
    filelist.write_text(
        _emit_filelist(source_manifest, frozen_root, (*copied_sources, soc_path), project),
        encoding="utf-8",
    )
    soc_manifest = build_elaboration_manifest(
        top_module=soc.module_name,
        filelists=(filelist,),
        allow_roots=(project,),
        tools=dict(source_manifest.tools),
    )

    mandatory = {soc.module_name, *(str(module) for module in required_modules)}
    analysis, frontend_manifest = analyze_elaboration_with_frontend(
        soc_manifest, project_root=project,
    )
    active = _active_module_names(analysis)
    missing_mandatory = sorted(mandatory - active)
    if missing_mandatory:
        raise InputValidationError(
            "generated SoC hierarchy omits mandatory module(s): " + ", ".join(missing_mandatory)
        )
    optional = (active | {str(module) for module in optional_modules}) - mandatory
    instrumentation = run_soc_instrumentation(
        soc_manifest,
        project,
        instrumented,
        required_modules=mandatory,
        optional_modules=optional,
        frontend_manifest=dict(frontend_manifest),
        coverage_abi_version=2,
        hierarchy_component_roots=roots,
        coverage_epoch_width=coverage_epoch_width,
    )
    instrumented_manifest = _manifest_from_dict(instrumentation["instrumented_manifest"])
    coverage_abi = _coverage_from_dict(instrumentation["coverage_abi"])
    harness = emit_generated_harness_v2(
        soc,
        control,
        constraints,
        module_name=harness_module_name,
        reset_cycles=reset_cycles,
        drain_cycles=drain_cycles,
        coverage_abi=coverage_abi,
        embed_soc_rtl=False,
    )
    target = build_generated_verilator_target_v2(
        output / "targets",
        manifest=instrumented_manifest,
        source_root=instrumented,
        harness=harness,
        layout=control.layout,
        temporal_ir=constraints.ir,
        coverage_abi=coverage_abi,
        boot_rom_hex=boot_rom_hex,
        verilator_bin=verilator_bin,
        jobs=jobs,
    )

    report = {
        "schema": PIPELINE_SCHEMA,
        "status": "built",
        "source_manifest_digest": source_manifest.digest,
        "soc_manifest_digest": soc_manifest.digest,
        "instrumented_manifest_digest": instrumented_manifest.digest,
        "soc_digest": soc.soc_digest,
        "rawbits_layout_digest": control.layout.digest,
        "constraint_digest": constraints.ir.digest,
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "coverage_width": coverage_abi.width,
        "coverage_transport_width": coverage_abi.transport_width,
        "hierarchy_component_roots": {
            component: list(paths) for component, paths in sorted(roots.items())
        },
        "required_instrumented_modules": sorted(mandatory),
        "optional_instrumented_modules": sorted(optional),
        "soc_rtl_sha256": hashlib.sha256(soc.rtl.encode()).hexdigest(),
        "target_digest": target.target_digest,
        "target_dir": target.path,
        "baseline_a_affected": False,
    }
    report_path = output / "generated_pipeline_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return GeneratedPipelineV2(
        output.as_posix(), project.as_posix(), instrumented.as_posix(), soc_manifest,
        instrumented_manifest, coverage_abi, harness, target, report_path.as_posix(),
    )


def _validate_contracts(
    soc: EmittedSocIRV2,
    control: GeneratedControlPlane,
    constraints: SynthesizedConstraints,
) -> None:
    if not soc.rtl.strip():
        raise InputValidationError("generated pipeline requires emitted SoC RTL")
    if control.control_ir.soc_digest != soc.soc_digest:
        raise InputValidationError("generated pipeline ControlPlane and SoC digests differ")
    if constraints.ir.soc_digest != soc.soc_digest:
        raise InputValidationError("generated pipeline constraints and SoC digests differ")
    if constraints.ir.rawbits_layout_digest != control.layout.digest:
        raise InputValidationError("generated pipeline constraints and RawBits layout digests differ")


def _emit_filelist(
    manifest: ElaborationManifest,
    source_root: Path,
    sources: tuple[Path, ...],
    project: Path,
) -> str:
    lines = []
    for include_dir in manifest.include_dirs:
        relative = Path(include_dir).resolve().relative_to(source_root)
        lines.append(shlex.quote(f"+incdir+{relative.as_posix()}"))
    lines.extend(shlex.quote(f"+define+{definition}") for definition in manifest.defines)
    lines.extend(shlex.quote(path.relative_to(project).as_posix()) for path in sources)
    return "\n".join(lines) + "\n"


def _manifest_from_dict(value: Mapping[str, object]) -> ElaborationManifest:
    return ElaborationManifest(
        str(value["schema"]), str(value["stage"]), str(value["top_module"]),
        str(value["language"]),
        tuple(ResolvedFile(str(item["path"]), str(item["sha256"]), int(item["size"]))
              for item in value["sources"]),  # type: ignore[index]
        tuple(str(item) for item in value["include_dirs"]),  # type: ignore[arg-type]
        tuple(str(item) for item in value["defines"]),  # type: ignore[arg-type]
        tuple((str(item[0]), str(item[1])) for item in value["parameters"]),  # type: ignore[index]
        tuple((str(item[0]), str(item[1])) for item in value["tools"]),  # type: ignore[index]
        None if value["parent_digest"] is None else str(value["parent_digest"]),
        str(value["digest"]),
    )


def _coverage_from_dict(value: Mapping[str, object]) -> CoverageABIV2:
    return CoverageABIV2(
        str(value["catalog_digest"]), str(value["port_name"]), int(value["width"]),
        int(value["epoch_width"]), tuple(value["points"]),  # type: ignore[arg-type]
        int(value["transport_width"]), str(value["writer"]), str(value["sampling"]),
        str(value["schema"]),
    )


def _active_module_names(analysis) -> set[str]:
    by_name = {module.name: module for module in analysis.modules}
    by_original = {module.original_name: module for module in analysis.modules}
    tops = [module for module in analysis.modules if module.top]
    if len(tops) != 1:
        raise InputValidationError(
            f"generated SoC analysis requires one top module, found {len(tops)}"
        )
    pending = [tops[0]]
    active = set()
    while pending:
        module = pending.pop()
        original = str(module.original_name or module.name)
        if original in active:
            continue
        active.add(original)
        for instance in module.instances:
            child = by_name.get(instance.module_type) or by_original.get(instance.module_type)
            if child is None:
                raise InputValidationError(
                    f"generated SoC hierarchy is missing child module {instance.module_type!r}"
                )
            pending.append(child)
    return active
