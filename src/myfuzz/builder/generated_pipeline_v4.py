"""End-to-end builder for an emitted SoCIR v4 protocol or CPU target."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import shutil
from typing import Iterable, Mapping

from .atomic_target import BuiltTarget, _validated_include_files, _validated_sources
from .contracts import CoverageABIV2, ElaborationManifest, build_elaboration_manifest
from .cpu_semantic_v4 import CpuExecutionProfile
from .environment_v4 import (
    EnvironmentInputRuleV4, EnvironmentPlanV4, EnvironmentReplayLimitsV4,
    build_environment_plan_v4,
)
from .generated_harness_v4 import EmittedHarnessV4, emit_protocol_harness_v4
from .generated_pipeline_v2 import (
    _active_module_names, _coverage_from_dict, _emit_filelist, _manifest_from_dict,
)
from .generated_soc_v2 import SocExternalPort
from .generated_soc_v4 import EmittedSocIRV4
from .generated_target_v4 import build_protocol_verilator_target_v4
from .input_model import InputValidationError
from .instrumentation_bridge import run_soc_instrumentation
from .rawbits_v4 import RawBitsV4Layout, RawBitsV4Limits
from .rtl_analysis import analyze_elaboration_with_frontend


PIPELINE_SCHEMA_V4 = "myfuzz.generated-pipeline/v4"


@dataclass(frozen=True)
class GeneratedPipelineV4:
    output_dir: str
    project_dir: str
    instrumented_dir: str
    soc_manifest: ElaborationManifest
    instrumented_manifest: ElaborationManifest
    coverage_abi: CoverageABIV2
    harness: EmittedHarnessV4
    environment_plan: EnvironmentPlanV4 | None
    target: BuiltTarget
    report_path: str


def build_generated_pipeline_v4(
    output_dir: str | Path,
    *,
    source_manifest: ElaborationManifest,
    source_root: str | Path,
    soc: EmittedSocIRV4,
    hierarchy_component_roots: Mapping[str, Iterable[str]],
    required_modules: Iterable[str] = (),
    optional_modules: Iterable[str] = (),
    layout: RawBitsV4Layout | None = None,
    cpu_profile: CpuExecutionProfile | None = None,
    environment_plan: EnvironmentPlanV4 | None = None,
    environment_rules: Mapping[str, EnvironmentInputRuleV4] | None = None,
    environment_limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
    limits: RawBitsV4Limits = RawBitsV4Limits(),
    harness_module_name: str = "myfuzz_generated_harness_v4",
    coverage_epoch_width: int = 64,
    verilator_bin: str = "verilator",
    jobs: int = 1,
    campaign_address_windows: tuple[tuple[str, int, int], ...] = (),
) -> GeneratedPipelineV4:
    """Freeze, instrument, wrap, and build one profile-driven v4 SoC target."""
    if not soc.rtl.strip():
        raise InputValidationError("generated v4 pipeline requires emitted SoC RTL")
    roots = {
        str(component): tuple(str(path) for path in paths)
        for component, paths in hierarchy_component_roots.items()
    }
    if not roots or any(
        not component or not paths or any(not path for path in paths)
        for component, paths in roots.items()
    ):
        raise InputValidationError(
            "generated v4 pipeline requires non-empty component hierarchy roots"
        )
    if coverage_epoch_width != 64:
        raise InputValidationError(
            "generated v4 pipeline requires an exact 64-bit coverage epoch"
        )
    if environment_plan is not None and environment_rules is not None:
        raise InputValidationError(
            "generated v4 pipeline accepts environment_plan or environment_rules, not both"
        )

    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(
            f"generated v4 pipeline output directory is not empty: {output}"
        )
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
            "generated v4 SoC hierarchy omits mandatory module(s): "
            + ", ".join(missing_mandatory)
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
    instrumented_manifest = _manifest_from_dict(
        instrumentation["instrumented_manifest"]
    )
    coverage_abi = _coverage_from_dict(instrumentation["coverage_abi"])
    harness_soc = replace(
        soc,
        external_port_specs=soc.external_port_specs + (
            SocExternalPort(
                "coverage_epoch_i", "input", coverage_abi.epoch_width, "coverage"
            ),
            SocExternalPort(
                coverage_abi.port_name,
                "output",
                coverage_abi.transport_width,
                "coverage",
            ),
        ),
    )
    harness = emit_protocol_harness_v4(
        harness_soc,
        module_name=harness_module_name,
        layout=layout,
        coverage_abi=coverage_abi,
        embed_soc_rtl=False,
    )
    resolved_environment_plan = environment_plan
    if environment_rules is not None:
        resolved_environment_plan = build_environment_plan_v4(
            harness, environment_rules,
        )
    target = build_protocol_verilator_target_v4(
        output / "targets",
        manifest=instrumented_manifest,
        source_root=instrumented,
        harness=harness,
        coverage_abi=coverage_abi,
        limits=limits,
        environment_plan=resolved_environment_plan,
        environment_limits=environment_limits,
        cpu_profile=cpu_profile,
        campaign_address_windows=campaign_address_windows,
        verilator_bin=verilator_bin,
        jobs=jobs,
    )

    report = {
        "schema": PIPELINE_SCHEMA_V4,
        "status": "built",
        "source_manifest_digest": source_manifest.digest,
        "soc_manifest_digest": soc_manifest.digest,
        "instrumented_manifest_digest": instrumented_manifest.digest,
        "soc_digest": soc.soc_digest,
        "rawbits_layout_digest": harness.layout.digest,
        "protocol_profile_digest": harness.protocol_profile_digest,
        "cpu_profile_digest": None if cpu_profile is None else cpu_profile.digest,
        "environment_plan_digest": (
            None if resolved_environment_plan is None else resolved_environment_plan.digest
        ),
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
        "campaign_address_windows": [
            {"name": name, "base": base, "size": size}
            for name, base, size in campaign_address_windows
        ],
        "target_dir": target.path,
        "baseline_a_affected": False,
    }
    report_path = output / "generated_pipeline_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return GeneratedPipelineV4(
        output.as_posix(),
        project.as_posix(),
        instrumented.as_posix(),
        soc_manifest,
        instrumented_manifest,
        coverage_abi,
        harness,
        resolved_environment_plan,
        target,
        report_path.as_posix(),
    )
