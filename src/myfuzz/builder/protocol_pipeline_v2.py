"""Protocol-driven SoCIR v2 build orchestration from a declarative system spec."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Mapping

from .analyzed_discovery_v2 import AnalyzedDiscoveryV2, analyze_declared_components_v2
from .constraint_synthesis import SynthesizedConstraints, synthesize_temporal_constraints
from .contracts import CpuExecutionProfile, SoCIRV2
from .control_plane import GeneratedControlPlane, build_control_plane
from .control_rom import ControlRomArtifact, generate_control_rom
from .cpu_profiles import builtin_cpu_execution_profile
from .generated_pipeline_v2 import GeneratedPipelineV2, build_generated_pipeline_v2
from .generated_soc_v2 import EmittedSocIRV2, emit_soc_ir_v2
from .input_model import InputValidationError, ModuleKind, SystemSpec
from .planner import SystemPlan, plan_system
from .soc_ir_v2 import build_soc_ir_v2
from .system_services import SystemServicePlan, add_system_services_to_soc_ir, plan_system_services


BUILD_SCHEMA = "myfuzz.protocol-system-build/v2"


@dataclass(frozen=True)
class ProtocolSystemBuildV2:
    output_dir: str
    analyzed: AnalyzedDiscoveryV2
    plan: SystemPlan
    soc_ir: SoCIRV2
    services: SystemServicePlan
    control: GeneratedControlPlane
    constraints: SynthesizedConstraints
    rom: ControlRomArtifact
    emitted_soc: EmittedSocIRV2
    pipeline: GeneratedPipelineV2
    report_path: str


def build_protocol_system_v2(
    spec: SystemSpec,
    project_root: str | Path,
    output_dir: str | Path,
    *,
    cpu_profile: CpuExecutionProfile | None = None,
    cpu_profile_id: str | None = None,
    module_name: str | None = None,
    operation_timeout_limit: int = 65535,
    coverage_epoch_width: int = 16,
    reset_cycles: int = 4,
    drain_cycles: int = 4,
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> ProtocolSystemBuildV2:
    """Analyze, plan, emit, instrument, and compile one generated SoC."""
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"protocol system output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    profile = _select_profile(cpu_profile, cpu_profile_id)
    _validate_cpu_contract(spec, profile)

    analyzed = analyze_declared_components_v2(spec, project_root)
    plan = plan_system(spec, analyzed.discovery)
    if not plan.valid:
        raise InputValidationError("invalid generated system plan: " + "; ".join(plan.validation_issues))
    base_soc = build_soc_ir_v2(
        spec,
        analyzed.discovery,
        plan,
        source_digests=analyzed.source_digests,
        analysis_manifest_digest=analyzed.analysis_manifest_digest,
    )
    services = plan_system_services(base_soc.address_views, profile)
    soc_ir = add_system_services_to_soc_ir(base_soc, services)
    control = build_control_plane(soc_ir, cpu_profile_digest=services.profile_digest)
    constraints = synthesize_temporal_constraints(
        soc_ir, control, operation_timeout_limit=operation_timeout_limit,
    )
    rom_dir = output / "rom"
    rom = generate_control_rom(profile, soc_ir, control, services, rom_dir)
    emitted = emit_soc_ir_v2(
        soc_ir,
        module_name=module_name or f"{_identifier(spec.name)}_generated_soc",
        control_plane=control,
        rom_install_backend=profile.rom_install_backend,
        boot_rom_words=_rom_word_count(rom),
        boot_rom_load_base=profile.reset_vector,
    )
    roots = _hierarchy_roots(spec, emitted.module_name)
    pipeline = build_generated_pipeline_v2(
        output / "pipeline",
        source_manifest=analyzed.source_manifest,
        source_root=project_root,
        soc=emitted,
        control=control,
        constraints=constraints,
        hierarchy_component_roots=roots,
        required_modules=tuple(module.rtl_module or module.name for module in spec.modules),
        boot_rom_hex=rom_dir / "control_rom.hex",
        coverage_epoch_width=coverage_epoch_width,
        reset_cycles=reset_cycles,
        drain_cycles=drain_cycles,
        verilator_bin=verilator_bin,
        jobs=jobs,
    )
    report = {
        "schema": BUILD_SCHEMA,
        "status": "built",
        "system": spec.name,
        "cpu_profile": profile.cpu_id,
        "source_manifest_digest": analyzed.source_manifest.digest,
        "component_analysis_digests": dict(sorted(analyzed.component_analysis_digests.items())),
        "analysis_manifest_digest": analyzed.analysis_manifest_digest,
        "soc_digest": soc_ir.digest,
        "service_plan_digest": services.digest,
        "control_plane_digest": control.control_ir.digest,
        "rawbits_layout_digest": control.layout.digest,
        "constraint_digest": constraints.ir.digest,
        "rom_image_digest": rom.image_digest,
        "target_digest": pipeline.target.target_digest,
        "coverage_abi_digest": pipeline.coverage_abi.manifest_digest,
        "coverage_width": pipeline.coverage_abi.width,
        "hierarchy_component_roots": {key: list(value) for key, value in sorted(roots.items())},
        "baseline_a_affected": False,
    }
    report_path = output / "protocol_system_build.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return ProtocolSystemBuildV2(
        output.as_posix(), analyzed, plan, soc_ir, services, control, constraints,
        rom, emitted, pipeline, report_path.as_posix(),
    )


def _select_profile(
    profile: CpuExecutionProfile | None,
    profile_id: str | None,
) -> CpuExecutionProfile:
    if profile is not None and profile_id is not None:
        raise InputValidationError("provide cpu_profile or cpu_profile_id, not both")
    if profile is not None:
        return profile
    if profile_id is None:
        raise InputValidationError("a qualified CPU execution profile is required")
    return builtin_cpu_execution_profile(profile_id)


def _validate_cpu_contract(spec: SystemSpec, profile: CpuExecutionProfile) -> None:
    cpus = [module for module in spec.modules if module.kind is ModuleKind.CPU]
    if len(cpus) != 1:
        raise InputValidationError(f"generated system requires one CPU component; found {len(cpus)}")
    initiators = [
        (module.name, interface)
        for module in spec.modules
        for interface in module.interfaces
        if interface.role == "initiator"
    ]
    if len(initiators) != 1 or initiators[0][0] != cpus[0].name:
        raise InputValidationError("the CPU must be the generated system's only protocol initiator")
    if initiators[0][1].protocol != "axi_lite":
        raise InputValidationError("the qualified CPU execution path requires an AXI-Lite initiator")
    if profile.data_width != 32 or profile.address_width != 32:
        raise InputValidationError("first-stage generated systems require a 32-bit CPU profile")


def _hierarchy_roots(spec: SystemSpec, top: str) -> Mapping[str, tuple[str, ...]]:
    roots = {}
    for module in spec.modules:
        prefix = "cpu" if module.kind is ModuleKind.CPU else "ip"
        component_id = module.component_id or f"{prefix}.{module.name}"
        if component_id in roots:
            raise InputValidationError(f"duplicate coverage component_id {component_id!r}")
        roots[component_id] = (f"{top}.i_{_identifier(module.name)}",)
    return roots


def _identifier(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not result or result[0].isdigit():
        result = "n_" + result
    return result


def _rom_word_count(artifact: ControlRomArtifact) -> int:
    binary = next((item for item in artifact.files if item.get("name") == "control_rom.bin"), None)
    if binary is None:
        raise InputValidationError("control ROM artifact is missing control_rom.bin")
    size = int(binary["size"])
    if size <= 0:
        raise InputValidationError("control ROM binary is empty")
    return (size + 3) // 4
