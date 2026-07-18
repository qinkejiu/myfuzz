"""Profile-driven RawBits v4 system build from a declarative SystemSpec."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from .analyzed_discovery_v2 import AnalyzedDiscoveryV2, analyze_declared_components_v2
from .axi_lite_v4 import AxiLiteV4Capability, build_axi_lite_v4_layout
from .contracts import CpuExecutionProfile as SocCpuExecutionProfile, SoCIRV2
from .cpu_profiles import builtin_cpu_execution_profile
from .cpu_semantic_v4 import (
    CpuExecutionProfile as SemanticCpuExecutionProfile,
    build_cpu_semantic_v4_layout,
    picorv32_semantic_profile,
    ultra_riscv_semantic_profile,
)
from .environment_v4 import (
    EnvironmentInputRuleV4, EnvironmentPlanV4, EnvironmentReplayLimitsV4,
)
from .generated_pipeline_v4 import GeneratedPipelineV4, build_generated_pipeline_v4
from .generated_soc_v4 import EmittedSocIRV4, emit_soc_ir_v4
from .input_model import InputValidationError, SystemSpec
from .planner import SystemPlan, plan_system
from .protocol_pipeline_v2 import _hierarchy_roots, _identifier, _validate_cpu_contract
from .rawbits_v4 import RawBitsV4Limits
from .soc_ir_v2 import build_soc_ir_v2
from .system_services import SystemServicePlan, add_system_services_to_soc_ir, plan_system_services


BUILD_SCHEMA_V4 = "myfuzz.protocol-system-build/v4"


@dataclass(frozen=True)
class ProtocolSystemBuildV4:
    output_dir: str
    analyzed: AnalyzedDiscoveryV2
    plan: SystemPlan
    soc_ir: SoCIRV2
    services: SystemServicePlan
    emitted_soc: EmittedSocIRV4
    pipeline: GeneratedPipelineV4
    report_path: str


def build_protocol_system_v4(
    spec: SystemSpec,
    project_root: str | Path,
    output_dir: str | Path,
    *,
    soc_cpu_profile: SocCpuExecutionProfile | None = None,
    semantic_cpu_profile: SemanticCpuExecutionProfile | None = None,
    cpu_profile_id: str | None = None,
    module_name: str | None = None,
    environment_plan: EnvironmentPlanV4 | None = None,
    environment_rules: Mapping[str, EnvironmentInputRuleV4] | None = None,
    environment_limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
    limits: RawBitsV4Limits = RawBitsV4Limits(),
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> ProtocolSystemBuildV4:
    """Analyze and compile an arbitrary declared AXI-Lite CPU/IP composition."""
    output = Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"protocol v4 system output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    physical, semantic = _select_profiles(
        soc_cpu_profile, semantic_cpu_profile, cpu_profile_id,
    )
    _validate_profile_pair(physical, semantic)
    _validate_cpu_contract(spec, physical)
    if environment_plan is not None and environment_rules is not None:
        raise InputValidationError(
            "v4 system build accepts environment_plan or environment_rules, not both"
        )

    analyzed = analyze_declared_components_v2(spec, project_root)
    plan = plan_system(spec, analyzed.discovery)
    if not plan.valid:
        raise InputValidationError(
            "invalid generated v4 system plan: " + "; ".join(plan.validation_issues)
        )
    base_soc = build_soc_ir_v2(
        spec,
        analyzed.discovery,
        plan,
        source_digests=analyzed.source_digests,
        analysis_manifest_digest=analyzed.analysis_manifest_digest,
    )
    services = plan_system_services(base_soc.address_views, physical)
    soc_ir = add_system_services_to_soc_ir(base_soc, services)
    emitted = emit_soc_ir_v4(
        soc_ir,
        module_name=module_name or f"{_identifier(spec.name)}_generated_soc_v4",
        rom_install_backend=dict(physical.rom_install_backend),
        boot_rom_words=_absolute_rom_word_count(physical),
        boot_rom_load_base=0,
    )
    capability = emitted.fabric_capability
    layout = build_cpu_semantic_v4_layout(build_axi_lite_v4_layout(
        AxiLiteV4Capability(
            capability.address_width,
            capability.data_width,
            capability.awprot_present,
            capability.arprot_present,
            max_write_outstanding=capability.write_reorder_depth,
            max_read_outstanding=capability.read_reorder_depth,
        )
    ))
    roots = _hierarchy_roots(spec, emitted.module_name)
    target_instances = {
        module.name for module in spec.modules
        if module.kind.value != "cpu" and module.address is not None
    }
    campaign_address_windows = tuple(
        (name, base, size)
        for name, base, size, _protocol in emitted.address_windows
        if name in target_instances
    )
    if target_instances != {name for name, _base, _size in campaign_address_windows}:
        raise InputValidationError("generated v4 campaign address windows do not match declared IP targets")
    resolved_environment_rules = environment_rules
    if environment_plan is None and resolved_environment_rules is None:
        resolved_environment_rules = _generated_service_environment_rules(emitted)
    pipeline = build_generated_pipeline_v4(
        output / "pipeline",
        source_manifest=analyzed.source_manifest,
        source_root=project_root,
        soc=emitted,
        hierarchy_component_roots=roots,
        layout=layout,
        cpu_profile=semantic,
        environment_plan=environment_plan,
        environment_rules=resolved_environment_rules,
        environment_limits=environment_limits,
        limits=limits,
        verilator_bin=verilator_bin,
        jobs=jobs,
        campaign_address_windows=campaign_address_windows,
    )
    report = {
        "schema": BUILD_SCHEMA_V4,
        "status": "built",
        "system": spec.name,
        "soc_cpu_profile": physical.cpu_id,
        "soc_cpu_profile_digest": services.profile_digest,
        "semantic_cpu_profile": semantic.name,
        "semantic_cpu_profile_digest": semantic.digest,
        "cpu_state_domain_digest": semantic.state_domain.digest,
        "source_manifest_digest": analyzed.source_manifest.digest,
        "component_analysis_digests": dict(
            sorted(analyzed.component_analysis_digests.items())
        ),
        "analysis_manifest_digest": analyzed.analysis_manifest_digest,
        "soc_digest": soc_ir.digest,
        "service_plan_digest": services.digest,
        "rawbits_layout_digest": layout.digest,
        "coverage_abi_digest": pipeline.coverage_abi.manifest_digest,
        "coverage_width": pipeline.coverage_abi.width,
        "target_digest": pipeline.target.target_digest,
        "campaign_address_windows": [
            {"name": name, "base": base, "size": size}
            for name, base, size in campaign_address_windows
        ],
        "rom_install_backend": dict(physical.rom_install_backend),
        "boot_rom_word_index_origin": 0,
        "boot_rom_words": _absolute_rom_word_count(physical),
        "hierarchy_component_roots": {
            key: list(value) for key, value in sorted(roots.items())
        },
        "baseline_a_affected": False,
    }
    report_path = output / "protocol_system_build_v4.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return ProtocolSystemBuildV4(
        output.as_posix(), analyzed, plan, soc_ir, services, emitted, pipeline,
        report_path.as_posix(),
    )


def _select_profiles(
    physical: SocCpuExecutionProfile | None,
    semantic: SemanticCpuExecutionProfile | None,
    profile_id: str | None,
) -> tuple[SocCpuExecutionProfile, SemanticCpuExecutionProfile]:
    if profile_id is not None and (physical is not None or semantic is not None):
        raise InputValidationError(
            "provide cpu_profile_id or both explicit v4 CPU profiles, not both"
        )
    if profile_id is not None:
        semantic_factories = {
            "picorv32": picorv32_semantic_profile,
            "ultra_riscv": ultra_riscv_semantic_profile,
        }
        try:
            semantic_factory = semantic_factories[profile_id]
        except KeyError as exc:
            raise InputValidationError(
                f"unknown qualified v4 CPU profile {profile_id!r}"
            ) from exc
        return builtin_cpu_execution_profile(profile_id), semantic_factory()
    if physical is None or semantic is None:
        raise InputValidationError(
            "v4 system build requires both physical and semantic CPU profiles"
        )
    return physical, semantic


def _validate_profile_pair(
    physical: SocCpuExecutionProfile,
    semantic: SemanticCpuExecutionProfile,
) -> None:
    if physical.cpu_id != semantic.name:
        raise InputValidationError("physical and semantic CPU profile identities differ")
    if physical.data_width != 32 or semantic.state_domain.xlen != 32:
        raise InputValidationError("v4 CPU execution currently requires RV32 data semantics")
    if "RV32I" not in semantic.isa or physical.isa.lower() != "rv32i":
        raise InputValidationError("physical and semantic CPU profiles must both declare RV32I")
    reset_pc = int(semantic.state_domain.reset_values.get("pc", -1))
    if reset_pc != physical.reset_vector:
        raise InputValidationError("physical and semantic CPU reset vectors differ")
    rom = physical.rom_window
    rom_base = int(rom["base"])
    rom_size = int(rom["size"])
    semantic_rom = next(
        (region for region in semantic.state_domain.memory_regions if region.name == "rom"),
        None,
    )
    if (
        semantic_rom is None
        or semantic_rom.base != rom_base
        or semantic_rom.size != rom_size
        or "x" not in semantic_rom.permissions
    ):
        raise InputValidationError("physical and semantic boot ROM domains differ")


def _absolute_rom_word_count(profile: SocCpuExecutionProfile) -> int:
    base = int(profile.rom_window["base"])
    size = int(profile.rom_window["size"])
    if base < 0 or size <= 0 or base + size > 1 << 32:
        raise InputValidationError("physical CPU ROM window is outside the 32-bit domain")
    return (base + size + 3) // 4


def _generated_service_environment_rules(
    emitted: EmittedSocIRV4,
) -> Mapping[str, EnvironmentInputRuleV4]:
    generated_defaults = {
        "external_irq_sources": "no asynchronous external interrupt is injected by default",
        "reset_domain_select": "the generated reset service remains on its default domain",
        "reset_domain_start": "no out-of-band reset request is issued by default",
    }
    inputs = {
        port.name for port in emitted.external_port_specs
        if port.kind != "verification_master" and port.direction == "input"
    }
    return {
        name: EnvironmentInputRuleV4(
            "constant",
            generated_defaults.get(
                name,
                "declared external input is held inactive unless an explicit replay plan is supplied",
            ),
            (
                "generated-system-service/v4"
                if name in generated_defaults
                else "system-spec-unknown-port-policy/v1"
            ),
            "constant before, during, and after harness reset",
            0,
        )
        for name in sorted(inputs)
    }
