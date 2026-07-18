"""Build and instrument the locked A/B/C large-SoC experiment pair."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
from typing import Iterable

from .contracts import ElaborationManifest, build_elaboration_manifest
from .experiment_inputs import SupersetInputContract, build_superset_input_contract
from .formal_ip_set import formal_axi_lite_ip_set
from .input_model import InputValidationError
from .instrumentation_bridge import run_soc_instrumentation
from .large_soc import emit_large_generated_soc
from .large_soc_flat import emit_large_flat_soc
from .large_soc_harness import emit_large_soc_transaction_harness
from .level1_rom import generate_level1_rom
from .cpu_profiles import builtin_cpu_execution_profile
from .rtl_analysis import analyze_elaboration_with_frontend


QUALIFICATION_SCHEMA = "myfuzz.large-soc-coverage-qualification/v1"
_CPU_FILELISTS = {
    "picorv32": "qualification/axi_lite/cases/picorv32_cpu.f",
    "ultra_riscv": "qualification/axi_lite/cases/ultra_riscv_cpu.f",
}
_BOUNDARY_MODULES = {
    "verilog_axi.axil_ram": "verilog_axi_ram_wrapper",
    "verilog_axi.axil_dp_ram": "verilog_axi_dp_ram_wrapper",
    "pulp.axi_lite_regs": "pulp_axi_lite_regs_wrapper",
    "pulp.axi_lite_lfsr": "pulp_axi_lite_lfsr_level1_adapter",
    "zipcpu.axilgpio": "zipcpu_axilgpio_level1_adapter",
    "zipcpu.axil2apb": "zipcpu_axil2apb_level1_adapter",
}


@dataclass(frozen=True)
class LargeSocQualification:
    cpu_id: str
    output_dir: str
    flat_top: str
    generated_top: str
    input_contract: SupersetInputContract
    flat_manifest: ElaborationManifest
    generated_manifest: ElaborationManifest
    flat_coverage: dict[str, object]
    generated_coverage: dict[str, object]
    common_point_ids: tuple[str, ...]


def qualify_large_soc_coverage(
    cpu_id: str,
    output_dir: str | Path,
    *,
    repository_root: str | Path | None = None,
    rom_words: int = 49,
    coverage_epoch_width: int = 64,
) -> LargeSocQualification:
    """Materialize, elaborate, and instrument scheme A and the shared B/C RTL."""
    if cpu_id not in _CPU_FILELISTS:
        raise InputValidationError(f"unsupported large-SoC CPU {cpu_id!r}")
    repository = (Path(repository_root).resolve() if repository_root else
                  Path(__file__).resolve().parents[3])
    materials = repository / "materials"
    builder_rtl = repository / "src" / "myfuzz" / "builder" / "rtl"
    output = Path(output_dir).resolve()
    if output.exists():
        shutil.rmtree(output)
    project = output / "project"
    project.mkdir(parents=True)

    copied_sources, copied_includes = _materialize_sources(
        materials, builder_rtl, project, cpu_id,
    )
    flat = emit_large_flat_soc(cpu_id)
    flat_inputs = tuple(
        {"target": str(port["name"]), "width": int(port["width"])}
        for port in flat.external_ports if port["direction"] == "input"
    )
    contract = build_superset_input_contract(flat_inputs)
    soc = emit_large_generated_soc(cpu_id, rom_words=rom_words)
    runtime = project / "runtime"
    rom_artifact = generate_level1_rom(
        builtin_cpu_execution_profile(cpu_id),
        tuple(ip.window for ip in formal_axi_lite_ip_set()), runtime,
    )
    actual_rom_words = (runtime / "level1_rom.hex").read_text(encoding="ascii").count("\n")
    if actual_rom_words != rom_words:
        raise InputValidationError(
            f"requested ROM_WORDS={rom_words} but generated image has {actual_rom_words} words"
        )
    harness = emit_large_soc_transaction_harness(
        soc.module_name, contract, rom_words=actual_rom_words,
        rom_hex_file="rtl/runtime/level1_rom.hex",
    )

    generated = project / "generated"
    generated.mkdir()
    flat_path = generated / "flat_top.sv"
    fabric_path = generated / "large_soc_fabric.sv"
    soc_path = generated / "large_soc.sv"
    harness_path = generated / "large_soc_harness.sv"
    flat_path.write_text(flat.rtl, encoding="utf-8")
    fabric_path.write_text(soc.fabric_rtl, encoding="utf-8")
    soc_path.write_text(soc.rtl, encoding="utf-8")
    harness_path.write_text(harness.rtl, encoding="utf-8")

    copied_includes = (*copied_includes, runtime)
    flat_manifest = _manifest(
        project, flat.module_name, copied_sources, copied_includes, (flat_path,), "flat_sources.f",
    )
    generated_manifest = _manifest(
        project, harness.module_name, copied_sources, copied_includes,
        (fabric_path, soc_path, harness_path), "generated_sources.f",
    )
    flat_analysis, flat_frontend = analyze_elaboration_with_frontend(
        flat_manifest, project_root=project,
    )
    generated_analysis, generated_frontend = analyze_elaboration_with_frontend(
        generated_manifest, project_root=project,
    )

    component_ids = ("cpu.main", *(f"ip.{ip.instance_id}" for ip in formal_axi_lite_ip_set()))
    flat_roots = {"cpu.main": (f"{flat.module_name}.cpu0",)}
    generated_roots = {"cpu.main": (f"{harness.module_name}.i_soc.i_cpu",)}
    for ip in formal_axi_lite_ip_set():
        flat_roots[f"ip.{ip.instance_id}"] = (f"{flat.module_name}.{ip.instance_id}",)
        generated_roots[f"ip.{ip.instance_id}"] = (
            f"{harness.module_name}.i_soc.i_{ip.instance_id}",
        )
    required_boundaries = {_BOUNDARY_MODULES[ip.type_id] for ip in formal_axi_lite_ip_set()}
    cpu_boundary = ("picorv32_level1_adapter" if cpu_id == "picorv32"
                    else "ultra_riscv_level1_adapter")
    flat_required = {flat.module_name, cpu_boundary, *required_boundaries}
    generated_required = {harness.module_name, cpu_boundary, *required_boundaries}
    flat_coverage = run_soc_instrumentation(
        flat_manifest, project, output / "instrumented_flat",
        required_modules=flat_required,
        optional_modules=_active_module_names(flat_analysis) - flat_required,
        frontend_manifest=dict(flat_frontend), coverage_abi_version=2,
        hierarchy_component_roots=flat_roots, coverage_epoch_width=coverage_epoch_width,
        force=True,
    )
    generated_coverage = run_soc_instrumentation(
        generated_manifest, project, output / "instrumented_generated",
        required_modules=generated_required,
        optional_modules=_active_module_names(generated_analysis) - generated_required,
        frontend_manifest=dict(generated_frontend), coverage_abi_version=2,
        hierarchy_component_roots=generated_roots, coverage_epoch_width=coverage_epoch_width,
        force=True,
    )
    flat_points = _included_points(flat_coverage)
    generated_points = _included_points(generated_coverage)
    if set(flat_points) != set(generated_points):
        missing_flat = sorted(set(generated_points) - set(flat_points))
        missing_generated = sorted(set(flat_points) - set(generated_points))
        raise InputValidationError(
            "A and B/C do not expose the same primary Coverage ABI v2 points: "
            f"missing_flat={len(missing_flat)}, missing_generated={len(missing_generated)}"
        )
    if (flat_coverage["coverage_abi"]["catalog_digest"] !=
            generated_coverage["coverage_abi"]["catalog_digest"]):
        raise InputValidationError("A and B/C primary Coverage ABI v2 digests differ")
    if {str(point["component_id"]) for point in flat_points.values()} != set(component_ids):
        raise InputValidationError("primary Coverage ABI omits a preregistered CPU/IP component")

    common_ids = tuple(sorted(flat_points))
    report = {
        "schema": QUALIFICATION_SCHEMA,
        "cpu_id": cpu_id,
        "schemes": {
            "A": {"top": flat.module_name, "coverage": flat_coverage["coverage_abi"]},
            "B_C": {"top": harness.module_name, "coverage": generated_coverage["coverage_abi"]},
        },
        "input_layout": contract.layout.to_dict(),
        "rom_artifact": rom_artifact.to_dict(),
        "scheme_input_use": [item.to_dict() for item in contract.scheme_use],
        "common_point_count": len(common_ids),
        "common_point_ids": common_ids,
    }
    (output / "qualification_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return LargeSocQualification(
        cpu_id, output.as_posix(), flat.module_name, harness.module_name, contract,
        flat_manifest, generated_manifest, flat_coverage, generated_coverage, common_ids,
    )


def _materialize_sources(
    materials: Path, builder_rtl: Path, project: Path, cpu_id: str,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    filelists = [_CPU_FILELISTS[cpu_id]]
    filelists.extend(dict.fromkeys(ip.filelist for ip in formal_axi_lite_ip_set()))
    sources: list[Path] = []
    includes: list[Path] = []
    for relative in filelists:
        manifest = build_elaboration_manifest(
            top_module="unused", filelists=(materials / relative,), allow_roots=(materials,),
        )
        for source in manifest.sources:
            original = Path(source.path)
            destination = project / "materials" / original.relative_to(materials)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, destination)
            if destination not in sources:
                sources.append(destination)
        for include in manifest.include_dirs:
            original = Path(include)
            destination = project / "materials" / original.relative_to(materials)
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(original, destination)
            if destination not in includes:
                includes.append(destination)
    for original in sorted(builder_rtl.glob("*.sv")):
        destination = project / "builder_rtl" / original.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        sources.append(destination)
    return tuple(dict.fromkeys(sources)), tuple(dict.fromkeys(includes))


def _manifest(
    project: Path,
    top: str,
    sources: Iterable[Path],
    includes: Iterable[Path],
    generated: Iterable[Path],
    filelist_name: str,
) -> ElaborationManifest:
    filelist = project / filelist_name
    lines = [f"+incdir+{path.relative_to(project).as_posix()}" for path in includes]
    lines.extend(path.relative_to(project).as_posix() for path in (*tuple(sources), *tuple(generated)))
    filelist.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return build_elaboration_manifest(
        top_module=top, filelists=(filelist,), allow_roots=(project,),
    )


def _included_points(result: dict[str, object]) -> dict[str, dict[str, object]]:
    abi = result["coverage_abi"]
    assert isinstance(abi, dict)
    points = abi["points"]
    assert isinstance(points, (list, tuple))
    return {str(point["point_id"]): point for point in points if point["included"]}


def _active_module_names(analysis: object) -> set[str]:
    modules = analysis.modules
    by_name = {module.name: module for module in modules}
    by_original = {module.original_name: module for module in modules}
    pending = [next(module for module in modules if module.top)]
    active: set[str] = set()
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
                    f"frontend hierarchy references unknown module {instance.module_type!r}"
                )
            pending.append(child)
    return active
