"""Executable Slice H qualification pipeline over the frozen AXI-Lite oracle."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import time
from typing import Any, Mapping, Sequence

from .atomic_target import COMPLETION_SCHEMA, build_verilator_target, run_verilator_target
from .axi_lite import AxiLiteFabricConfig, emit_axi_lite_fabric
from .constraint_engine import build_constraint_ir
from .contracts import (
    CoverageABI, ElaborationManifest, ResolvedFile, SystemIR,
    build_elaboration_manifest, derive_elaboration_manifest,
)
from .graph_diff import verify_realized_system_ir
from .harness import HarnessPort, emit_dual_mode_harness
from .input_model import InputValidationError, PortDirection
from .instrumentation_bridge import run_soc_instrumentation
from .qualification import QualificationOracle, evaluate_acceptance, load_qualification_oracle
from .rawbits import build_rawbits_layout, write_rawbits_testcase
from .rtl_analysis import analyze_elaboration_with_frontend
from .soc_emitter import emit_generated_soc_top


CASE_SCHEMA = "myfuzz.qualification-case/v1"
PIPELINE_SCHEMA = "myfuzz.qualification-pipeline/v1"
TOP_MODULE = "generated_soc_top"
FABRIC_MODULE = "myfuzz_axi_lite_fabric"
BINDING_MODULE = "myfuzz_axi_lite_binding"
CLOCK_MODULE = "myfuzz_clock_reset_adapter"

_SEMANTICS = (
    "awvalid", "awready", "awaddr", "wvalid", "wready", "wdata", "wstrb",
    "bvalid", "bready", "bresp", "arvalid", "arready", "araddr", "rvalid",
    "rready", "rdata", "rresp",
)
_WIDTHS = {
    "awvalid": 1, "awready": 1, "awaddr": 32, "wvalid": 1, "wready": 1,
    "wdata": 32, "wstrb": 4, "bvalid": 1, "bready": 1, "bresp": 2,
    "arvalid": 1, "arready": 1, "araddr": 32, "rvalid": 1, "rready": 1,
    "rdata": 32, "rresp": 2,
}
_MASTER_OUTPUTS = {
    "awvalid", "awaddr", "wvalid", "wdata", "wstrb", "bready", "arvalid",
    "araddr", "rready",
}


@dataclass(frozen=True)
class QualificationBuild:
    case_id: str
    case_dir: str
    target_dir: str
    coverage_width: int
    compile_seconds: float


def build_qualification_case(
    oracle: QualificationOracle,
    case_id: str,
    output_root: str | Path,
    *,
    verilator_bin: str = "verilator",
    jobs: int = 1,
) -> QualificationBuild:
    """Build one real, fully analyzed and instrumented qualification target."""
    case_spec = _case(oracle, case_id)
    pipeline_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(output_root).resolve()
    case_dir = root / case_id
    if (case_dir / "case_completion.json").is_file():
        completion = _read_json(case_dir / "case_completion.json")
        if (completion.get("oracle_digest") == oracle.digest
                and completion.get("pipeline_implementation_sha256") == pipeline_digest
                and _cached_target_is_complete(completion)):
            return QualificationBuild(
                case_id, case_dir.as_posix(), str(completion["target_dir"]),
                int(completion["coverage_width"]), float(completion["compile_seconds"]),
            )
    if case_dir.exists():
        shutil.rmtree(case_dir)
    project = case_dir / "project"
    project.mkdir(parents=True)
    started = time.monotonic()

    selected = _selected_candidates(oracle, case_spec)
    sources, include_dirs = _materialize_sources(oracle, selected, project)
    case_config = _load_case_config(oracle, case_spec)
    address_map = tuple(case_config["address_map"])
    ips = tuple(selected[identifier] for identifier in case_config["ips"])
    bases = tuple(int(item["base"]) for item in address_map)
    sizes = tuple(int(item["size"]) for item in address_map)
    _validate_address_binding(ips, bases, sizes)

    generated = project / "generated"
    generated.mkdir()
    fabric_path = generated / "myfuzz_axi_lite_fabric.sv"
    binding_path = generated / "myfuzz_axi_lite_binding.sv"
    clock_path = generated / "myfuzz_clock_reset_adapter.sv"
    _write_text(
        fabric_path,
        emit_axi_lite_fabric(AxiLiteFabricConfig(32, 32, len(ips), bases, sizes)),
    )
    _write_text(binding_path, _emit_binding(ips, bases, sizes))
    _write_text(clock_path, _emit_clock_reset_adapter())

    ir = _build_system_ir(selected[str(case_config["cpu"])], ips, bases, sizes)
    emitted = emit_generated_soc_top(ir, TOP_MODULE)
    top_path = generated / "generated_soc_top.sv"
    _write_text(top_path, emitted.rtl)
    generated_sources = (fabric_path, binding_path, clock_path, top_path)

    filelist = project / "sources.f"
    _write_filelist(filelist, include_dirs, (*sources, *generated_sources), project)
    # Include directories are immutable root facts, so rebuild the root through the combined filelist.
    full_root = build_elaboration_manifest(
        top_module=TOP_MODULE, filelists=(filelist,), allow_roots=(project,),
        tools={"verilator": _tool_version(verilator_bin)},
    )
    soc_manifest = derive_elaboration_manifest(full_root, stage="verified-soc", top_module=TOP_MODULE)
    analysis, frontend_manifest = analyze_elaboration_with_frontend(
        soc_manifest, project_root=project,
    )
    diff = verify_realized_system_ir(ir, analysis)

    active = _active_module_names(analysis)
    mandatory = {
        TOP_MODULE, FABRIC_MODULE, BINDING_MODULE, CLOCK_MODULE,
        *(str(candidate["module"]) for candidate in selected.values()),
    }
    if not mandatory.issubset(active):
        raise InputValidationError("qualification hierarchy omits a mandatory generated or component module")
    optional = active - mandatory
    instrumented_dir = case_dir / "instrumented"
    instrumentation = run_soc_instrumentation(
        soc_manifest, project, instrumented_dir, required_modules=mandatory,
        optional_modules=optional,
        frontend_manifest=frontend_manifest, force=True,
    )
    instrumented_manifest = _manifest_from_dict(instrumentation["instrumented_manifest"])
    coverage_abi = _coverage_from_dict(instrumentation["coverage_abi"])

    layout = build_rawbits_layout(({
        "target": "cpu__fuzz_irq", "raw_width": 5, "value_width": 32,
        "purpose": "entropy_matched_interrupt_selection", "provenance": "qualification_oracle",
    },))
    constraints = build_constraint_ir(layout, ({
        "target": "cpu__fuzz_irq", "primitive": "ONEHOT",
        "provenance": "axi_lite_cpu_interrupt_profile/v1", "idle_value": 0,
    },))
    harness = emit_dual_mode_harness(
        TOP_MODULE, layout, constraints, (
            HarnessPort("clock__clk_i", PortDirection.INPUT, 1, "clock"),
            HarnessPort("clock__resetn_i", PortDirection.INPUT, 1, "reset", True),
            HarnessPort("cpu__fuzz_irq", PortDirection.INPUT, 32),
        ), coverage_abi=coverage_abi, reset_cycles=2, drain_cycles=4,
    )

    reports = case_dir / "reports"
    reports.mkdir()
    address_graph = {"schema": "myfuzz.address-graph/v1", "windows": list(address_map)}
    connection_graph = {
        "schema": "myfuzz.connection-graph/v1", "system_ir": ir.to_dict(),
        "planned_realized_equivalent": diff.equivalent,
    }
    port_bindings = _port_binding_report(selected, ips)
    generation_report = {
        "schema": PIPELINE_SCHEMA, "case_id": case_id, "status": "verified",
        "oracle_digest": oracle.digest, "soc_manifest_digest": soc_manifest.digest,
        "pipeline_implementation_sha256": pipeline_digest,
        "coverage_abi_digest": coverage_abi.manifest_digest,
        "required_instrumented_modules": sorted(mandatory),
        "optional_instrumented_modules": sorted(optional),
        "coverage": _coverage_summary(coverage_abi),
        "rawbits": {"format": "RFUZZ RawBits v2", "layout_digest": layout.digest,
                    "cycle_width": layout.cycle_width, "modes": ["raw", "constrained"]},
        "ram_initialization": "none", "cpu_program_injection": "none",
    }
    _write_json(reports / "address_graph.json", address_graph)
    _write_json(reports / "connection_graph.json", connection_graph)
    _write_json(reports / "port_bindings.json", port_bindings)
    _write_json(reports / "generation_report.json", generation_report)
    _write_json(reports / "system_ir.json", ir.to_dict())

    target = build_verilator_target(
        case_dir / "targets", manifest=instrumented_manifest, source_root=instrumented_dir,
        harness=harness, layout=layout, constraint_ir=constraints, coverage_abi=coverage_abi,
        evidence={
            "original_soc_rtl": top_path,
            "rfuzz_config": generation_report["rawbits"],
            "address_graph": address_graph,
            "connection_graph": connection_graph,
            "port_bindings": port_bindings,
            "instrumentation_manifest": Path(str(instrumentation["instrumentation_manifest"])),
            "generation_report": generation_report,
        }, verilator_bin=verilator_bin, jobs=jobs,
    )
    elapsed = time.monotonic() - started
    budget = case_spec["resource_budget"]
    if elapsed > float(budget["compile_seconds"]):
        raise InputValidationError(f"qualification case {case_id} exceeded compile budget")
    artifact_bytes = _tree_size(case_dir)
    if artifact_bytes > int(budget["max_bytes"]):
        raise InputValidationError(f"qualification case {case_id} exceeded artifact budget")
    completion = {
        "schema": PIPELINE_SCHEMA, "case_id": case_id, "status": "built",
        "target_dir": target.path, "target_digest": target.target_digest,
        "coverage_width": coverage_abi.width, "compile_seconds": elapsed,
        "artifact_bytes": artifact_bytes, "expected_artifact_bytes": case_spec["expected_artifact_bytes"],
        "oracle_digest": oracle.digest,
        "pipeline_implementation_sha256": pipeline_digest,
    }
    _write_json(case_dir / "case_completion.json", completion)
    return QualificationBuild(case_id, case_dir.as_posix(), target.path, coverage_abi.width, elapsed)


def run_qualification(
    oracle_path: str | Path,
    materials_root: str | Path,
    output_root: str | Path,
    *,
    verilator_bin: str = "verilator",
    jobs: int = 1,
    seeds: Sequence[int] | None = None,
    cycles: int | None = None,
) -> Mapping[str, object]:
    """Build every frozen case and execute paired RAW/CONSTRAINED experiments."""
    oracle = load_qualification_oracle(
        oracle_path, materials_root=materials_root, verify_elaboration=True,
        verilator_bin=verilator_bin,
    )
    experiment = oracle.data["experiment"]
    selected_seeds = tuple(int(value) for value in (seeds or experiment["seeds"]))
    selected_cycles = int(cycles or experiment["cycles"])
    full_denominator = selected_seeds == tuple(experiment["seeds"]) and selected_cycles == experiment["cycles"]
    output = Path(output_root).resolve()
    output.mkdir(parents=True, exist_ok=True)
    builds = [
        build_qualification_case(oracle, str(case["id"]), output, verilator_bin=verilator_bin, jobs=jobs)
        for case in oracle.data["cases"]
    ]
    case_results = [{"case_id": build.case_id, "status": "passed"} for build in builds]
    run_results: list[Mapping[str, object]] = []
    for build in builds:
        case_dir = Path(build.case_dir)
        layout_value = _read_json(Path(build.target_dir) / "evidence/bit_layout.json")
        layout = _layout_from_dict(layout_value)
        for seed in selected_seeds:
            rng = random.Random(seed)
            raw_cycles = tuple(rng.getrandbits(layout.cycle_width) for _ in range(selected_cycles))
            testcase = write_rawbits_testcase(layout, raw_cycles, case_dir / "testcases", name=f"seed_{seed}")
            reports_by_mode: dict[str, Mapping[str, object]] = {}
            for mode in ("raw", "constrained"):
                run = run_verilator_target(
                    build.target_dir, testcase["rawbits"], testcase["metadata"], case_dir / "runs",
                    mode=mode, timeout_seconds=float(experiment["timeout_seconds"]),
                )
                trace = tuple(int(value) for value in run.report["coverage_hit_count_by_cycle"])
                reports_by_mode[mode] = run.report
                run_results.append(_experiment_result(
                    build.case_id, seed, mode, trace, len(run.report["coverage_hit_offsets"]),
                    layout.cycle_width, int(experiment["early_cycle"]),
                ))
            if seed == selected_seeds[0]:
                repeat = run_verilator_target(
                    build.target_dir, testcase["rawbits"], testcase["metadata"],
                    case_dir / "determinism_runs", mode="raw",
                    timeout_seconds=float(experiment["timeout_seconds"]),
                )
                first_report = reports_by_mode["raw"]
                if (repeat.report["coverage_sha256"] != first_report["coverage_sha256"]
                        or repeat.report["coverage_trace_sha256"] != first_report["coverage_trace_sha256"]):
                    raise InputValidationError(f"qualification case {build.case_id} is nondeterministic")
    result: dict[str, object] = {
        "schema": PIPELINE_SCHEMA, "oracle_digest": oracle.digest,
        "status": "passed", "full_denominator": full_denominator,
        "cases": case_results, "runs": run_results,
    }
    if full_denominator:
        result["acceptance"] = evaluate_acceptance(oracle, case_results, run_results)
    _write_json(output / "qualification_report.json", result)
    return result


def _build_system_ir(
    cpu: Mapping[str, object], ips: tuple[Mapping[str, object], ...],
    bases: tuple[int, ...], sizes: tuple[int, ...],
) -> SystemIR:
    modules: list[Mapping[str, Any]] = []
    connections: list[Mapping[str, str]] = []

    def port(name: str, direction: PortDirection, width: int, semantic: str, *, external: bool = False):
        return {"name": name, "direction": direction.value, "width": width,
                "semantic": semantic, "external": external}

    def connect(source: str, target: str, semantic: str, kind: str = "data") -> None:
        connections.append({"source": source, "target": target, "kind": kind,
                            "reason": "frozen AXI-Lite qualification binding",
                            "evidence_source": "qualification_oracle", "confidence": "proven"})

    modules.append({
        "name": "clock", "module_type": CLOCK_MODULE, "instance": "u_clock_reset",
        "parameters": {}, "ports": (
            port("clk_i", PortDirection.INPUT, 1, "clock_source", external=True),
            port("resetn_i", PortDirection.INPUT, 1, "reset_source", external=True),
            port("clk", PortDirection.OUTPUT, 1, "clock"),
            port("resetn", PortDirection.OUTPUT, 1, "reset_active_low"),
            port("reset_high", PortDirection.OUTPUT, 1, "reset_active_high"),
        ),
    })
    cpu_ports = [
        port(str(cpu["interface"]["clock"]), PortDirection.INPUT, 1, "clock"),
        port(str(cpu["interface"]["reset"]), PortDirection.INPUT, 1,
             "reset_active_low" if str(cpu["interface"]["reset"]).endswith("n") else "reset_active_high"),
        port("fuzz_irq", PortDirection.INPUT, 32, "interrupt", external=True),
    ]
    for semantic in _SEMANTICS:
        direction = PortDirection.OUTPUT if semantic in _MASTER_OUTPUTS else PortDirection.INPUT
        cpu_ports.append(port(str(cpu["interface"][semantic]), direction, _WIDTHS[semantic], semantic))
    modules.append({"name": "cpu", "module_type": cpu["module"], "instance": "u_cpu",
                    "parameters": {}, "ports": tuple(cpu_ports)})

    fabric_ports = [port("aclk", PortDirection.INPUT, 1, "clock"),
                    port("aresetn", PortDirection.INPUT, 1, "reset_active_low")]
    for semantic in _SEMANTICS:
        direction = PortDirection.INPUT if semantic in _MASTER_OUTPUTS else PortDirection.OUTPUT
        fabric_ports.append(port(f"m_{semantic}", direction, _WIDTHS[semantic], semantic))
    for semantic in _SEMANTICS:
        direction = PortDirection.OUTPUT if semantic in _MASTER_OUTPUTS else PortDirection.INPUT
        fabric_ports.append(port(f"s_{semantic}", direction, _WIDTHS[semantic] * len(ips), f"packed_{semantic}"))
    modules.append({"name": "fabric", "module_type": FABRIC_MODULE, "instance": "u_fabric",
                    "parameters": {"ADDR_WIDTH": 32, "DATA_WIDTH": 32, "SLAVES": len(ips)},
                    "ports": tuple(fabric_ports)})

    binding_ports = []
    for semantic in _SEMANTICS:
        direction = PortDirection.INPUT if semantic in _MASTER_OUTPUTS else PortDirection.OUTPUT
        binding_ports.append(port(f"s_{semantic}", direction, _WIDTHS[semantic] * len(ips), f"packed_{semantic}"))
    for index, candidate in enumerate(ips):
        address_width = int(candidate["address_width"])
        for semantic in _SEMANTICS:
            direction = PortDirection.OUTPUT if semantic in _MASTER_OUTPUTS else PortDirection.INPUT
            width = address_width if semantic in {"awaddr", "araddr"} else _WIDTHS[semantic]
            binding_ports.append(port(f"ip{index}_{semantic}", direction, width, f"ip{index}_{semantic}"))
    modules.append({"name": "binding", "module_type": BINDING_MODULE, "instance": "u_binding",
                    "parameters": {}, "ports": tuple(binding_ports)})

    for index, candidate in enumerate(ips):
        ip_ports = [
            port(str(candidate["interface"]["clock"]), PortDirection.INPUT, 1, "clock"),
            port(str(candidate["interface"]["reset"]), PortDirection.INPUT, 1,
                 "reset_active_low" if str(candidate["interface"]["reset"]).endswith("n") else "reset_active_high"),
        ]
        for semantic in _SEMANTICS:
            direction = PortDirection.INPUT if semantic in _MASTER_OUTPUTS else PortDirection.OUTPUT
            width = int(candidate["address_width"]) if semantic in {"awaddr", "araddr"} else _WIDTHS[semantic]
            ip_ports.append(port(str(candidate["interface"][semantic]), direction, width, f"ip{index}_{semantic}"))
        modules.append({"name": f"ip{index}", "module_type": candidate["module"],
                        "instance": f"u_ip{index}", "parameters": {},
                        "ports": tuple(ip_ports)})

    connect("clock.clk", "cpu." + str(cpu["interface"]["clock"]), "clock", "clock_reset")
    connect("clock.clk", "fabric.aclk", "clock", "clock_reset")
    cpu_reset = "resetn" if str(cpu["interface"]["reset"]).endswith("n") else "reset_high"
    connect(f"clock.{cpu_reset}", "cpu." + str(cpu["interface"]["reset"]), "reset", "clock_reset")
    connect("clock.resetn", "fabric.aresetn", "reset_active_low", "clock_reset")
    for semantic in _SEMANTICS:
        cpu_endpoint = "cpu." + str(cpu["interface"][semantic])
        fabric_endpoint = f"fabric.m_{semantic}"
        if semantic in _MASTER_OUTPUTS:
            connect(cpu_endpoint, fabric_endpoint, semantic)
        else:
            connect(fabric_endpoint, cpu_endpoint, semantic)
        if semantic in _MASTER_OUTPUTS:
            connect(f"fabric.s_{semantic}", f"binding.s_{semantic}", f"packed_{semantic}")
        else:
            connect(f"binding.s_{semantic}", f"fabric.s_{semantic}", f"packed_{semantic}")
    for index, candidate in enumerate(ips):
        connect("clock.clk", f"ip{index}." + str(candidate["interface"]["clock"]), "clock", "clock_reset")
        reset = "resetn" if str(candidate["interface"]["reset"]).endswith("n") else "reset_high"
        connect(f"clock.{reset}", f"ip{index}." + str(candidate["interface"]["reset"]), "reset", "clock_reset")
        for semantic in _SEMANTICS:
            binding_endpoint = f"binding.ip{index}_{semantic}"
            ip_endpoint = f"ip{index}." + str(candidate["interface"][semantic])
            if semantic in _MASTER_OUTPUTS:
                connect(binding_endpoint, ip_endpoint, f"ip{index}_{semantic}")
            else:
                connect(ip_endpoint, binding_endpoint, f"ip{index}_{semantic}")
    windows = tuple({"target": str(candidate["id"]), "base": base, "size": size, "unit": "byte"}
                    for candidate, base, size in zip(ips, bases, sizes))
    return SystemIR("qualification_" + str(cpu["split"]), tuple(modules), tuple(connections), windows)


def _emit_binding(
    ips: tuple[Mapping[str, object], ...], bases: tuple[int, ...], sizes: tuple[int, ...],
) -> str:
    if len(ips) < 2:
        raise InputValidationError("qualification binding requires at least two IPs")
    if len(bases) != len(ips) or len(sizes) != len(ips):
        raise InputValidationError("qualification binding address windows do not match IP count")
    ports = []
    for semantic in _SEMANTICS:
        direction = "input" if semantic in _MASTER_OUTPUTS else "output"
        ports.append(
            f" {direction} logic {_sv_range(_WIDTHS[semantic] * len(ips))}s_{semantic}"
        )
    for index, candidate in enumerate(ips):
        for semantic in _SEMANTICS:
            direction = "output" if semantic in _MASTER_OUTPUTS else "input"
            width = int(candidate["address_width"]) if semantic in {"awaddr", "araddr"} else _WIDTHS[semantic]
            ports.append(f" {direction} logic {_sv_range(width)}ip{index}_{semantic}")
    lines = ["// SPDX-License-Identifier: Apache-2.0", f"module {BINDING_MODULE} (",
             ",\n".join(ports), ");", " always_comb begin"]
    for index, candidate in enumerate(ips):
        aw = int(candidate["address_width"])
        base = bases[index]
        lines.extend([
            f"  ip{index}_awvalid=s_awvalid[{index}];",
            f"  ip{index}_wvalid=s_wvalid[{index}]; ip{index}_bready=s_bready[{index}];",
            f"  ip{index}_arvalid=s_arvalid[{index}]; ip{index}_rready=s_rready[{index}];",
            f"  ip{index}_wdata=s_wdata[{index * 32} +: 32]; ip{index}_wstrb=s_wstrb[{index * 4} +: 4];",
            f"  if (s_awvalid[{index}]) ip{index}_awaddr=s_awaddr[{index * 32} +: 32]-32'h{base:x}; else ip{index}_awaddr={aw}'d0;",
            f"  if (s_arvalid[{index}]) ip{index}_araddr=s_araddr[{index * 32} +: 32]-32'h{base:x}; else ip{index}_araddr={aw}'d0;",
            f"  s_awready[{index}]=ip{index}_awready; s_wready[{index}]=ip{index}_wready;",
            f"  s_bvalid[{index}]=ip{index}_bvalid; s_bresp[{index * 2} +: 2]=ip{index}_bresp;",
            f"  s_arready[{index}]=ip{index}_arready; s_rvalid[{index}]=ip{index}_rvalid;",
            f"  s_rdata[{index * 32} +: 32]=ip{index}_rdata; s_rresp[{index * 2} +: 2]=ip{index}_rresp;",
        ])
    lines.extend([" end", "endmodule"])
    return "\n".join(lines) + "\n"


def _emit_clock_reset_adapter() -> str:
    return f"""// SPDX-License-Identifier: Apache-2.0
module {CLOCK_MODULE}(
 input logic clk_i, input logic resetn_i,
 output logic clk, output logic resetn, output logic reset_high
);
 always_comb begin
  clk=clk_i;
  if (resetn_i) begin resetn=1'b1; reset_high=1'b0; end
  else begin resetn=1'b0; reset_high=1'b1; end
 end
endmodule
"""


def _materialize_sources(
    oracle: QualificationOracle, selected: Mapping[str, Mapping[str, object]], project: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    materials = Path(oracle.path).parents[2]
    source_paths: list[Path] = []
    include_dirs: list[Path] = []
    for candidate in selected.values():
        manifest = build_elaboration_manifest(
            top_module=str(candidate["module"]),
            filelists=((materials / str(candidate["filelist"])).resolve(),),
            allow_roots=(materials,),
        )
        for source in manifest.sources:
            original = Path(source.path)
            destination = project / original.relative_to(materials)
            _copy_checked(original, destination, source.sha256)
            if destination not in source_paths:
                source_paths.append(destination)
        for dependency in candidate["dependencies"]:
            original = (materials / str(dependency["path"])).resolve()
            destination = project / original.relative_to(materials)
            _copy_checked(original, destination, str(dependency["sha256"]))
        for include in manifest.include_dirs:
            original_dir = Path(include)
            destination_dir = project / original_dir.relative_to(materials)
            destination_dir.mkdir(parents=True, exist_ok=True)
            if destination_dir not in include_dirs:
                include_dirs.append(destination_dir)
    return tuple(source_paths), tuple(include_dirs)


def _selected_candidates(
    oracle: QualificationOracle, case: Mapping[str, object],
) -> dict[str, Mapping[str, object]]:
    by_id = {str(candidate["id"]): candidate for candidate in oracle.qualified}
    identifiers = (str(case["cpu"]), *(str(value) for value in case["ips"]))
    return {identifier: by_id[identifier] for identifier in identifiers}


def _case(oracle: QualificationOracle, case_id: str) -> Mapping[str, object]:
    try:
        return next(item for item in oracle.data["cases"] if item["id"] == case_id)
    except StopIteration as exc:
        raise InputValidationError(f"unknown frozen qualification case {case_id!r}") from exc


def _load_case_config(
    oracle: QualificationOracle, case: Mapping[str, object],
) -> Mapping[str, object]:
    path = Path(oracle.path).parent / "cases" / f"{case['id']}.json"
    if hashlib.sha256(path.read_bytes()).hexdigest() != case["manifest_hash"]:
        raise InputValidationError(f"qualification case {case['id']} manifest hash mismatch")
    value = _read_json(path)
    if value.get("schema") != CASE_SCHEMA or value.get("id") != case["id"]:
        raise InputValidationError(f"qualification case {case['id']} schema mismatch")
    return value


def _validate_address_binding(
    ips: tuple[Mapping[str, object], ...], bases: tuple[int, ...], sizes: tuple[int, ...],
) -> None:
    previous_end = 0
    for candidate, base, size in zip(ips, bases, sizes):
        width = int(candidate["address_width"])
        if base < previous_end or base % 4 or size <= 0 or size > (1 << width):
            raise InputValidationError(f"candidate {candidate['id']}: unsafe address translation window")
        if base + size > (1 << 32):
            raise InputValidationError(f"candidate {candidate['id']}: address window overflows fabric")
        previous_end = base + size


def _port_binding_report(
    selected: Mapping[str, Mapping[str, object]], ips: tuple[Mapping[str, object], ...],
) -> Mapping[str, object]:
    unknown_ports = [{
        "module": "cpu", "port": "fuzz_irq", "policy": "constrained_fuzz",
        "provenance": "qualification_wrapper",
    }]
    for candidate in selected.values():
        for decision in candidate.get("unknown_ports", ()):
            unknown_ports.append({
                "candidate": candidate["id"], "module": candidate["module"],
                **decision,
            })
    return {
        "schema": "myfuzz.port-bindings/v1",
        "components": [
            {"candidate": candidate["id"], "module": candidate["module"],
             "interface": candidate["interface"], "source": "qualification_oracle"}
            for candidate in selected.values()
        ],
        "generated_adapters": [
            {"module": BINDING_MODULE, "kind": "base_subtract_and_proven_low_address_slice",
             "targets": [candidate["id"] for candidate in ips]},
            {"module": CLOCK_MODULE, "kind": "shared_clock_and_reset_waveform_polarity"},
        ],
        "unknown_ports": unknown_ports,
    }


def _active_module_names(analysis) -> set[str]:
    by_name = {module.name: module for module in analysis.modules}
    by_original = {module.original_name: module for module in analysis.modules}
    pending = [next(module for module in analysis.modules if module.top)]
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
                    f"frontend hierarchy is missing child module {instance.module_type!r}"
                )
            pending.append(child)
    return active


def _coverage_summary(coverage_abi: CoverageABI) -> Mapping[str, object]:
    required = [point for point in coverage_abi.points if point["requirement"] == "required"]
    optional = [point for point in coverage_abi.points if point["requirement"] == "optional"]
    skipped: dict[str, int] = {}
    for point in coverage_abi.points:
        reason = point.get("skip_reason")
        if reason is not None:
            skipped[str(reason)] = skipped.get(str(reason), 0) + 1
    return {
        "included_point_count": coverage_abi.width,
        "required_point_count": len(required),
        "required_included_point_count": sum(bool(point["included"]) for point in required),
        "optional_point_count": len(optional),
        "optional_included_point_count": sum(bool(point["included"]) for point in optional),
        "skipped_point_count_by_reason": dict(sorted(skipped.items())),
    }


def _cached_target_is_complete(completion: Mapping[str, object]) -> bool:
    try:
        target = Path(str(completion["target_dir"])).resolve(strict=True)
        target_completion = _read_json(target / "completion_manifest.json")
    except (KeyError, OSError, InputValidationError):
        return False
    return (
        target_completion.get("schema") == COMPLETION_SCHEMA
        and target_completion.get("target_digest") == completion.get("target_digest")
    )


def _experiment_result(
    case_id: str, seed: int, mode: str, trace: tuple[int, ...], final: int,
    cycle_width: int, early_cycle: int,
) -> Mapping[str, object]:
    first = next((index + 1 for index, value in enumerate(trace) if value > 0), len(trace))
    longest = 0
    plateau = 0
    previous = 0
    for value in trace:
        if value == previous:
            plateau += 1
            longest = max(longest, plateau)
        else:
            plateau = 0
        previous = value
    return {
        "case_id": case_id, "seed": seed, "mode": mode, "status": "passed",
        "bit_budget": cycle_width * len(trace), "coverage_cleared": True,
        "first_new_coverage_cycle": first,
        "early_coverage": trace[min(early_cycle, len(trace)) - 1],
        "longest_plateau": longest, "final_coverage": final,
    }


def _manifest_from_dict(value: Mapping[str, object]) -> ElaborationManifest:
    return ElaborationManifest(
        str(value["schema"]), str(value["stage"]), str(value["top_module"]),
        str(value["language"]),
        tuple(ResolvedFile(str(item["path"]), str(item["sha256"]), int(item["size"]))
              for item in value["sources"]),
        tuple(str(item) for item in value["include_dirs"]),
        tuple(str(item) for item in value["defines"]),
        tuple((str(item[0]), str(item[1])) for item in value["parameters"]),
        tuple((str(item[0]), str(item[1])) for item in value["tools"]),
        None if value["parent_digest"] is None else str(value["parent_digest"]),
        str(value["digest"]),
    )


def _coverage_from_dict(value: Mapping[str, object]) -> CoverageABI:
    return CoverageABI(str(value["manifest_digest"]), str(value["port_name"]),
                       int(value["width"]), tuple(value["points"]))


def _layout_from_dict(value: Mapping[str, object]):
    from .rawbits import RawBitsLayout, RawBitsLayoutEntry
    return RawBitsLayout(
        tuple(RawBitsLayoutEntry(**item) for item in value["entries"]),
        int(value["cycle_width"]), int(value["bytes_per_cycle"]), str(value["digest"]),
        str(value["schema"]), str(value["byte_order"]), str(value["bit_order"]),
        str(value["cycle_order"]),
    )


def _write_filelist(path: Path, include_dirs: Sequence[Path], sources: Sequence[Path], root: Path) -> None:
    lines = [f"+incdir+{directory.relative_to(root).as_posix()}" for directory in include_dirs]
    lines.extend(source.relative_to(root).as_posix() for source in sources)
    _write_text(path, "\n".join(lines) + "\n")


def _resolved(path: Path) -> ResolvedFile:
    data = path.read_bytes()
    return ResolvedFile(path.resolve().as_posix(), hashlib.sha256(data).hexdigest(), len(data))


def _copy_checked(source: Path, destination: Path, expected_sha256: str) -> None:
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise InputValidationError(f"frozen source changed: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise InputValidationError(f"expected JSON object: {path}")
    return value


def _tree_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _tool_version(executable: str) -> str:
    completed = subprocess.run((executable, "--version"), capture_output=True, text=True)
    if completed.returncode:
        raise InputValidationError(f"cannot query {executable} version")
    return completed.stdout.strip()


def _sv_range(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--materials-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--smoke", action="store_true", help="run seed 1 for 8 cycles; not acceptance")
    args = parser.parse_args(argv)
    result = run_qualification(
        args.oracle, args.materials_root, args.output, jobs=args.jobs,
        seeds=(1,) if args.smoke else None, cycles=8 if args.smoke else None,
    )
    print(json.dumps({"status": result["status"], "full_denominator": result["full_denominator"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
