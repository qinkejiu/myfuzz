#!/usr/bin/env python3
"""Compare pure-random AXI-Lite wires with a protocol-constrained harness."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import shutil
import statistics
import sys
import time


REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT = REPO_ROOT / "materials" / "capability" / "axi_lite"
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(ROOT))

from freeze_manifest import build_manifest  # noqa: E402
from myfuzz.builder.atomic_target import build_verilator_target, run_verilator_target  # noqa: E402
from myfuzz.builder.axi_lite import AxiLiteFabricConfig, emit_axi_lite_fabric  # noqa: E402
from myfuzz.builder.contracts import (  # noqa: E402
    ConstraintIR, SystemIR, build_elaboration_manifest, derive_elaboration_manifest,
)
from myfuzz.builder.graph_diff import verify_realized_system_ir  # noqa: E402
from myfuzz.builder.harness import EmittedHarness  # noqa: E402
from myfuzz.builder.input_model import PortDirection  # noqa: E402
from myfuzz.builder.instrumentation_bridge import run_soc_instrumentation  # noqa: E402
from myfuzz.builder.qualification import QualificationOracle  # noqa: E402
from myfuzz.builder.qualification_pipeline import (  # noqa: E402
    BINDING_MODULE, CLOCK_MODULE, FABRIC_MODULE, TOP_MODULE, _MASTER_OUTPUTS,
    _SEMANTICS, _WIDTHS, _active_module_names, _coverage_from_dict, _emit_binding,
    _emit_clock_reset_adapter, _manifest_from_dict, _materialize_sources,
    _tool_version, _write_filelist,
)
from myfuzz.builder.rawbits import build_rawbits_layout, write_rawbits_testcase  # noqa: E402
from myfuzz.builder.rtl_analysis import analyze_elaboration_with_frontend  # noqa: E402
from myfuzz.builder.soc_emitter import emit_generated_soc_top  # noqa: E402


CASE_ID = "axi_lite_constraint_effect"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _port(name: str, direction: PortDirection, width: int, *, external: bool = False) -> dict:
    return {"name": name, "direction": direction.value, "width": width, "external": external}


def _build_ip_system_ir(ips: tuple[dict, ...], bases: tuple[int, ...], sizes: tuple[int, ...]) -> SystemIR:
    modules = []
    connections = []

    def connect(source: str, target: str, kind: str) -> None:
        connections.append({
            "source": source, "target": target,
            "kind": "clock_reset" if kind in {"clock", "reset"} else "protocol",
            "reason": "generated AXI-Lite constraint-effect system",
            "evidence_source": "capability_manifest", "confidence": "proven",
        })

    modules.append({
        "name": "clock", "module_type": CLOCK_MODULE, "instance": "u_clock_reset",
        "parameters": {}, "ports": (
            _port("clk_i", PortDirection.INPUT, 1, external=True),
            _port("resetn_i", PortDirection.INPUT, 1, external=True),
            _port("clk", PortDirection.OUTPUT, 1),
            _port("resetn", PortDirection.OUTPUT, 1),
            _port("reset_high", PortDirection.OUTPUT, 1),
        ),
    })
    fabric_ports = [_port("aclk", PortDirection.INPUT, 1), _port("aresetn", PortDirection.INPUT, 1)]
    for semantic in _SEMANTICS:
        direction = PortDirection.INPUT if semantic in _MASTER_OUTPUTS else PortDirection.OUTPUT
        fabric_ports.append(_port(f"m_{semantic}", direction, _WIDTHS[semantic], external=True))
    for semantic in _SEMANTICS:
        direction = PortDirection.OUTPUT if semantic in _MASTER_OUTPUTS else PortDirection.INPUT
        fabric_ports.append(_port(f"s_{semantic}", direction, _WIDTHS[semantic] * len(ips)))
    modules.append({
        "name": "fabric", "module_type": FABRIC_MODULE, "instance": "u_fabric",
        "parameters": {"ADDR_WIDTH": 32, "DATA_WIDTH": 32, "SLAVES": len(ips)},
        "ports": tuple(fabric_ports),
    })

    binding_ports = []
    for semantic in _SEMANTICS:
        direction = PortDirection.INPUT if semantic in _MASTER_OUTPUTS else PortDirection.OUTPUT
        binding_ports.append(_port(f"s_{semantic}", direction, _WIDTHS[semantic] * len(ips)))
    for index, candidate in enumerate(ips):
        for semantic in _SEMANTICS:
            direction = PortDirection.OUTPUT if semantic in _MASTER_OUTPUTS else PortDirection.INPUT
            width = int(candidate["address_width"]) if semantic in {"awaddr", "araddr"} else _WIDTHS[semantic]
            binding_ports.append(_port(f"ip{index}_{semantic}", direction, width))
    modules.append({
        "name": "binding", "module_type": BINDING_MODULE, "instance": "u_binding",
        "parameters": {}, "ports": tuple(binding_ports),
    })

    for index, candidate in enumerate(ips):
        ports = [
            _port(str(candidate["interface"]["clock"]), PortDirection.INPUT, 1),
            _port(str(candidate["interface"]["reset"]), PortDirection.INPUT, 1),
        ]
        for semantic in _SEMANTICS:
            direction = PortDirection.INPUT if semantic in _MASTER_OUTPUTS else PortDirection.OUTPUT
            width = int(candidate["address_width"]) if semantic in {"awaddr", "araddr"} else _WIDTHS[semantic]
            ports.append(_port(str(candidate["interface"][semantic]), direction, width))
        modules.append({
            "name": f"ip{index}", "module_type": candidate["module"],
            "instance": f"u_ip{index}", "parameters": {}, "ports": tuple(ports),
        })

    connect("clock.clk", "fabric.aclk", "clock")
    connect("clock.resetn", "fabric.aresetn", "reset")
    for semantic in _SEMANTICS:
        if semantic in _MASTER_OUTPUTS:
            connect(f"fabric.s_{semantic}", f"binding.s_{semantic}", semantic)
        else:
            connect(f"binding.s_{semantic}", f"fabric.s_{semantic}", semantic)
    for index, candidate in enumerate(ips):
        connect("clock.clk", f"ip{index}.{candidate['interface']['clock']}", "clock")
        reset_source = "resetn" if str(candidate["interface"]["reset"]).endswith("n") else "reset_high"
        connect(f"clock.{reset_source}", f"ip{index}.{candidate['interface']['reset']}", "reset")
        for semantic in _SEMANTICS:
            binding = f"binding.ip{index}_{semantic}"
            ip = f"ip{index}.{candidate['interface'][semantic]}"
            connect(binding, ip, semantic) if semantic in _MASTER_OUTPUTS else connect(ip, binding, semantic)
    windows = tuple({"target": ip["id"], "base": base, "size": size, "unit": "byte"}
                    for ip, base, size in zip(ips, bases, sizes))
    return SystemIR(CASE_ID, tuple(modules), tuple(connections), windows)


def _slice(layout, target: str) -> str:
    entry = next(item for item in layout.entries if item.target == target)
    return f"raw_bits_i[{entry.offset} +: {entry.raw_width}]"


def _mapped_address(raw: str, bases: tuple[int, ...], sizes: tuple[int, ...]) -> list[str]:
    lines = [" function automatic logic [31:0] map_address(input logic [31:0] raw);", "  begin", "   case (raw[2:0])"]
    for index, (base, size) in enumerate(zip(bases, sizes)):
        mask = size - 4
        lines.append(f"    3'd{index}: map_address=32'h{base:08x} + (raw & 32'h{mask:08x});")
    lines += ["    default: map_address=32'h00000000;", "   endcase", "  end", " endfunction"]
    return lines


def _emit_protocol_harness(layout, coverage_abi, bases: tuple[int, ...], sizes: tuple[int, ...]) -> EmittedHarness:
    awvalid = _slice(layout, "awvalid")
    awaddr = _slice(layout, "awaddr")
    wvalid = _slice(layout, "wvalid")
    wdata = _slice(layout, "wdata")
    wstrb = _slice(layout, "wstrb")
    bready = _slice(layout, "bready")
    arvalid = _slice(layout, "arvalid")
    araddr = _slice(layout, "araddr")
    rready = _slice(layout, "rready")
    lines = [
        "module generated_harness_top (",
        " input logic clk_i, input logic harness_resetn_i, input logic start_i,",
        " input logic mode_constrained_i, input logic [15:0] format_version_i,",
        " input logic [255:0] layout_digest_i, input logic [255:0] coverage_abi_digest_i,",
        f" input logic [{layout.cycle_width - 1}:0] raw_bits_i,",
        " input logic raw_bits_valid_i, input logic end_i,",
        " output logic raw_bits_ready_o, output logic done_o, output logic format_error_o,",
        f" output logic [{coverage_abi.width - 1}:0] coverage_o, output logic coverage_valid_o",
        ");",
        f" localparam logic [255:0] EXPECTED_LAYOUT_DIGEST=256'h{layout.digest};",
        f" localparam logic [255:0] EXPECTED_COVERAGE_DIGEST=256'h{coverage_abi.manifest_digest};",
        " localparam logic [2:0] H_IDLE=0, H_RESET=1, H_RUN=2, H_DRAIN=3, H_DONE=4;",
        " localparam logic [2:0] T_IDLE=0, T_WSEND=1, T_WRESP=2, T_RSEND=3, T_RRESP=4;",
        " logic [2:0] hstate, tstate; integer reset_count, drain_count;",
        " logic aw_pending, w_pending; logic [31:0] tx_addr, tx_data; logic [3:0] tx_strb;",
        " logic soc_resetn;",
        " logic m_awvalid, m_awready; logic [31:0] m_awaddr;",
        " logic m_wvalid, m_wready; logic [31:0] m_wdata; logic [3:0] m_wstrb;",
        " logic m_bvalid, m_bready; logic [1:0] m_bresp;",
        " logic m_arvalid, m_arready; logic [31:0] m_araddr;",
        " logic m_rvalid, m_rready; logic [31:0] m_rdata; logic [1:0] m_rresp;",
        f" logic [{coverage_abi.width - 1}:0] soc_coverage;",
        *_mapped_address("raw", bases, sizes),
        " always_comb begin",
        "  raw_bits_ready_o=(hstate==H_RUN); done_o=(hstate==H_DONE);",
        "  coverage_o=soc_coverage; coverage_valid_o=done_o; soc_resetn=(hstate!=H_IDLE && hstate!=H_RESET);",
        "  m_awvalid=0; m_awaddr=0; m_wvalid=0; m_wdata=0; m_wstrb=0; m_bready=0;",
        "  m_arvalid=0; m_araddr=0; m_rready=0;",
        "  if (!mode_constrained_i) begin",
        f"   m_awvalid={awvalid}; m_awaddr={awaddr}; m_wvalid={wvalid};",
        f"   m_wdata={wdata}; m_wstrb={wstrb}; m_bready={bready};",
        f"   m_arvalid={arvalid}; m_araddr={araddr}; m_rready={rready};",
        "  end else begin",
        "   case (tstate)",
        "    T_WSEND: begin m_awvalid=aw_pending; m_awaddr=tx_addr; m_wvalid=w_pending; m_wdata=tx_data; m_wstrb=tx_strb; end",
        "    T_WRESP: m_bready=1'b1;",
        "    T_RSEND: begin m_arvalid=1'b1; m_araddr=tx_addr; end",
        "    T_RRESP: m_rready=1'b1;",
        "    default: begin end",
        "   endcase",
        "  end",
        " end",
        " always_ff @(posedge clk_i or negedge harness_resetn_i) begin",
        "  if (!harness_resetn_i) begin hstate<=H_IDLE; tstate<=T_IDLE; reset_count<=0; drain_count<=0; format_error_o<=0; aw_pending<=0; w_pending<=0; tx_addr<=0; tx_data<=0; tx_strb<=0; end",
        "  else begin",
        "   case (hstate)",
        "    H_IDLE: if (start_i) begin if (format_version_i!=16'd2 || layout_digest_i!=EXPECTED_LAYOUT_DIGEST || coverage_abi_digest_i!=EXPECTED_COVERAGE_DIGEST) begin format_error_o<=1; hstate<=H_DONE; end else begin reset_count<=0; hstate<=H_RESET; end end",
        "    H_RESET: if (reset_count+1>=2) hstate<=H_RUN; else reset_count<=reset_count+1;",
        "    H_RUN: if (end_i) begin drain_count<=0; hstate<=H_DRAIN; end",
        "    H_DRAIN: begin drain_count<=drain_count+1; if ((!mode_constrained_i || tstate==T_IDLE) && drain_count>=4) hstate<=H_DONE; else if (drain_count>=64) hstate<=H_DONE; end",
        "    H_DONE: hstate<=H_DONE; default: hstate<=H_IDLE;",
        "   endcase",
        "   if (hstate==H_RESET) begin tstate<=T_IDLE; aw_pending<=0; w_pending<=0; end",
        "   else if (mode_constrained_i && (hstate==H_RUN || hstate==H_DRAIN)) begin",
        "    case (tstate)",
        "     T_IDLE: if (hstate==H_RUN && raw_bits_valid_i && raw_bits_ready_o) begin",
        f"      if ({awvalid}) begin tx_addr<=map_address({awaddr}); tx_data<={wdata}; tx_strb<=({wstrb}==0) ? 4'hf : {wstrb}; aw_pending<=1; w_pending<=1; tstate<=T_WSEND; end",
        f"      else if ({arvalid}) begin tx_addr<=map_address({araddr}); tstate<=T_RSEND; end",
        "     end",
        "     T_WSEND: begin",
        "      if (aw_pending && m_awready) aw_pending<=0; if (w_pending && m_wready) w_pending<=0;",
        "      if ((!aw_pending || m_awready) && (!w_pending || m_wready)) tstate<=T_WRESP;",
        "     end",
        "     T_WRESP: if (m_bvalid) tstate<=T_IDLE;",
        "     T_RSEND: if (m_arready) tstate<=T_RRESP;",
        "     T_RRESP: if (m_rvalid) tstate<=T_IDLE;",
        "     default: tstate<=T_IDLE;",
        "    endcase",
        "   end",
        "  end",
        " end",
        f" {TOP_MODULE} u_soc (",
        "  .clock__clk_i(clk_i), .clock__resetn_i(soc_resetn),",
        "  .fabric__m_awaddr(m_awaddr), .fabric__m_awvalid(m_awvalid), .fabric__m_awready(m_awready),",
        "  .fabric__m_wdata(m_wdata), .fabric__m_wstrb(m_wstrb), .fabric__m_wvalid(m_wvalid), .fabric__m_wready(m_wready),",
        "  .fabric__m_bresp(m_bresp), .fabric__m_bvalid(m_bvalid), .fabric__m_bready(m_bready),",
        "  .fabric__m_araddr(m_araddr), .fabric__m_arvalid(m_arvalid), .fabric__m_arready(m_arready),",
        "  .fabric__m_rdata(m_rdata), .fabric__m_rresp(m_rresp), .fabric__m_rvalid(m_rvalid), .fabric__m_rready(m_rready),",
        f"  .{coverage_abi.port_name}(soc_coverage)",
        " );",
        "endmodule",
    ]
    return EmittedHarness("generated_harness_top", "\n".join(lines) + "\n", (), layout.digest)


def _coverage_by_component(abi, hit_offsets: list[int], ips: tuple[dict, ...]) -> dict:
    hits = set(hit_offsets)
    groups: dict[str, dict[str, int]] = {}
    for point in abi.points:
        if not point.get("included"):
            continue
        hierarchy = str(point["hierarchy"])
        group = "soc_glue"
        for index, candidate in enumerate(ips):
            if f".u_ip{index}" in hierarchy:
                group = str(candidate["id"])
                break
        if ".u_fabric" in hierarchy:
            group = "axi_lite_fabric"
        elif ".u_binding" in hierarchy:
            group = "address_binding"
        item = groups.setdefault(group, {"points": 0, "hits": 0})
        item["points"] += 1
        item["hits"] += int(point["offset"] in hits)
    return dict(sorted(groups.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--cycles", type=int, default=256)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--seeds", help="comma-separated paired-run seeds")
    args = parser.parse_args()

    manifest_path = ROOT / "manifest.json"
    frozen = _read_json(manifest_path)
    if frozen != build_manifest():
        raise SystemExit("capability manifest is stale")
    oracle = QualificationOracle(manifest_path.as_posix(), frozen["manifest_digest"], frozen)
    config = _read_json(ROOT / "cases/picorv32_scale_system.json")
    by_id = {item["id"]: item for item in oracle.qualified}
    ips = tuple(by_id[item] for item in config["ips"])
    selected = {item["id"]: item for item in ips}
    bases = tuple(int(item["base"]) for item in config["address_map"])
    sizes = tuple(int(item["size"]) for item in config["address_map"])

    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    project = output / "project"
    project.mkdir(parents=True)
    started = time.monotonic()
    sources, include_dirs = _materialize_sources(oracle, selected, project)
    generated = project / "generated"
    generated.mkdir()
    fabric = generated / "myfuzz_axi_lite_fabric.sv"
    binding = generated / "myfuzz_axi_lite_binding.sv"
    clock = generated / "myfuzz_clock_reset_adapter.sv"
    fabric.write_text(emit_axi_lite_fabric(AxiLiteFabricConfig(32, 32, len(ips), bases, sizes)), encoding="utf-8")
    binding.write_text(_emit_binding(ips, bases, sizes), encoding="utf-8")
    clock.write_text(_emit_clock_reset_adapter(), encoding="utf-8")
    ir = _build_ip_system_ir(ips, bases, sizes)
    emitted = emit_generated_soc_top(ir, TOP_MODULE)
    top = generated / "generated_soc_top.sv"
    top.write_text(emitted.rtl, encoding="utf-8")
    filelist = project / "sources.f"
    _write_filelist(filelist, include_dirs, (*sources, fabric, binding, clock, top), project)
    root_manifest = build_elaboration_manifest(
        top_module=TOP_MODULE, filelists=(filelist,), allow_roots=(project,),
        tools={"verilator": _tool_version("verilator")},
    )
    soc_manifest = derive_elaboration_manifest(root_manifest, stage="verified-soc", top_module=TOP_MODULE)
    analysis, frontend = analyze_elaboration_with_frontend(soc_manifest, project_root=project)
    diff = verify_realized_system_ir(ir, analysis)
    if not diff.equivalent:
        raise SystemExit("generated constraint-effect SystemIR does not match elaborated RTL")
    mandatory = {TOP_MODULE, FABRIC_MODULE, BINDING_MODULE, CLOCK_MODULE, *(item["module"] for item in ips)}
    active = _active_module_names(analysis)
    instrumentation = run_soc_instrumentation(
        soc_manifest, project, output / "instrumented", required_modules=mandatory,
        optional_modules=active - mandatory, frontend_manifest=frontend, force=True,
    )
    instrumented_manifest = _manifest_from_dict(instrumentation["instrumented_manifest"])
    abi = _coverage_from_dict(instrumentation["coverage_abi"])
    layout = build_rawbits_layout((
        {"target": "awvalid", "width": 1, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "awaddr", "width": 32, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "wvalid", "width": 1, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "wdata", "width": 32, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "wstrb", "width": 4, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "bready", "width": 1, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "arvalid", "width": 1, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "araddr", "width": 32, "purpose": "raw_axi_lite", "provenance": "ab_test"},
        {"target": "rready", "width": 1, "purpose": "raw_axi_lite", "provenance": "ab_test"},
    ))
    constraint_ir = ConstraintIR(layout.digest, layout.cycle_width, ({
        "target": "axi_lite_master", "primitive": "AXI_LITE_PROTOCOL_FSM",
        "provenance": "axi_lite_profile/v1", "same_rawbits": True,
        "rules": ["mapped_address", "stable_until_ready", "wait_for_response"],
    },))
    harness = _emit_protocol_harness(layout, abi, bases, sizes)
    generation_report = {
        "schema": "myfuzz.constraint-effect/v1", "case_id": CASE_ID,
        "comparison_control": {
            "same_soc_top": True, "same_target": True, "same_rawbits": True,
            "only_runtime_variable": "mode_constrained_i",
        },
        "raw_mode": "direct per-cycle random AXI-Lite wire drive",
        "constrained_mode": "profile-generated legal transaction FSM",
        "address_map": config["address_map"], "ips": list(config["ips"]),
    }
    target = build_verilator_target(
        output / "targets", manifest=instrumented_manifest,
        source_root=output / "instrumented", harness=harness, layout=layout,
        constraint_ir=constraint_ir, coverage_abi=abi,
        evidence={
            "original_soc_rtl": top, "rfuzz_config": {"cycle_width": layout.cycle_width},
            "address_graph": {"windows": config["address_map"]},
            "connection_graph": {"system_ir": ir.to_dict(), "equivalent": diff.equivalent},
            "port_bindings": {"external_master": emitted.external_ports},
            "instrumentation_manifest": Path(instrumentation["instrumentation_manifest"]),
            "generation_report": generation_report,
        }, jobs=args.jobs,
    )
    seeds = tuple(int(item) for item in args.seeds.split(",")) if args.seeds else (args.seed,)
    experiments = []
    for seed in seeds:
        rng = random.Random(seed)
        raw_cycles = tuple(rng.getrandbits(layout.cycle_width) for _ in range(args.cycles))
        testcase = write_rawbits_testcase(layout, raw_cycles, output / "testcases", name=f"seed_{seed}")
        runs = []
        for mode in ("raw", "constrained"):
            run_started = time.monotonic()
            run = run_verilator_target(
                target.path, testcase["rawbits"], testcase["metadata"], output / "runs",
                mode=mode, timeout_seconds=120,
            )
            runs.append({
                "mode": mode, "seconds": time.monotonic() - run_started,
                "target_digest": run.report["target_digest"],
                "testcase_sha256": run.report["testcase_sha256"],
                "coverage_hit_count_by_cycle": run.report["coverage_hit_count_by_cycle"],
                "coverage_hit_offsets": run.report["coverage_hit_offsets"],
                "coverage_by_component": _coverage_by_component(abi, run.report["coverage_hit_offsets"], ips),
            })
        raw, constrained = runs
        experiments.append({
            "seed": seed, "runs": runs,
            "comparison": {
                "raw_final_hits": raw["coverage_hit_count_by_cycle"][-1],
                "constrained_final_hits": constrained["coverage_hit_count_by_cycle"][-1],
                "constrained_minus_raw": constrained["coverage_hit_count_by_cycle"][-1] - raw["coverage_hit_count_by_cycle"][-1],
                "constrained_unique_hits": len(set(constrained["coverage_hit_offsets"]) - set(raw["coverage_hit_offsets"])),
                "raw_unique_hits": len(set(raw["coverage_hit_offsets"]) - set(constrained["coverage_hit_offsets"])),
            },
        })
    deltas = [item["comparison"]["constrained_minus_raw"] for item in experiments]
    raw_hits = [item["comparison"]["raw_final_hits"] for item in experiments]
    constrained_hits = [item["comparison"]["constrained_final_hits"] for item in experiments]
    report = {
        "schema": "myfuzz.constraint-effect-report/v1", "status": "passed",
        "seeds": list(seeds), "cycles": args.cycles, "rawbits_width": layout.cycle_width,
        "coverage_point_count": abi.width, "compile_seconds": time.monotonic() - started,
        "control_proof": {
            "same_target_digest": all(
                item["runs"][0]["target_digest"] == item["runs"][1]["target_digest"]
                for item in experiments
            ),
            "same_testcase_sha256_within_each_pair": all(
                item["runs"][0]["testcase_sha256"] == item["runs"][1]["testcase_sha256"]
                for item in experiments
            ),
            "only_runtime_variable": "mode_constrained_i",
        },
        "experiments": experiments,
        "aggregate": {
            "pair_count": len(experiments),
            "raw_final_hits_mean": statistics.fmean(raw_hits),
            "constrained_final_hits_mean": statistics.fmean(constrained_hits),
            "coverage_gain_mean": statistics.fmean(deltas),
            "coverage_gain_median": statistics.median(deltas),
            "coverage_gain_min": min(deltas), "coverage_gain_max": max(deltas),
            "constrained_wins": sum(delta > 0 for delta in deltas),
        },
    }
    report_path = output / "constraint_effect_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", **report["aggregate"], "report": report_path.as_posix()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
