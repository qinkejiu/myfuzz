#!/usr/bin/env python3
"""Build and smoke a generic protocol-driven RawBits v4 CPU/IP system."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AddressBiasConfigV4, GeneratedTargetServerV4, InputValidationError,
    ProgramFragmentIR, RawBitsV4Lane, RawBitsV4Submode, V4Controller,
    build_mmio_smoke_program_fragment_v4, build_protocol_system_v4,
    encode_program_fragment_records_v4, encode_rawbits_v4_testcase,
    load_system_spec, run_protocol_campaign_v4,
    run_protocol_verilator_target_v4,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and smoke one generic protocol-driven RawBits v4 CPU/IP system",
    )
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cpu-profile", choices=("picorv32", "ultra_riscv"), required=True)
    parser.add_argument("--module-name")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--protocol-testcases", type=int, default=256)
    parser.add_argument("--records-per-testcase", type=int, default=16)
    parser.add_argument("--wall-seconds", type=float, default=30.0)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--verilator", default="verilator")
    parser.add_argument("--build-only", action="store_true")
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    for name in ("protocol_testcases", "records_per_testcase", "jobs"):
        value = getattr(args, name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise InputValidationError(f"v4 system command {name} must be positive")
    for name in ("wall_seconds", "timeout_seconds"):
        value = getattr(args, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise InputValidationError(f"v4 system command {name} must be positive")
    if args.jobs != 1:
        raise InputValidationError("v4 system command requires exactly one build job")

    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    spec = load_system_spec(args.spec)
    built = build_protocol_system_v4(
        spec, args.project_root, output / "build",
        cpu_profile_id=args.cpu_profile, module_name=args.module_name,
        verilator_bin=args.verilator, jobs=args.jobs,
    )
    report: dict[str, object] = {
        "schema": "myfuzz.protocol-system-command/v4",
        "status": "built" if args.build_only else "completed",
        "system": spec.name,
        "cpu_profile": args.cpu_profile,
        "inputs": {
            "spec": args.spec.resolve().as_posix(),
            "spec_sha256": hashlib.sha256(args.spec.read_bytes()).hexdigest(),
            "project_root": args.project_root.resolve().as_posix(),
            "seed": args.seed,
            "protocol_testcases": args.protocol_testcases,
            "records_per_testcase": args.records_per_testcase,
            "wall_seconds": args.wall_seconds,
            "timeout_seconds": args.timeout_seconds,
            "jobs": args.jobs,
        },
        "build_report": built.report_path,
        "pipeline_report": built.pipeline.report_path,
        "target_dir": built.pipeline.target.path,
        "target_digest": built.pipeline.target.target_digest,
        "coverage_abi_digest": built.pipeline.coverage_abi.manifest_digest,
        "baseline_a_affected": False,
    }
    if not args.build_only:
        smoke = _run_smoke(args, spec, built)
        smoke_path = output / "smoke_report.json"
        _write_json_atomic(smoke_path, smoke)
        report["smoke_report"] = smoke_path.as_posix()
    report_path = output / "command_report.json"
    _write_json_atomic(report_path, report)
    return report


def _run_smoke(args: argparse.Namespace, spec, built) -> Mapping[str, object]:
    layout = built.pipeline.harness.layout
    abi = built.pipeline.coverage_abi
    profile = _semantic_profile_from_target(built.pipeline.target.path)
    windows = tuple(
        (name, base, size)
        for name, base, size, _protocol in built.emitted_soc.address_windows
        if any(module.name == name and module.address is not None for module in spec.modules)
    )
    if not windows:
        raise InputValidationError("v4 system smoke found no declared address target")
    expected_components = tuple(sorted(
        module.component_id or f"ip.{module.name}"
        for module in spec.modules
        if module.kind.value != "cpu" and module.address is not None
    ))

    control = _run_cpu_fragment(
        built, profile,
        ProgramFragmentIR(
            words=(0x0000006F,), entry_pc=profile.state_domain.pc_base,
            registers={}, csrs={name: 0 for name in profile.state_domain.csr_masks},
            memory={}, privilege=profile.state_domain.privilege_modes[0],
            trap_vector=profile.state_domain.trap_vector_base,
            max_steps=min(1024, profile.state_domain.max_steps),
            profile_digest=profile.digest,
        ),
        testcase_id=0, coverage_epoch=1, timeout_seconds=args.timeout_seconds,
    )
    access = _run_cpu_fragment(
        built, profile,
        build_mmio_smoke_program_fragment_v4(
            profile, windows, max_steps=min(1024, profile.state_domain.max_steps),
        ),
        testcase_id=1, coverage_epoch=2, timeout_seconds=args.timeout_seconds,
    )
    cpu_components = _hit_components(access.coverage_bitmap, abi)
    cpu_added_components = _added_components(
        control.coverage_bitmap, access.coverage_bitmap, abi,
    )

    address_bias = AddressBiasConfigV4(windows)
    server = GeneratedTargetServerV4(
        built.pipeline.target.path, layout=layout, coverage_abi=abi,
        environment_plan=built.pipeline.environment_plan, cpu_profile=profile,
        first_coverage_epoch=3, timeout_seconds=args.timeout_seconds,
    )
    protocol = run_protocol_campaign_v4(
        V4Controller(
            layout, policy="C", seed=args.seed, coverage_bits=abi.width,
            address_bias=address_bias,
        ),
        server, wall_seconds=args.wall_seconds,
        max_testcases=args.protocol_testcases,
        records_per_testcase=args.records_per_testcase,
    )
    protocol_bitmap = base64.b64decode(protocol.coverage_bitmap_base64, validate=True)
    protocol_components = _hit_components(protocol_bitmap, abi)
    missing_cpu = sorted(set(expected_components) - set(cpu_added_components))
    missing_protocol = sorted(set(expected_components) - set(protocol_components))
    if missing_cpu or missing_protocol:
        raise InputValidationError(
            "v4 system smoke did not exercise every declared target: "
            f"cpu={missing_cpu}, protocol={missing_protocol}"
        )
    return {
        "schema": "myfuzz.protocol-system-smoke/v4",
        "status": "passed",
        "expected_target_components": list(expected_components),
        "cpu_semantic": {
            "classification": access.observed_classification,
            "dut_cycles": access.dut_cycles,
            "coverage_hits": sum(byte.bit_count() for byte in access.coverage_bitmap),
            "hit_components": list(cpu_components),
            "added_components_over_control": list(cpu_added_components),
            "wire_trace_digest": access.wire_trace_digest,
        },
        "protocol_waveform": {
            "completed_count": protocol.completed_count,
            "coverage_hits": protocol.coverage_hits,
            "lane_counts": dict(protocol.lane_counts),
            "observed_classification_counts": dict(protocol.observed_classification_counts),
            "hit_components": list(protocol_components),
        },
        "single_case_serial": True,
        "jobs": 1,
        "baseline_a_affected": False,
    }


def _run_cpu_fragment(
    built, profile, fragment: ProgramFragmentIR, *, testcase_id: int,
    coverage_epoch: int, timeout_seconds: float,
):
    records = encode_program_fragment_records_v4(
        built.pipeline.harness.layout, fragment, profile,
    )
    transport = encode_rawbits_v4_testcase(
        built.pipeline.harness.layout, lane=RawBitsV4Lane.CPU_SEMANTIC,
        submode=RawBitsV4Submode.PROGRAM_FRAGMENT,
        logical_testcase_id=testcase_id, records=records,
    )
    return run_protocol_verilator_target_v4(
        built.pipeline.target.path, transport,
        layout_digest=built.pipeline.harness.layout.digest,
        coverage_abi=built.pipeline.coverage_abi,
        coverage_epoch=coverage_epoch,
        environment_plan=built.pipeline.environment_plan,
        cpu_profile=profile, timeout_seconds=timeout_seconds,
    )


def _semantic_profile_from_target(target_dir: str):
    from myfuzz.builder import cpu_execution_profile_v4_from_dict

    path = Path(target_dir) / "evidence/cpu_execution_profile.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError("v4 system target CPU profile is unreadable") from exc
    if not isinstance(value, Mapping):
        raise InputValidationError("v4 system target CPU profile is malformed")
    return cpu_execution_profile_v4_from_dict(value)


def _hit_components(bitmap: bytes, abi) -> tuple[str, ...]:
    return tuple(sorted({
        str(point["component_id"])
        for point in abi.points
        if point.get("included") is True and point.get("component_id")
        and bitmap[int(point["offset"]) // 8] & (1 << (int(point["offset"]) % 8))
    }))


def _added_components(before: bytes, after: bytes, abi) -> tuple[str, ...]:
    return tuple(sorted({
        str(point["component_id"])
        for point in abi.points
        if point.get("included") is True and point.get("component_id")
        and after[int(point["offset"]) // 8] & (1 << (int(point["offset"]) % 8))
        and not before[int(point["offset"]) // 8] & (1 << (int(point["offset"]) % 8))
    }))


def _write_json_atomic(path: Path, value: object) -> None:
    payload = json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False,
    ) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run(args)
    except (InputValidationError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
