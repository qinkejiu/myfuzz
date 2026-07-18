"""Build and run a protocol-driven SoCIR v2 / RawBits v3 experiment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from myfuzz.builder import (
    InputValidationError, build_protocol_system_v2, load_system_spec,
    run_generated_bcd_campaign,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a generic generated SoC and paired B/C/D campaign")
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cpu-profile", choices=("picorv32", "ultra_riscv"), required=True)
    parser.add_argument("--module-name")
    parser.add_argument("--cycles", type=int, default=1024)
    parser.add_argument("--seeds", default=",".join(str(value) for value in range(10)))
    parser.add_argument("--checkpoints", default="")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--operation-timeout", type=int, default=65535)
    parser.add_argument("--coverage-epoch-width", type=int, default=16)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--verilator", default="verilator")
    parser.add_argument("--build-only", action="store_true")
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    built = build_protocol_system_v2(
        load_system_spec(args.spec), args.project_root, output / "build",
        cpu_profile_id=args.cpu_profile,
        module_name=args.module_name,
        operation_timeout_limit=args.operation_timeout,
        coverage_epoch_width=args.coverage_epoch_width,
        verilator_bin=args.verilator,
        jobs=args.jobs,
    )
    report: dict[str, object] = {
        "schema": "myfuzz.protocol-system-command/v2",
        "status": "built" if args.build_only else "completed",
        "build_report": built.report_path,
        "target_dir": built.pipeline.target.path,
        "baseline_a_affected": False,
    }
    if not args.build_only:
        campaign = run_generated_bcd_campaign(
            built.pipeline.target.path,
            output / "campaign",
            seeds=_integers(args.seeds, "seeds"),
            cycles=args.cycles,
            checkpoints=_integers(args.checkpoints, "checkpoints") if args.checkpoints else (),
            timeout_seconds=args.timeout_seconds,
        )
        report["campaign_report"] = str(Path(campaign.output_dir) / "bcd_campaign_report.json")
    report_path = output / "command_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return report


def _integers(value: str, label: str) -> tuple[int, ...]:
    try:
        result = tuple(int(item.strip(), 0) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise InputValidationError(f"{label} must be comma-separated integers") from exc
    if not result:
        raise InputValidationError(f"{label} must not be empty")
    return result


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
