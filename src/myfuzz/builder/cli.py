"""Command-line orchestration for protocol-driven system generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .discovery import discover_system
from .emitter import emit_system
from .input_model import InputValidationError, load_system_spec
from .instrumentation_bridge import run_instrumentation, update_generation_report
from .planner import plan_system
from .rfuzz_bridge import emit_rfuzz_metadata, generate_rfuzz_testcase


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a system from RTL and protocol profiles")
    parser.add_argument("--spec", type=Path, required=True, help="system specification JSON")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--wrapper", action="store_true", help="emit a wrapper when no fabric backend is needed")
    parser.add_argument("--rfuzz", action="store_true", help="emit RFUZZ metadata and a testcase")
    parser.add_argument("--rfuzz-format", choices=("legacy-v1",), help="explicitly select the legacy action encoding")
    parser.add_argument("--rfuzz-cycles", type=int, default=1024)
    parser.add_argument("--rfuzz-seed", type=int, default=1)
    parser.add_argument("--instrument-output", type=Path)
    parser.add_argument("--instrument-filelist", type=Path)
    parser.add_argument("--instrument-force", action="store_true")
    return parser


def run(args: argparse.Namespace) -> dict:
    output_dir = args.output_dir.resolve()
    spec = load_system_spec(args.spec)
    discovery = discover_system(spec, args.project_root)
    plan = plan_system(spec, discovery)
    if not plan.valid:
        raise InputValidationError("invalid system plan: " + "; ".join(plan.validation_issues))

    report = emit_system(
        plan, spec, discovery, output_dir, generate_wrapper=args.wrapper,
    )
    if args.rfuzz:
        if args.rfuzz_format != "legacy-v1":
            raise InputValidationError("--rfuzz requires explicit --rfuzz-format legacy-v1")
        emit_rfuzz_metadata(plan, output_dir, format_version=args.rfuzz_format)
        testcase_dir = output_dir / "rfuzz_testcases"
        testcase = generate_rfuzz_testcase(
            output_dir, testcase_dir, cycles=args.rfuzz_cycles, seed=args.rfuzz_seed,
            format_version=args.rfuzz_format,
        )
        report = _read_report(output_dir)
        report["rfuzz_testcase"] = testcase
        report["generated_files"].extend([
            "rfuzz_testcases/rfuzz_seed.bin", "rfuzz_testcases/rfuzz_seed.json",
        ])
        _write_report(output_dir, report)
    if args.instrument_output:
        instrumentation = run_instrumentation(
            plan,
            discovery,
            args.project_root,
            args.instrument_output,
            filelist=args.instrument_filelist,
            force=args.instrument_force,
        )
        update_generation_report(output_dir, instrumentation)
        report = _read_report(output_dir)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except (InputValidationError, OSError, ValueError) as exc:
        report = _failure_report(args, str(exc))
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _failure_report(args: argparse.Namespace, error: str) -> dict:
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "status": "failed",
        "spec": str(args.spec),
        "project_root": str(args.project_root),
        "validation_issues": [error],
        "generated_files": ["generation_report.json"],
    }
    _write_report(output_dir, report)
    return report


def _read_report(output_dir: Path) -> dict:
    return json.loads((output_dir / "generation_report.json").read_text(encoding="utf-8"))


def _write_report(output_dir: Path, report: dict) -> None:
    (output_dir / "generation_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
