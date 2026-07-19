#!/usr/bin/env python3
"""Run compose-v5 A/B/C/D campaigns serially and write a coverage summary."""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.compose_v5 import load_compose_v5_manifest  # noqa: E402
from myfuzz.builder.compose_v5_target import (  # noqa: E402
    build_compose_v5_target_artifact_from_manifest,
)
from myfuzz.builder.contracts import content_digest  # noqa: E402
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.scripts.compose_v5_campaign import (  # noqa: E402
    ComposeV5CampaignError,
    run as run_campaign,
)


ABCD_SCHEMA = "myfuzz.compose-v5-abcd-report/v1"


class ComposeV5AbcdError(ValueError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest", type=Path, help="build A and BCD target artifacts from this manifest")
    mode.add_argument("--flat-artifact", type=Path, help="existing scheme-A flat target artifact")
    parser.add_argument("--generated-artifact", type=Path, help="existing generated-SoC artifact for B/C/D")
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--allow-root", type=Path, action="append", default=[])
    parser.add_argument("--frontend-library", type=Path)
    parser.add_argument("--verilator-bin", default="verilator")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seconds", type=float, required=True, help="wall-clock budget per scheme")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--max-testcases", type=int)
    parser.add_argument("--testcase-bytes", type=int, default=64)
    parser.add_argument("--target-timeout", type=float, default=10.0)
    parser.add_argument("--target-name", default="myfuzz_target")
    parser.add_argument("--stall-inputs-before-escalation", type=int, default=256)
    parser.add_argument("--force", action="store_true")
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.seconds <= 0:
        raise ComposeV5AbcdError("--seconds must be positive")
    if args.jobs <= 0:
        raise ComposeV5AbcdError("--jobs must be positive")
    output = args.output_dir.resolve()
    if output.exists():
        if not args.force and any(output.iterdir()):
            raise ComposeV5AbcdError(f"output directory is not empty: {output}")
        if args.force:
            shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    artifacts = _resolve_artifacts(args, output)
    campaigns_root = output / "campaigns"
    campaigns_root.mkdir()
    rows: list[dict[str, object]] = []
    campaign_reports: dict[str, str] = {}

    for scheme in ("A", "B", "C", "D"):
        artifact = artifacts["flat"] if scheme == "A" else artifacts["generated"]
        scheme_output = campaigns_root / f"scheme_{scheme.lower()}"
        command = run_campaign(argparse.Namespace(
            artifact=artifact,
            scheme=scheme,
            seconds=float(args.seconds),
            output_dir=scheme_output,
            seed=int(args.seed),
            max_testcases=args.max_testcases,
            testcase_bytes=int(args.testcase_bytes),
            testcase_file=[],
            target_timeout=float(args.target_timeout),
            target_name=str(args.target_name),
            stall_inputs_before_escalation=int(args.stall_inputs_before_escalation),
        ))
        report_path = Path(command["campaign_report"])
        report = _read_json(report_path)
        campaign_reports[scheme] = report_path.as_posix()
        rows.append(_summary_row(scheme, artifact, report, report_path))

    csv_path = output / "abcd_summary.csv"
    _write_csv(csv_path, rows)
    report: dict[str, object] = {
        "schema": ABCD_SCHEMA,
        "status": "valid",
        "mode": "manifest_build" if args.manifest else "existing_artifacts",
        "seconds_per_scheme": float(args.seconds),
        "seed": int(args.seed),
        "max_testcases": args.max_testcases,
        "testcase_bytes": int(args.testcase_bytes),
        "artifacts": {key: value.as_posix() for key, value in artifacts.items()},
        "campaign_reports": campaign_reports,
        "summary_csv": csv_path.as_posix(),
        "rows": rows,
    }
    report["digest"] = content_digest(report)
    report_path = output / "abcd_report.json"
    _write_json_atomic(report_path, report)
    _write_json_atomic(output / "command_report.json", {
        "schema": "myfuzz.compose-v5-abcd-command/v1",
        "status": "valid",
        "abcd_report": report_path.as_posix(),
        "summary_csv": csv_path.as_posix(),
    })
    return report


def _resolve_artifacts(args: argparse.Namespace, output: Path) -> dict[str, Path]:
    if args.manifest is None:
        if args.generated_artifact is None:
            raise ComposeV5AbcdError("--generated-artifact is required with --flat-artifact")
        return {
            "flat": args.flat_artifact.resolve(strict=True),
            "generated": args.generated_artifact.resolve(strict=True),
        }

    if args.generated_artifact is not None:
        raise ComposeV5AbcdError("--generated-artifact is only valid with --flat-artifact")
    manifest = load_compose_v5_manifest(args.manifest)
    roots = args.allow_root or [args.project_root]
    artifact_root = output / "artifacts"
    flat = artifact_root / "scheme_a_flat"
    generated = artifact_root / "scheme_bcd_generated"
    build_compose_v5_target_artifact_from_manifest(
        manifest,
        project_root=args.project_root,
        allow_roots=roots,
        scheme="A",
        output_dir=flat,
        frontend_library=args.frontend_library,
        verilator_bin=args.verilator_bin,
        jobs=int(args.jobs),
        target_name=str(args.target_name),
        force=True,
    )
    build_compose_v5_target_artifact_from_manifest(
        manifest,
        project_root=args.project_root,
        allow_roots=roots,
        scheme="B",
        output_dir=generated,
        frontend_library=args.frontend_library,
        verilator_bin=args.verilator_bin,
        jobs=int(args.jobs),
        target_name=str(args.target_name),
        force=True,
        stall_inputs_before_escalation=int(args.stall_inputs_before_escalation),
    )
    return {"flat": flat, "generated": generated}


def _summary_row(
    scheme: str,
    artifact: Path,
    report: Mapping[str, object],
    report_path: Path,
) -> dict[str, object]:
    return {
        "scheme": scheme,
        "artifact": artifact.as_posix(),
        "campaign_report": report_path.as_posix(),
        "completed_count": _int(report, "completed_count"),
        "settled_count": _int(report, "settled_count"),
        "failed_count": _int(report, "failed_count"),
        "dut_steps": _int(report, "dut_steps"),
        "eval_count": _int(report, "eval_count"),
        "coverage_hits": _int(report, "coverage_hits"),
        "coverage_bytes": _int(report, "coverage_bytes"),
        "max_adaptive_strength": _int(report, "max_adaptive_strength"),
    }


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ComposeV5AbcdError("cannot write empty ABCD summary")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="ascii") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _read_json(path: Path) -> Mapping[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ComposeV5AbcdError(f"{path} must contain a JSON object")
    return value


def _int(value: Mapping[str, object], key: str) -> int:
    raw = value.get(key)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise ComposeV5AbcdError(f"campaign report {key} must be a non-negative integer")
    return raw


def _write_json_atomic(path: Path, value: object) -> None:
    payload = json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run(args)
    except (ComposeV5AbcdError, ComposeV5CampaignError, InputValidationError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "abcd_report": str(Path(report["summary_csv"]).with_name("abcd_report.json")),
        "summary_csv": report["summary_csv"],
        "digest": report["digest"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
