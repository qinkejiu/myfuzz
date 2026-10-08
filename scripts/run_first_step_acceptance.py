#!/usr/bin/env python3
"""Analyze a first-step acceptance run, or launch one through the frozen entry.

``analyze`` streams the saved artifacts of one online run directory and prints
the ``first_step_acceptance_report.v1`` report. ``run`` composes the existing
``scripts/run_ibex_pulp_online.py`` entry point (never a new RTL path), then
analyzes the produced run and optionally replays it in fresh RTL. Every command
it would execute is printed and recorded, so ``--dry-run`` can be inspected
without starting any RTL process.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.acceptance_metrics import (  # noqa: E402
    DEFAULT_MAX_CERTIFICATES,
    analyze_run,
    render_markdown,
)


ONLINE_RUNNER = ROOT / "scripts" / "run_ibex_pulp_online.py"
DEFAULT_CLIENT_BINARY = (ROOT / "third_party" / "rfuzz" / "upstream" /
                         "rfuzz_reference" / "fuzzer" / "target" / "release" /
                         "kfuzz")
RUN_PLAN_SCHEMA_VERSION = "first_step_acceptance_run_plan.v1"
RUN_LOG_NAME = "first_step_acceptance_run.json"
REPLAY_LOG_NAME = "first_step_acceptance_replay.json"


def _dump(document: object) -> str:
    return json.dumps(document, sort_keys=True, allow_nan=False)


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _analyze_arguments(args: argparse.Namespace) -> list[str]:
    run_dir = getattr(args, "run_dir", None)
    if run_dir is None:
        run_dir = args.output_dir
    return [sys.executable, str(Path(__file__).resolve()), "analyze",
            "--run-dir", str(run_dir),
            "--max-certificates", str(args.max_certificates)]


def _analyze_command(args: argparse.Namespace) -> int:
    report = analyze_run(
        args.run_dir, replay_dir=args.replay_dir,
        max_certificates=args.max_certificates, max_pending=args.max_pending,
        max_event_gap=args.max_event_gap,
        require_native_receipts=args.require_native_receipts,
        verify_semantic=args.verify_semantic,
        ingest_batch_size=args.ingest_batch_size)
    payload = _dump(report)
    print(payload)
    if args.json_out is not None:
        _write_text(Path(args.json_out), payload + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_markdown(report))
    return 0


def _number(value: float) -> str:
    """Render integral budgets as integers, so printed commands match the docs."""
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _trace_path(output_dir: Path) -> Path:
    meta = output_dir / "online_final_trace.meta.json"
    if meta.is_file():
        return meta
    return output_dir / "online_final_trace.json"


def _replay_command(args: argparse.Namespace, output_dir: Path) -> list[str]:
    replay_cache = (Path(args.replay_cache_dir)
                    if args.replay_cache_dir is not None
                    else Path(f"{output_dir}-replay-cache"))
    return [sys.executable, str(ONLINE_RUNNER), "replay",
            "--cache-dir", str(replay_cache),
            "--plan", str(output_dir / "online_plan.json"),
            "--trace", str(_trace_path(output_dir))]


def _run_plan(args: argparse.Namespace) -> dict:
    output_dir = Path(args.output_dir)
    cache_dir = (Path(args.cache_dir) if args.cache_dir is not None
                 else output_dir.parent / f"{output_dir.name}-cache")
    run_id = args.run_id or output_dir.name
    run_command = [sys.executable, str(ONLINE_RUNNER), "run",
                   "--client-binary", str(args.client_binary),
                   "--cache-dir", str(cache_dir),
                   "--output", str(output_dir),
                   "--seconds", _number(args.seconds),
                   "--max-tests", str(args.max_tests)]
    if args.seed is not None:
        run_command += ["--seed", str(args.seed)]
    run_command += ["--run-id", run_id]
    if args.cpu_retirement:
        run_command.append("--cpu-retirement")
    if args.gpio_consumption:
        run_command.append("--gpio-consumption")
    if args.native_irq_receipts:
        run_command.append("--native-irq-receipts")
    if args.compressed_trace:
        run_command.append("--compressed-trace")
    commands = [run_command]
    replay_command = None
    if args.replay:
        # The trace artifact name depends on how the session finalizes; the
        # executed replay command is recomputed from the produced files.
        replay_command = _replay_command(args, output_dir)
        commands.append(replay_command)
    return {
        "schema_version": RUN_PLAN_SCHEMA_VERSION,
        "run_dir": str(output_dir),
        "cache_dir": str(cache_dir),
        "run_id": run_id,
        "seconds": args.seconds,
        "max_tests": args.max_tests,
        "compressed_trace": args.compressed_trace,
        "replay_requested": args.replay,
        "commands": commands,
        "replay_trace_resolved_after_run": bool(args.replay),
        "analysis_command": _analyze_arguments(args),
        "shell": " && ".join(shlex.join(command) for command in commands),
    }


def _execute(command: list[str]) -> subprocess.CompletedProcess:
    print(f"$ {shlex.join(command)}", file=sys.stderr, flush=True)
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _run_command(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    plan = _run_plan(args)
    if args.dry_run:
        print(_dump({**plan, "dry_run": True, "analysis": None}))
        return 0
    if not Path(args.client_binary).is_file():
        raise ValueError(f"RFuzz client binary does not exist: {args.client_binary}")
    if not ONLINE_RUNNER.is_file():
        raise ValueError(f"online entry point does not exist: {ONLINE_RUNNER}")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output directory must be new")

    exit_codes = []
    run_process = _execute(plan["commands"][0])
    exit_codes.append(run_process.returncode)
    if run_process.returncode != 0:
        sys.stderr.write(run_process.stdout)
        sys.stderr.write(run_process.stderr)
        raise RuntimeError(
            f"online session exited with {run_process.returncode}: "
            f"{shlex.join(plan['commands'][0])}")
    # The runner's own summary is kept on stderr so stdout stays one JSON plan.
    sys.stderr.write(run_process.stdout)

    replay_dir = None
    replay_record = None
    if args.replay:
        resolved_replay = _replay_command(args, output_dir)
        plan["commands"][1] = resolved_replay
        plan["shell"] = " && ".join(shlex.join(command)
                                    for command in plan["commands"])
        replay_process = _execute(resolved_replay)
        exit_codes.append(replay_process.returncode)
        replay_record = {
            "command": resolved_replay,
            "exit_code": replay_process.returncode,
            "stdout": replay_process.stdout.strip(),
            "stderr": replay_process.stderr.strip(),
        }
        replay_path = output_dir / REPLAY_LOG_NAME
        _write_text(replay_path, _dump(replay_record) + "\n")
        if replay_process.returncode == 0:
            replay_dir = replay_path
        else:
            sys.stderr.write(replay_process.stderr)

    report = analyze_run(output_dir, replay_dir=replay_dir,
                         max_certificates=args.max_certificates,
                         max_pending=args.max_pending,
                         max_event_gap=args.max_event_gap,
                         require_native_receipts=args.require_native_receipts,
                         verify_semantic=args.verify_semantic,
                         ingest_batch_size=args.ingest_batch_size)
    if args.json_out is not None:
        _write_text(Path(args.json_out), _dump(report) + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_markdown(report))
    log_path = output_dir / RUN_LOG_NAME
    _write_text(log_path, _dump({
        **plan, "dry_run": False, "command_exit_codes": exit_codes,
        "replay": replay_record, "analysis": report}) + "\n")
    print(_dump({**plan, "dry_run": False, "command_exit_codes": exit_codes,
                 "replay": replay_record, "run_log": str(log_path),
                 "analysis": report}))
    return 0 if all(code == 0 for code in exit_codes) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser(
        "analyze", help="stream one saved online run into an acceptance report")
    analyze.add_argument("--run-dir", type=Path, required=True)
    analyze.add_argument("--replay-dir", type=Path,
                         help="fresh replay run directory or saved comparison JSON")
    analyze.add_argument("--json-out", type=Path)
    analyze.add_argument("--markdown-out", type=Path)
    analyze.add_argument("--max-certificates", type=int,
                         default=DEFAULT_MAX_CERTIFICATES)
    analyze.add_argument("--max-pending", type=int, default=128)
    analyze.add_argument("--max-event-gap", type=int, default=4096)
    analyze.add_argument("--no-require-native-receipts", dest="require_native_receipts",
                         action="store_false")
    analyze.add_argument("--no-verify-semantic", dest="verify_semantic",
                         action="store_false")
    analyze.add_argument("--ingest-batch-size", type=int, default=256)
    analyze.set_defaults(require_native_receipts=True, verify_semantic=True)

    run = commands.add_parser(
        "run", help="launch the existing online entry and analyze its run")
    run.add_argument("--seconds", type=float, required=True)
    run.add_argument("--max-tests", type=int, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--client-binary", type=Path, default=DEFAULT_CLIENT_BINARY)
    run.add_argument("--cache-dir", type=Path)
    run.add_argument("--seed", type=int)
    run.add_argument("--run-id")
    run.add_argument("--cpu-retirement", action="store_true",
                     help="observe official RVFI with the authenticated Ibex wrapper")
    run.add_argument("--gpio-consumption", action="store_true",
                     help="observe authenticated passive GPIO register and input consumption facts")
    run.add_argument("--native-irq-receipts", action="store_true",
                     help="record parsed Ibex pre/post IRQ decisions; requires RVFI")
    run.add_argument("--compressed-trace", action="store_true",
                     help="save lossless indexed zlib event blocks")
    run.add_argument("--replay", action="store_true",
                     help="compare the saved evidence with fresh RTL after analysis")
    run.add_argument("--replay-cache-dir", type=Path)
    run.add_argument("--json-out", type=Path)
    run.add_argument("--markdown-out", type=Path)
    run.add_argument("--max-certificates", type=int,
                     default=DEFAULT_MAX_CERTIFICATES)
    run.add_argument("--max-pending", type=int, default=128)
    run.add_argument("--max-event-gap", type=int, default=4096)
    run.add_argument("--no-require-native-receipts", dest="require_native_receipts",
                     action="store_false")
    run.add_argument("--no-verify-semantic", dest="verify_semantic",
                     action="store_false")
    run.add_argument("--ingest-batch-size", type=int, default=256)
    run.add_argument("--dry-run", action="store_true",
                     help="print the exact commands and exit without starting RTL")
    run.set_defaults(require_native_receipts=True, verify_semantic=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return _run_command(args)
        return _analyze_command(args)
    except (ValueError, OSError, RuntimeError, TimeoutError) as exc:
        print(f"first-step-acceptance-error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
