#!/usr/bin/env python3
"""Run or replay the controlled UART CPU read observation fault."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.integration.ibex_uart_online import (  # noqa: E402
    _read_uart_online_trace, _saved_cpu_retirement_mode,
    _saved_memory_commit_mode, _saved_memory_readback_mode,
    _saved_uart_fifo_mode, make_ibex_uart_online_factory,
    make_ibex_uart_online_runtime)
from myfuzz.integration.scenario_rfuzz_live import (  # noqa: E402
    _verify_online_run_identity, run_scenario_rfuzz_live)
from myfuzz.scenario.p5_controlled_uart_fault import (  # noqa: E402
    ControlledUartReadFaultChecker)
from myfuzz.scenario.session_runtime import (  # noqa: E402
    _checker_identity, replay_online_session)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--client-binary", type=Path, required=True)
    run.add_argument("--cache-dir", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--seconds", type=float, default=30)
    run.add_argument("--max-tests", type=int, default=8)
    run.add_argument("--seed", type=int, default=43)
    run.add_argument("--run-id", default="p5-controlled-uart-read-fault")
    replay = commands.add_parser("replay")
    replay.add_argument("--cache-dir", type=Path, required=True)
    replay.add_argument("--plan", type=Path, required=True)
    replay.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()
    checker = ControlledUartReadFaultChecker()
    if args.command == "run":
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output directory must be new")
        runtime = make_ibex_uart_online_runtime(
            cache_dir=args.cache_dir, run_id=args.run_id, checker=checker,
            cpu_retirement=True, uart_fifo=True, memory_commit=True,
            memory_readback=True)
        result = run_scenario_rfuzz_live(
            executor=runtime.executor, client_binary=args.client_binary,
            output_dir=args.output, duration_seconds=args.seconds,
            max_tests=args.max_tests, search_seed=args.seed, max_runs_per_batch=1)
        print(json.dumps({"tests": result.tests, "statuses": result.statuses,
                          "fault": checker.fault, "output_dir": str(result.output_dir)},
                         sort_keys=True))
        return 0 if checker.fault is not None else 2
    reference = _read_uart_online_trace(args.trace)
    verified = _verify_online_run_identity(
        args.trace.parent, plan_path=args.plan, trace_path=args.trace,
        trace=reference)
    manifest = json.loads((args.trace.parent / "online_session_manifest.json").read_bytes())
    if manifest["checker"] != _checker_identity(checker):
        raise ValueError("saved checker identity differs from requested fault")
    factory = make_ibex_uart_online_factory(
        args.cache_dir,
        cpu_retirement=_saved_cpu_retirement_mode(args.trace.parent, verified),
        uart_fifo=_saved_uart_fifo_mode(args.trace.parent, verified),
        memory_commit=_saved_memory_commit_mode(args.trace.parent, verified),
        memory_readback=_saved_memory_readback_mode(args.trace.parent, verified))
    comparison = replay_online_session(args.plan.read_bytes(), factory, reference,
                                       checker=checker)
    print(json.dumps({"matches": comparison.matches,
                      "first_difference": comparison.first_difference,
                      "difference_context": comparison.difference_context,
                      "fault": checker.fault}, sort_keys=True))
    return 0 if comparison.matches and checker.fault is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
