#!/usr/bin/env python3
"""Run or replay the reset-free Ibex + OpenTitan UART online RFuzz pilot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.ibex_uart_online import (  # noqa: E402
    make_ibex_uart_online_runtime, replay_ibex_uart_online_files)
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="start one persistent RTL fuzz session")
    run.add_argument("--client-binary", type=Path, required=True)
    run.add_argument("--cache-dir", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--seconds", type=float, default=60.0)
    run.add_argument("--max-tests", type=int, default=10000)
    run.add_argument("--seed", type=int)
    run.add_argument("--run-id", default="ibex-uart-online")
    run.add_argument("--cpu-retirement", action="store_true",
                     help="observe official RVFI with the authenticated Ibex wrapper")
    run.add_argument("--uart-fifo", action="store_true",
                     help="observe authenticated native UART RX/FIFO consumption probes")
    run.add_argument("--memory-commit", action="store_true",
                     help="observe actual host-memory commit receipts for UART Store joins")
    run.add_argument("--memory-readback", action="store_true",
                     help="observe actual host-memory reads for UART Store readback")
    run.add_argument("--uart-wdata-byte-store", action="store_true",
                     help="enable CPU SB only for OpenTitan UART WDATA lane 0")
    run.add_argument("--compressed-trace", action="store_true",
                     help="save lossless indexed zlib event blocks")
    replay = commands.add_parser("replay", help="compare saved plan with fresh RTL")
    replay.add_argument("--cache-dir", type=Path, required=True)
    replay.add_argument("--plan", type=Path, required=True)
    replay.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            if args.output.exists() or args.output.is_symlink():
                raise ValueError("output directory must be new")
            runtime = make_ibex_uart_online_runtime(
                cache_dir=args.cache_dir, run_id=args.run_id,
                cpu_retirement=args.cpu_retirement, uart_fifo=args.uart_fifo,
                memory_commit=args.memory_commit,
                memory_readback=args.memory_readback,
                uart_wdata_byte_store=args.uart_wdata_byte_store)
            result = run_scenario_rfuzz_live(
                executor=runtime.executor, client_binary=args.client_binary,
                output_dir=args.output, duration_seconds=args.seconds,
                max_tests=args.max_tests, search_seed=args.seed,
                max_runs_per_batch=1,
                compressed_trace=args.compressed_trace)
            print(json.dumps({"output_dir": str(result.output_dir),
                              "tests": result.tests, "statuses": result.statuses,
                              "elapsed_seconds": result.elapsed_seconds,
                              "effective_search_seconds": result.effective_search_seconds},
                             sort_keys=True))
            return 0
        comparison = replay_ibex_uart_online_files(
            cache_dir=args.cache_dir, plan_path=args.plan, trace_path=args.trace)
        print(json.dumps({"matches": comparison.matches,
                          "first_difference": comparison.first_difference,
                          "difference_context": comparison.difference_context},
                         sort_keys=True))
        return 0 if comparison.matches else 2
    except (ValueError, OSError, RuntimeError, TimeoutError) as exc:
        print(f"ibex-uart-online-error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
