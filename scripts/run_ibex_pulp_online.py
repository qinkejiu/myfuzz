#!/usr/bin/env python3
"""Run or replay the reset-free Ibex + two PULP GPIO online RFuzz pilot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.ibex_pulp_online import (  # noqa: E402
    make_ibex_pulp_online_runtime, replay_ibex_pulp_online_files,
)
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live  # noqa: E402

#: The shipped raw seed of the live RFuzz client
#: (``run_scenario_rfuzz_live(seed_records=(bytes(8),))``).  The initial RAM
#: operator draws from exactly the record the run gives the client, and the run
#: stores it verbatim in ``seed.bin``, so a reviewer recomputes the drawn byte
#: from the run's own artifacts instead of trusting the report.
DEFAULT_INITIAL_RAM_RECORD = "0000000000000000"


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
    run.add_argument("--run-id", default="ibex-pulp-online")
    run.add_argument("--cpu-retirement", action="store_true",
                     help="observe official RVFI with the authenticated Ibex wrapper")
    run.add_argument("--native-irq-receipts", action="store_true",
                     help="record parsed Ibex pre/post IRQ decisions and receipt identity; requires RVFI")
    run.add_argument("--gpio-consumption", action="store_true",
                     help="observe authenticated passive GPIO register and input consumption facts")
    run.add_argument("--memory-commit", action="store_true",
                     help="journal authenticated host-memory commit receipts for cross-case RAM prerequisites")
    run.add_argument("--result-slot-byte-store", action="store_true",
                     help="allow one declared SB byte write to the result-slot window "
                          "0x10000 so a partial byte_enable (lane selectivity) can be observed")
    run.add_argument("--initial-ram-data", action="store_true", default=None,
                     help="opt in to the pre-session initial RAM data operator: mutate "
                          "one declared initial byte before the session starts "
                          "(MYFUZZ_INITIAL_RAM_DATA is the equivalent opt-in)")
    run.add_argument("--initial-ram-record", default=DEFAULT_INITIAL_RAM_RECORD,
                     help="hex of the raw pre-session record the initial RAM draw is "
                          "derived from; the same bytes seed the RFuzz client "
                          "(default %(default)s, the shipped seed record)")
    run.add_argument("--compressed-trace", action="store_true",
                     help="save lossless indexed zlib event blocks")
    replay = commands.add_parser("replay", help="compare saved evidence with fresh RTL")
    replay.add_argument("--cache-dir", type=Path, required=True)
    replay.add_argument("--plan", type=Path, required=True)
    replay.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            if args.output.exists() or args.output.is_symlink():
                raise ValueError("output directory must be new")
            try:
                initial_ram_record = bytes.fromhex(args.initial_ram_record)
            except ValueError as exc:
                raise ValueError(
                    "--initial-ram-record must be hexadecimal") from exc
            if not initial_ram_record:
                raise ValueError("--initial-ram-record must not be empty")
            runtime = make_ibex_pulp_online_runtime(
                cache_dir=args.cache_dir, run_id=args.run_id,
                cpu_retirement=args.cpu_retirement,
                gpio_consumption=args.gpio_consumption,
                initial_ram_data=args.initial_ram_data,
                initial_ram_record=initial_ram_record,
                **({'native_irq_receipts': True} if args.native_irq_receipts else {}),
                **({'memory_commit_receipts': True} if args.memory_commit else {}),
                **({'result_slot_byte_store': True}
                   if args.result_slot_byte_store else {}))
            result = run_scenario_rfuzz_live(
                executor=runtime.executor, client_binary=args.client_binary,
                output_dir=args.output, duration_seconds=args.seconds,
                max_tests=args.max_tests, search_seed=args.seed,
                # The seed the client receives is exactly the record the
                # operator draws from; by default both are the shipped bytes.
                seed_records=(initial_ram_record,),
                max_runs_per_batch=1,
                compressed_trace=args.compressed_trace)
            print(json.dumps({"output_dir": str(result.output_dir),
                              "tests": result.tests,
                              "statuses": result.statuses,
                              "elapsed_seconds": result.elapsed_seconds,
                              "effective_search_seconds": result.effective_search_seconds},
                             sort_keys=True))
            return 0
        comparison = replay_ibex_pulp_online_files(
            cache_dir=args.cache_dir, plan_path=args.plan, trace_path=args.trace)
        print(json.dumps({"matches": comparison.matches,
                          "first_difference": comparison.first_difference,
                          "difference_context": comparison.difference_context},
                         sort_keys=True))
        return 0 if comparison.matches else 2
    except (ValueError, OSError, RuntimeError, TimeoutError) as exc:
        print(f"ibex-pulp-online-error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
