#!/usr/bin/env python3
"""cProfile one live Ibex+UART online session (host-side cost of each step).

Answers "为什么每条命令要几毫秒": it profiles the host between RTL replies —
JSON encode/decode, event bookkeeping, per-step input recomputation — by running
a handful of real cases through the same session the published runs use.

Usage: PYTHONPATH=src python3 scripts/profile_online_host_cost.py \
          --cache-dir RUNS_CACHE --output NEW_DIR [--cases 4] [--top 22]
"""
from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, (ROOT / "src").as_posix())

from myfuzz.integration.ibex_uart_online import (  # noqa: E402
    make_ibex_uart_online_bootstrap, make_ibex_uart_online_decoder,
    make_ibex_uart_online_factory)
from myfuzz.scenario.batch import BatchSourceEvent  # noqa: E402
from myfuzz.scenario.ibex_uart_online import uart_online_advances  # noqa: E402
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker  # noqa: E402
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession  # noqa: E402


def _round_trip_steps(runner) -> int:
    """Count the STEP commands actually issued to the RTL subprocess."""
    return int(getattr(runner, "_next_command_sequence", 0)) - 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cases", type=int, default=4)
    parser.add_argument("--top", type=int, default=22)
    args = parser.parse_args(argv[1:])
    if Path(args.output).exists():
        print(f"output directory must be new: {args.output}")
        return 3

    bootstrap = make_ibex_uart_online_bootstrap()
    decoder = make_ibex_uart_online_decoder(bootstrap=bootstrap)
    session = ScenarioSession(bootstrap.template,
                              make_ibex_uart_online_factory(Path(args.cache_dir))(),
                              checker=IbexUartOnlineChecker())
    session.declare_instruction_slots("cpu", bootstrap.instruction_start,
                                      bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    warmup = OnlineCase(
        "uart-fixed-warmup", "IP_TO_CPU",
        next(decoder.graph.path_identity(path, direction=direction)
             for direction, path in decoder.runtime_paths
             if direction == "IP_TO_CPU" and path.target == "uart_rx_to_cpu"),
        BatchSourceEvent("uart-fixed-warmup-rx", "uart", "uart_rx_byte", 0x5a, 0, 8),
        uart_online_advances("warmup"))
    session.submit_case(warmup, source_role="bootstrap")
    steps_after_warmup = _round_trip_steps(session.runner)

    submitted = 0
    seed = 0x100
    profiler = cProfile.Profile()
    started = time.monotonic()
    profiler.enable()
    # Entropy varies across bytes 3.. so the decoder produces several distinct
    # legal fragments instead of one repeated shape.
    while submitted < args.cases and seed < 0x10000:
        raw = bytes((0, 0, 0, seed & 0xFF, (seed >> 8) & 0xFF, 0x01, 0x06, 0xB0))
        seed += 0x11
        try:
            case, candidate = decoder.decode_candidate(raw, coverage_hints={})
            if case is None:
                continue
            session.submit_case(case)
        except BaseException:
            continue
        submitted += 1
    elapsed = time.monotonic() - started
    profiler.disable()
    steps = _round_trip_steps(session.runner) - steps_after_warmup
    session.finish()

    stream = io.StringIO()
    pstats.Stats(profiler, stream=stream).sort_stats("tottime").print_stats(args.top)
    print(f"cases={submitted} steps={steps} elapsed={elapsed:.3f}s "
          f"=> {elapsed / steps * 1000 if steps else 0:.3f} ms/step (host, incl. RTL reply wait)")
    print(stream.getvalue()[:6000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
