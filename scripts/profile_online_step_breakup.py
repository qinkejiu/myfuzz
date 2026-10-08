#!/usr/bin/env python3
"""Per-step timing breakup for one live Ibex+UART online session (diagnostic).

Answers "where does the ~1.4 s per case actually go": it times the session
construction (RTL prepare), the bootstrap case, and then each case's decode /
submit / checker phases separately, printing p50/p95 per phase.

Read-only with respect to saved runs: it writes its own output directory.

Usage: PYTHONPATH=src python3 scripts/profile_online_step_breakup.py \
          --cache-dir RUNS_CACHE --output NEW_DIR --cases 6 [--json-out PATH]
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, (ROOT / "src").as_posix())

from myfuzz.integration.ibex_uart_online import (  # noqa: E402
    make_ibex_uart_online_bootstrap, make_ibex_uart_online_decoder,
    make_ibex_uart_online_factory)
from myfuzz.scenario.ibex_uart_online import uart_online_advances  # noqa: E402
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker  # noqa: E402
from myfuzz.scenario.batch import BatchSourceEvent  # noqa: E402
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession  # noqa: E402


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return ordered[index]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cases", type=int, default=6)
    parser.add_argument("--seconds", type=float, default=6.0)
    parser.add_argument("--json-out")
    args = parser.parse_args(argv[1:])

    output = Path(args.output)
    if output.exists():
        print(f"output directory must be new: {output}")
        return 3

    timings: dict[str, list[float]] = {}

    def mark(name: str, started: float) -> float:
        now = time.monotonic()
        timings.setdefault(name, []).append(now - started)
        return now

    t0 = time.monotonic()
    bootstrap = make_ibex_uart_online_bootstrap()
    decoder = make_ibex_uart_online_decoder(bootstrap=bootstrap)
    t1 = mark("build_bootstrap_and_decoder", t0)
    factory = make_ibex_uart_online_factory(Path(args.cache_dir))
    runner = factory()
    t2 = mark("factory_and_runner_construct", t1)
    session = ScenarioSession(bootstrap.template, runner,
                             checker=IbexUartOnlineChecker())
    session.declare_instruction_slots("cpu", bootstrap.instruction_start,
                                      bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    mark("session_declare_and_begin", t2)

    warmup = OnlineCase(
        "uart-fixed-warmup", "IP_TO_CPU",
        next(decoder.graph.path_identity(path, direction=direction)
             for direction, path in decoder.runtime_paths
             if direction == "IP_TO_CPU" and path.target == "uart_rx_to_cpu"),
        BatchSourceEvent("uart-fixed-warmup-rx", "uart", "uart_rx_byte", 0x5a, 0, 8),
        uart_online_advances("warmup"))
    started = time.monotonic()
    receipt = session.submit_case(warmup, source_role="bootstrap")
    mark("bootstrap_submit_case", started)
    statuses = {receipt.status: 1}
    events = len(session.runner.events_since(0))

    started = time.monotonic()
    deadline = started + args.seconds
    submitted = 0
    raw_seed = 0
    while submitted < args.cases and time.monotonic() < deadline:
        raw = (raw_seed.to_bytes(8, "little"))
        raw_seed += 1
        step = time.monotonic()
        case, candidate = decoder.decode_candidate(raw, coverage_hints={})
        mark("decode_candidate", step)
        if case is None:
            statuses["input_invalid"] = statuses.get("input_invalid", 0) + 1
            continue
        step = time.monotonic()
        try:
            one = session.submit_case(case)
        except BaseException as error:  # keep the profile running
            statuses[type(error).__name__] = statuses.get(type(error).__name__, 0) + 1
            mark("submit_case_failed", step)
            continue
        mark("submit_case", step)
        statuses[one.status] = statuses.get(one.status, 0) + 1
        submitted += 1
    mark("live_loop_total", started)

    step = time.monotonic()
    session.finish()
    mark("session_finish", step)
    events_after = len(session.runner.events_since(0))

    document = {
        "schema_version": "online_step_breakup_profile.v1",
        "cache_dir": args.cache_dir,
        "output_dir": output.as_posix(),
        "cases_submitted": submitted,
        "statuses": statuses,
        "events_bootstrap": events,
        "events_total": events_after,
        "local_ticks": dict(session.runner.local_ticks),
        "phases": {
            name: {"count": len(values),
                   "total": round(sum(values), 6),
                   "p50": _pct(values, 0.50),
                   "p95": _pct(values, 0.95),
                   "max": max(values)}
            for name, values in sorted(timings.items())},
    }
    text = json.dumps(document, indent=1, sort_keys=True)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8")
    print(f"cases={submitted} statuses={statuses} events={events_after}")
    for name, row in document["phases"].items():
        print(f"  {name:34s} n={row['count']:3d} p50={row['p50']!s:>10.10s} "
              f"p95={row['p95']!s:>10.10s} total={row['total']:.3f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
