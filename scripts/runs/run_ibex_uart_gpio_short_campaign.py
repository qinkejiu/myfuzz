#!/usr/bin/env python3
"""Run varied, continuous Ibex + OpenTitan UART + GPIO real RTL cases.

Example: PYTHONPATH=src:. python3 scripts/runs/run_ibex_uart_gpio_short_campaign.py \
    --seconds 600 --output /tmp/ibex-uart-gpio-10min
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import random
import sys
import time

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import GenomeCodec, ScenarioGenome
from myfuzz.scenario.ibex_uart_gpio_assertions import check_ibex_uart_gpio_chain
from myfuzz.scenario.uart_gpio_example import make_ibex_uart_rx_gpio_runner


ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "configs/scenario/ibex_uart_rx_gpio_two_rounds.json"


def mutate_frames(seed: ScenarioGenome, *, index: int,
                  rng: random.Random) -> tuple[ScenarioGenome, tuple[int, int]]:
    """Alter only UART RX source bits; bound IRQ and CPU data remain untouched."""
    if index == 0:
        values = (0xa5, 0x3c)
    else:
        values = (rng.randrange(256), rng.randrange(256))
    actions = []
    for action in seed.actions:
        frame, bit = (int(part) for part in action.action_id.split("-")[1::2])
        if (action.component, action.port, frame in (1, 2), 0 <= bit <= 9) != (
                "uart", "uart_rx", True, True):
            raise ValueError("unexpected UART RX seed action")
        level = (0 if bit == 0 else 1 if bit == 9
                 else (values[frame - 1] >> (bit - 1)) & 1)
        actions.append(replace(action, value=level))
    return replace(seed, testcase_id=f"ibex-uart-gpio-{index:04d}",
                   actions=tuple(actions)), values


def run(*, seconds: float, output: Path, random_seed: int,
        max_cases: int | None = None) -> dict:
    if seconds <= 0 or max_cases is not None and max_cases <= 0:
        raise ValueError("seconds and max_cases must be positive")
    if output.exists():
        raise ValueError("output directory must be new")
    output.mkdir(parents=True)
    seed = GenomeCodec.decode(SEED.read_bytes())
    rng = random.Random(random_seed)
    started = time.monotonic()
    cases: list[dict] = []
    seen_inputs: set[tuple[int, int]] = set()
    index = 0
    try:
        while index == 0 or (time.monotonic() - started < seconds
                             and (max_cases is None or index < max_cases)):
            # Avoid duplicate source pairs within a normal ten-minute run.
            for _ in range(65536):
                genome, values = mutate_frames(seed, index=index, rng=rng)
                if values not in seen_inputs:
                    break
            else:
                raise RuntimeError("UART RX input pair space exhausted")
            seen_inputs.add(values)
            case_dir = output / f"case-{index:04d}"
            report: dict = {"case": index, "uart_rx_bytes": list(values),
                            "genome_sha256": None, "status": "not_started",
                            "assertion_findings": [], "replay_matches": None,
                            "failure_class": None, "local_ticks": {},
                            "coverage": {}}
            try:
                trace = save_evidence_bundle(
                    genome, make_ibex_uart_rx_gpio_runner, case_dir,
                    gpio_check_devices=("gpio",))
                report["genome_sha256"] = trace.genome_sha256
                report["status"] = trace.status
                report["local_ticks"] = trace.local_ticks
                check = check_ibex_uart_gpio_chain(trace.events, values)
                report["assertion_findings"] = check["findings"]
                report["coverage"] = {
                    "closed_rounds": check["closed_rounds"],
                    "cpu_irq_taken": sum(e.get("component") == "cpu" and
                                         e.get("outputs", {}).get("irq_taken_pre") == 1
                                         for e in trace.events),
                    "uart_fifo_reads": sum(e.get("kind") == "mmio_delivery" and
                                           e.get("device_id") == "uart" and
                                           e.get("offset") == 0x18 and
                                           e.get("write") is False for e in trace.events),
                    "gpio_direct_out_writes": sum(e.get("kind") == "mmio_delivery" and
                                                  e.get("device_id") == "gpio" and
                                                  e.get("offset") == 0x14 and
                                                  e.get("write") is True
                                                  for e in trace.events),
                }
                replay = replay_evidence_bundle(
                    case_dir, make_ibex_uart_rx_gpio_runner)
                report["replay_matches"] = replay.matches
                if trace.status != "complete":
                    report["failure_class"] = "scenario_incomplete"
                elif check["findings"]:
                    report["failure_class"] = "chain_assertion"
                elif not replay.matches:
                    report["failure_class"] = "replay_mismatch"
                else:
                    report["failure_class"] = None
            except Exception as exc:
                report["status"] = "execution_exception"
                report["failure_class"] = type(exc).__name__
                report["error"] = str(exc)
            cases.append(report)
            (output / f"case-{index:04d}-report.json").write_text(
                json.dumps(report, sort_keys=True, indent=2) + "\n")
            print(json.dumps({"case": index, "inputs": values,
                              "status": report["status"],
                              "findings": report["assertion_findings"],
                              "failure_class": report["failure_class"],
                              "replay_matches": report["replay_matches"],
                              "local_ticks": report["local_ticks"]}), flush=True)
            index += 1
    finally:
        elapsed = time.monotonic() - started
        summary = {"requested_seconds": seconds, "elapsed_seconds": elapsed,
                   "testcases": len(cases), "unique_inputs": len(seen_inputs),
                   "complete": sum(case["status"] == "complete" for case in cases),
                   "assertion_findings": sum(len(case["assertion_findings"])
                                             for case in cases),
                   "replay_matches": sum(case["replay_matches"] is True
                                         for case in cases),
                   "failure_classes": {}, "cases": cases}
        for case in cases:
            name = case["failure_class"]
            if name is not None:
                summary["failure_classes"][name] = (
                    summary["failure_classes"].get(name, 0) + 1)
        (output / "summary.json").write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261005)
    parser.add_argument("--max-cases", type=int)
    args = parser.parse_args()
    summary = run(seconds=args.seconds, output=args.output,
                  random_seed=args.seed, max_cases=args.max_cases)
    print(json.dumps({key: value for key, value in summary.items() if key != "cases"},
                     sort_keys=True), flush=True)
    return 1 if summary["failure_classes"] else 0


if __name__ == "__main__":
    sys.exit(main())
