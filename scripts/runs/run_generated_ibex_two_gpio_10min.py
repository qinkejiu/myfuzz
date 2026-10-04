#!/usr/bin/env python3
"""Timed source-aware RTL campaign for generated Ibex and two PULP GPIOs.

The mutable source is a legal odd byte in the Ibex program. Ibex must issue
the MMIO write; GPIO A, GPIO B and Ibex ISR must produce all later facts.
This pilot uses deterministic source-aware mutation, not RFuzz feedback.

PYTHONPATH=src:. python3 scripts/runs/run_generated_ibex_two_gpio_10min.py \
    --seconds 600 --output /tmp/ibex-two-gpio-10min
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics
import sys
import time

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource, SourceBinding,
                                        SourceBindings)
from myfuzz.scenario.checker import check_pulp_gpio_irq_chain
from tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real import (
    genome, make_factory)


def _case_counts(cases: list[dict]) -> dict[str, int]:
    """Keep scheduler, causal checker, and replay accounting separate."""
    scheduler_complete = sum(case.get("status") == "complete" for case in cases)
    return {
        "complete": scheduler_complete,  # legacy field
        "scheduler_complete": scheduler_complete,
        "chain_complete": sum(case.get("coverage", {}).get("chain_complete") is True
                              for case in cases),
        "replay_attempted": sum(case.get("replay_attempted") is True
                                for case in cases),
        "replay_skipped": sum(case.get("replay_skipped") is True for case in cases),
        "replay_matches": sum(case.get("replay_matches") is True for case in cases),
        "replay_errors": sum(case.get("replay_error") is not None for case in cases),
    }


def _mark_replay_error(report: dict, exc: Exception) -> None:
    report["replay_error"] = {"type": type(exc).__name__, "message": str(exc)}
    report["failure_class"] = "replay_error"


def run(*, seconds: float, output: Path, seed: int = 20261005,
        max_cases: int | None = None, cache_dir: Path | None = None) -> dict:
    if seconds <= 0 or max_cases is not None and max_cases <= 0:
        raise ValueError("seconds and max_cases must be positive")
    if output.exists():
        raise ValueError("output directory must be new")
    output.mkdir(parents=True)
    wall_start = time.monotonic()
    factory, _instances = make_factory(cache_dir or output / "compile-cache")
    first_boot = next(image for image in genome(1).initial_images
                      if image.component == "cpu" and image.image_id == "boot")
    last_boot = next(image for image in genome(0xff).initial_images
                     if image.component == "cpu" and image.image_id == "boot")
    changed = [bit for bit in range(len(first_boot.data) * 8)
               if (first_boot.data[bit // 8] ^ last_boot.data[bit // 8])
               & (1 << (bit % 8))]
    if (len(changed) != 7 or changed != list(range(changed[0], changed[0] + 7))
            or changed[0] % 32 != 21 or first_boot.address != 0x10080):
        raise ValueError("CPU GPIO immediate source no longer matches pinned genome")
    source_bit_offset = changed[0]
    # Build all three native executables once before counting search time.
    warm_runner = factory()
    graph = DependencyGraph(
        sources=(FuzzableSource(
            "cpu.program.gpio_a_padout_immediate", "cpu", "boot",
            source_bit_offset, 7,
            ("CPU_TO_IP_TO_CPU",), "memory_image"),),
        rules=(
            DependencyRule("cpu.gpio_a.mmio_write", ("cpu.program.gpio_a_padout_immediate",),
                           "DATA_BINDING"),
            DependencyRule("gpio_a.real_output", ("cpu.gpio_a.mmio_write",),
                           "PERSISTENT_STATE_RULE"),
            DependencyRule("gpio_b.bound_input", ("gpio_a.real_output",), "DATA_BINDING"),
            DependencyRule("gpio_b.real_irq", ("gpio_b.bound_input",), "EVENT_ORDER"),
            DependencyRule("cpu.isr", ("gpio_b.real_irq",), "EVENT_ORDER"),
            DependencyRule("cpu.ram_result", ("cpu.isr",), "PERSISTENT_STATE_RULE"),
        ))
    paths = graph.paths_to("cpu.ram_result", direction="CPU_TO_IP_TO_CPU")
    if len(paths) != 1:
        raise ValueError("generated Ibex GPIO dependency path is ambiguous")
    SourceBindings((SourceBinding(
        "cpu.program.gpio_a_padout_immediate", "memory_image", "cpu", "boot",
        source_bit_offset, 7, "initial_image:cpu:boot", 0x10080),)).validate(
            graph, warm_runner.ownership, (genome(1),))
    try:
        warm_runner.ownership.mutation_source(
            "gpio_b", "gpio_in", 0, 8, direction="CPU_TO_IP_TO_CPU")
    except ValueError as exc:
        if "bound input cannot be mutated" not in str(exc):
            raise
    else:
        raise AssertionError("GPIO B bound input became fuzzable")
    for session in warm_runner.sessions.values():
        prepare = getattr(session, "prepare_local", None)
        if callable(prepare):
            prepare()
    warmup_seconds = time.monotonic() - wall_start
    search_start = time.monotonic()
    cases: list[dict] = []
    rng = random.Random(seed)
    priority_values = (1, 3, 0x7f, 0x81, 0xff, 5, 0x11, 0x55, 0x7d, 0x83)
    source_uses: dict[int, int] = {}
    covered_values: set[int] = set()
    first_coverage: dict[str, int] = {}
    try:
        while not cases or (time.monotonic() - search_start < seconds
                            and (max_cases is None or len(cases) < max_cases)):
            index = len(cases)
            if index < len(priority_values):
                value, energy = priority_values[index], 100
            else:
                candidates = tuple(range(1, 256, 2))
                weights = tuple(100 if candidate not in covered_values
                                and candidate not in source_uses else
                                20 if candidate not in covered_values else 1
                                for candidate in candidates)
                value = rng.choices(candidates, weights=weights, k=1)[0]
                energy = weights[candidates.index(value)]
            source_uses[value] = source_uses.get(value, 0) + 1
            case = genome(value)
            bundle = output / f"case-{index:04d}"
            started = time.monotonic()
            report = {"index": index, "source": "cpu.program.gpio_a_padout_immediate",
                      "source_value": value, "mutation_direction": "CPU_TO_IP_TO_CPU",
                      "mutation_energy": energy,
                      "dependency_target": paths[0].target,
                      "dependency_sources": list(paths[0].source_ids),
                      "status": "not_started", "assertion_findings": [],
                      "failure_class": None, "replay_matches": None,
                      "replay_attempted": False, "replay_skipped": False,
                      "replay_error": None, "local_ticks": {}, "coverage": {},
                      "record_seconds": None, "replay_seconds": None,
                      "case_seconds": 0.0}
            phase = "record"
            try:
                trace = save_evidence_bundle(case, factory, bundle)
                report["record_seconds"] = time.monotonic() - started
                report["status"] = trace.status
                report["local_ticks"] = trace.local_ticks
                report["genome_sha256"] = trace.genome_sha256
                check = check_pulp_gpio_irq_chain(trace.events, expected_value=value)
                report["path_incomplete"] = check["path_incomplete"]
                report["dut_violations"] = check["dut_violations"]
                report["assertion_findings"] = (check["path_incomplete"]
                                                + check["dut_violations"])
                report["coverage"] = {
                    "chain_complete": check["complete"],
                    "endpoint_event_id": check["endpoint_event_id"],
                    "real_b_irq_events": sum(e.get("kind") == "source_start"
                                             and e.get("source") == ("gpio_b", "irq")
                                             for e in trace.events),
                    "cpu_isr_fetches": sum(e.get("component") == "cpu"
                                           and e.get("outputs", {}).get("instr_req_accepted") == 1
                                           and e.get("outputs", {}).get("instr_addr") == 0x1012c
                                           for e in trace.events),
                }
                real_ram_values = {e.get("value") for e in trace.events
                                   if e.get("kind") == "memory_write"
                                   and e.get("component") == "cpu"
                                   and e.get("address") == 0x20000
                                   and type(e.get("value")) is int}
                report["coverage"]["real_ram_values"] = sorted(real_ram_values)
                new_coverage = []
                for observed in real_ram_values:
                    key = f"cpu.ram_result:{observed:#x}"
                    if key not in first_coverage:
                        new_coverage.append(key)
                    covered_values.add(observed)
                    first_coverage.setdefault(key, index)
                stage_facts = {
                    "gpio_a_real_output": any(
                        e.get("component") == "gpio_a"
                        and e.get("outputs", {}).get("gpio_out") == value
                        for e in trace.events),
                    "gpio_b_bound_input": any(
                        e.get("component") == "gpio_b"
                        and e.get("inputs", {}).get("gpio_in") == value
                        for e in trace.events),
                    "gpio_b_real_irq": report["coverage"]["real_b_irq_events"] > 0,
                    "cpu_isr": report["coverage"]["cpu_isr_fetches"] > 0,
                    "cpu_ram_result": value in real_ram_values,
                    "complete_causal_chain": check["complete"],
                }
                report["coverage"]["observed_facts"] = stage_facts
                for stage, observed in stage_facts.items():
                    if not observed:
                        continue
                    key = f"chain_fact:{stage}"
                    if key not in first_coverage:
                        new_coverage.append(key)
                    first_coverage.setdefault(key, index)
                report["new_semantic_coverage"] = new_coverage
                new_value = any(item.startswith("cpu.ram_result:")
                                for item in new_coverage)
                first_complete = "chain_fact:complete_causal_chain" in new_coverage
                failure = bool(report["assertion_findings"] or
                               trace.status != "complete")
                sampled_value = new_value and len(covered_values) % 5 == 0
                replay_required = first_complete or sampled_value or failure
                report["replay_reason"] = (
                    "failure" if failure else "first_complete_chain" if first_complete
                    else "every_fifth_new_value" if sampled_value else None)
                if replay_required:
                    replay_start = time.monotonic()
                    report["replay_attempted"] = True
                    phase = "replay"
                    replay = replay_evidence_bundle(bundle, factory)
                    phase = "classify"
                    report["replay_seconds"] = time.monotonic() - replay_start
                    report["replay_matches"] = replay.matches
                else:
                    report["replay_skipped"] = True
                if trace.status != "complete":
                    report["failure_class"] = "scenario_incomplete"
                elif check["dut_violations"]:
                    report["failure_class"] = "dut_violation_candidate"
                elif check["path_incomplete"]:
                    report["failure_class"] = "path_incomplete"
                elif report["replay_matches"] is False:
                    report["failure_class"] = "replay_mismatch"
            except Exception as exc:
                if phase == "replay":
                    report["replay_seconds"] = time.monotonic() - replay_start
                    _mark_replay_error(report, exc)
                else:
                    report["status"] = "execution_exception"
                    report["failure_class"] = type(exc).__name__
                    report["error"] = str(exc)
            report["case_seconds"] = time.monotonic() - started
            cases.append(report)
            (output / f"case-{index:04d}-report.json").write_text(
                json.dumps(report, sort_keys=True, indent=2) + "\n")
            print(json.dumps({"index": index, "source_value": value,
                              "status": report["status"],
                              "findings": report["assertion_findings"],
                              "failure_class": report["failure_class"],
                              "replay_matches": report["replay_matches"],
                              "case_seconds": report["case_seconds"]}), flush=True)
    finally:
        search_seconds = time.monotonic() - search_start
        classes: dict[str, int] = {}
        for case in cases:
            failure = case["failure_class"]
            if failure:
                classes[failure] = classes.get(failure, 0) + 1
        summary = {"campaign_kind": "source_aware_seed_schedule_not_rfuzz_coverage_guided",
                   "coverage_kind": "semantic_dataflow_values_and_chain_stages",
                   "dependency_path": {"target": paths[0].target,
                                       "sources": list(paths[0].source_ids)},
                   "requested_search_seconds": seconds,
                   "warmup_seconds": warmup_seconds,
                   "effective_search_seconds": search_seconds,
                   "total_wall_seconds": time.monotonic() - wall_start,
                   "testcases": len(cases),
                   "unique_source_values": len({case["source_value"] for case in cases}),
                   "assertion_findings": sum(len(case["assertion_findings"])
                                             for case in cases),
                   **_case_counts(cases),
                   "replay_policy": "first_complete_chain_every_fifth_new_value_or_failure",
                   "failure_classes": classes,
                   "semantic_dataflow_values": sorted(covered_values),
                   "first_coverage_case": first_coverage,
                   "warm_case_seconds": [case["case_seconds"] for case in cases],
                   "mean_warm_case_seconds": statistics.mean(
                       case["case_seconds"] for case in cases) if cases else None,
                   "mean_record_seconds": statistics.mean(
                       case["record_seconds"] for case in cases
                       if case["record_seconds"] is not None)
                       if any(case["record_seconds"] is not None for case in cases)
                       else None,
                   "mean_replay_seconds": statistics.mean(
                       case["replay_seconds"] for case in cases
                       if case["replay_seconds"] is not None)
                       if any(case["replay_seconds"] is not None for case in cases)
                       else None,
                   "cases": cases}
        (output / "summary.json").write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261005)
    parser.add_argument("--max-cases", type=int)
    parser.add_argument("--cache-dir", type=Path,
                        help="reuse compiled RTL artifacts from a prior run")
    args = parser.parse_args()
    summary = run(seconds=args.seconds, output=args.output,
                  seed=args.seed, max_cases=args.max_cases,
                  cache_dir=args.cache_dir)
    print(json.dumps({key: val for key, val in summary.items() if key != "cases"},
                     sort_keys=True), flush=True)
    return 1 if summary["failure_classes"] else 0


if __name__ == "__main__":
    sys.exit(main())
