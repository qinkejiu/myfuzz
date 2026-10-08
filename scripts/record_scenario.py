#!/usr/bin/env python3
"""Record one persistent testcase as a replayable evidence bundle."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import GenomeCodec


def _parse_values(raw: str) -> tuple[int, ...]:
    try:
        values = tuple(int(item.strip(), 0) for item in raw.split(","))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integer values") from exc
    if len(values) < 2:
        raise argparse.ArgumentTypeError("at least two values are required")
    return values


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--genome", required=True, type=Path)
    parser.add_argument("--factory", required=True,
                        help="importable module:function returning a fresh ScenarioRunner")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gpio-direct-out", action="append", default=[],
                        metavar="DEVICE", help="check a real OpenTitan GPIO output")
    parser.add_argument("--coverage-targets", type=Path,
                        help="JSON array of observed RTL output predicates")
    parser.add_argument("--closed-chain-value", type=lambda raw: int(raw, 0),
                        help="check two or more real CPU→GPIO A→GPIO B→CPU rounds")
    parser.add_argument("--closed-chain-rounds", type=int, default=2,
                        help="minimum closed rounds required by the chain checker")
    parser.add_argument("--reverse-chain-values", type=_parse_values,
                        help="comma-separated expected GPIO B external values")
    parser.add_argument("--budget", type=Path,
                        help="explicit JSON ResourceBudget enforced for this testcase")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    module_name, separator, function_name = args.factory.partition(":")
    if not separator or not module_name or not function_name:
        parser.error("--factory must have module:function form")
    factory = getattr(importlib.import_module(module_name), function_name)
    if not callable(factory):
        parser.error("--factory must resolve to a callable")
    genome = GenomeCodec.decode(args.genome.read_bytes())
    targets = tuple(CoverageTarget(**item) for item in json.loads(
        args.coverage_targets.read_text(encoding="utf-8"))) \
        if args.coverage_targets else ()
    budget = (ResourceBudget.from_document(json.loads(
        args.budget.read_text(encoding="utf-8"))) if args.budget else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    trace = save_evidence_bundle(genome, factory, args.output,
                                 gpio_check_devices=tuple(args.gpio_direct_out),
                                 coverage_targets=targets,
                                 budget=budget,
                                 closed_chain_expected_value=args.closed_chain_value,
                                 closed_chain_min_rounds=args.closed_chain_rounds,
                                 reverse_chain_expected_values=args.reverse_chain_values)
    report = {"status": trace.status,
              "semantic_sha256": trace.semantic_sha256,
              "manifest_sha256": trace.manifest_sha256,
              "local_ticks": trace.local_ticks}
    if args.closed_chain_value is not None or args.reverse_chain_values is not None:
        checks = [json.loads(line) for line in
                  (args.output / "checks.jsonl").read_text(encoding="utf-8").splitlines()]
        chain_checks = [item for item in checks if item["checker"] in (
            "cpu_gpio_closed_chain.v1", "gpio_cpu_gpio_closed_chain.v1")]
        report["closed_chains_complete"] = bool(chain_checks) and all(
            item["complete"] for item in chain_checks)
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    return 0 if report.get("closed_chains_complete", True) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
