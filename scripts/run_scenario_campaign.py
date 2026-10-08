#!/usr/bin/env python3
"""Run or plan the strict 18-cell persistent scenario G4 campaign.

An executable provider is supplied as ``module:attribute``. Its object must
implement the CampaignProvider search/replay methods. The built-in
``myfuzz.integration.scenario_campaign:IbexTwoGpioBoundProvider`` and
``myfuzz.integration.cva6_scenario_campaign:Cva6TwoGpioBoundProvider`` run
three search strategies through Rust and real local RTL processes. Each
provider requires bound and independent-baseline manifests. Without a
provider, all cells are blocked.
"""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if ROOT.as_posix() not in sys.path:
    sys.path.insert(0, ROOT.as_posix())
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.scenario_campaign import (  # noqa: E402
    CampaignConfig, run_scenario_campaign,
)


def _load_provider(reference: str):
    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise ValueError("provider must be module:attribute")
    provider = getattr(importlib.import_module(module_name), attribute_name)
    if isinstance(provider, type):
        provider = provider()
    if not callable(getattr(provider, "search", None)) or not callable(
            getattr(provider, "replay", None)):
        raise ValueError("provider needs search and replay methods")
    return provider


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True, type=Path,
                        help="real-bound scenario manifest")
    parser.add_argument("--baseline-manifest", type=Path,
                        help="separate independent-drive diagnostic manifest; omitted arms stay blocked")
    parser.add_argument("--seconds", type=float, default=60.0,
                        help="effective search seconds requested per cell")
    parser.add_argument("--seed", type=int, default=20260927,
                        help="first of three fixed integer seed identifiers")
    parser.add_argument("--output", required=True, type=Path,
                        help="new campaign output directory")
    parser.add_argument("--provider", help="executable CampaignProvider as module:attribute")


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        if not args.manifest.is_file():
            raise ValueError("bound scenario manifest file must exist")
        if args.baseline_manifest is not None and not args.baseline_manifest.is_file():
            raise ValueError("independent baseline manifest file must exist")
        baseline_manifest = (args.baseline_manifest or
                             args.manifest.with_name("independent-drive-unavailable.json"))
        config = CampaignConfig(args.manifest.resolve(),
                                baseline_manifest.resolve(),
                                args.seconds,
                                (args.seed, args.seed + 1, args.seed + 2))
        provider = _load_provider(args.provider) if args.provider else None
        report = run_scenario_campaign(config, args.output, provider=provider)
    except (ValueError, ImportError, AttributeError, OSError) as exc:
        print(f"scenario-campaign-error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "gate_status": report["gate_status"],
        "cells": len(report["cells"]),
        "effective_search_seconds": report["effective_search_seconds"],
        "report": str(Path(args.output).absolute() / "campaign_report.json"),
    }, sort_keys=True))
    return 0 if report["gate_status"] == "complete" else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
