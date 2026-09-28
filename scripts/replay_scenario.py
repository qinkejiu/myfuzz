#!/usr/bin/env python3
"""Replay a saved scenario evidence bundle with fresh local harnesses."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from myfuzz.scenario.evidence import replay_evidence_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--factory", required=True,
                        help="importable module:function returning a fresh ScenarioRunner")
    parser.add_argument("--rebuild", action="store_true",
                        help="start fresh local harnesses using the supplied factory")
    parser.add_argument("--compare-trace", action="store_true",
                        help="compare every saved semantic event")
    parser.add_argument("--allow-factory-mismatch", action="store_true",
                        help="diagnostic replay with modified factory code")
    parser.add_argument("--resume", type=Path,
                        help="reserved; RTL checkpoint resume is unsupported")
    args = parser.parse_args()
    if args.resume is not None:
        parser.error("unsupported_checkpoint_resume: replay must start fresh RTL")
    module_name, separator, function_name = args.factory.partition(":")
    if not separator or not module_name or not function_name:
        parser.error("--factory must have module:function form")
    module = importlib.import_module(module_name)
    factory = getattr(module, function_name)
    if not callable(factory):
        parser.error("--factory must resolve to a callable")
    comparison = replay_evidence_bundle(
        args.evidence, factory,
        allow_factory_mismatch=args.allow_factory_mismatch)
    print(json.dumps({"matches": comparison.matches,
                      "verification_scope": comparison.verification_scope,
                      "first_difference": comparison.first_difference,
                      "difference_context": comparison.difference_context},
                     sort_keys=True, ensure_ascii=False))
    return 0 if comparison.matches else 1


if __name__ == "__main__":
    raise SystemExit(main())
