#!/usr/bin/env python3
"""Run a data-driven scenario descriptor using its admitted flow backend.

F1-F4 use the shared runtime; F5/F6 reuse their standalone executors,
component bindings, saved evidence and fresh replay.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.local_harness.build import harness_validation_scope, host_source_discovery_scope
from myfuzz.local_harness.session import record_local_commands
from myfuzz.runtime.generic_campaign import (GenericScenarioRefused,
                                             load_descriptor, run_descriptor)


def load_external_records(path: Path) -> list[str]:
    """Load a bounded, ordered corpus; flow-specific validation stays in the runtime."""
    try:
        with path.open('rb') as source:
            raw = source.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('file-too-large')
        records = json.loads(raw.decode('utf-8'))
    except (OSError, UnicodeError, ValueError) as error:
        raise GenericScenarioRefused('generic-scenario-records-file-invalid', '/records_file',
                                     {'reason': type(error).__name__}) from error
    if type(records) is not list or not records or any(type(item) is not str for item in records):
        raise GenericScenarioRefused('generic-scenario-records-file-invalid', '/records_file',
                                     {'reason': 'nonempty-string-array-required'})
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--flow", required=True, choices=("F2", "F4", "F5", "F6", "mixed"))
    parser.add_argument("--mode", required=True, choices=("original", "fresh"))
    parser.add_argument("--case", type=Path, required=True,
                        help="evidence root for this campaign")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--record-limit", type=int, default=0)
    parser.add_argument("--rounds", type=int, default=None,
                        help="complete local advance rounds per case (default: descriptor)")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--record", action="append", dest="records",
                        help="ordered case as FLOW:HEX; repeat for each case")
    inputs.add_argument("--records-file", type=Path,
                        help="JSON array of ordered FLOW:HEX records from an input corpus")
    parser.add_argument("--record-local-commands", action="store_true",
                        help="record bounded original and fresh component commands for coverage replay")
    parser.add_argument("--execution-mode", choices=("develop", "search", "acceptance"),
                        default=None,
                        help="search skips the default within-invocation replay; fresh still replays")
    args = parser.parse_args(argv)

    try:
        descriptor = load_descriptor(args.descriptor, base_dir=ROOT)
        sequence = load_external_records(args.records_file) if args.records_file else args.records
        recording = record_local_commands() if args.record_local_commands else nullcontext(None)
        with host_source_discovery_scope(reuse_nested=True), harness_validation_scope(), recording as trace:
            summary = run_descriptor(
                descriptor, flow=args.flow, mode=args.mode,
                case_root=args.case, base_dir=ROOT,
                cache_dir=args.cache, record_limit=args.record_limit,
                sequence=sequence, rounds=args.rounds, command_trace=trace,
                execution_mode=args.execution_mode)
    except GenericScenarioRefused as error:
        print(json.dumps({"status": "refused", "code": error.code,
                          "pointer": error.pointer, "detail": error.detail},
                         sort_keys=True))
        return 2
    print(json.dumps({"scenario": summary["scenario"], "flow": summary["flow"],
                      "mode": summary["mode"], "cases": summary["case_count"],
                      "backend": summary.get("backend"),
                      "replay_scope": summary.get("replay_scope"),
                      "evidence_dir": summary.get("evidence_dir"),
                      "replay_matches": summary["replay_matches"],
                      "wall_seconds": summary["wall_seconds"],
                      "rounds_per_case": summary["rounds_per_case"],
                      "plan": summary["plan_identity_sha256"]}, sort_keys=True))
    # An original run without the legacy within-invocation replay reports
    # replay_matches=None, which is not a failure.  A fresh run must match.
    matches = summary.get("replay_matches")
    if args.mode == "fresh":
        return 0 if matches is True else 1
    return 0 if matches is not False else 1


if __name__ == "__main__":
    raise SystemExit(main())
