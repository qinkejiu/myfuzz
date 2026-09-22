#!/usr/bin/env python3
"""Build one SoC and execute the three-arm input-projection campaign.

The three arms - ``direct_input``, ``constrained_baseline`` and
``dependency_repair`` - share one build (same SoC, source closure, coverage
instrumentation, budget and seed) and differ only in the input projection they
apply to the same seeded corpus.  Each arm's corpus, coverage, projection and
repair counters and its replay verification are written under the output
directory, together with the executed comparison.

Example (from the repository root):

    MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 scripts/run_soc_campaign_arms.py \\
        --config configs/soc/arms-example.json \\
        --output runs/soc-arms/example

Exit codes: 0 all three arms executed and compared, 1 the arms could not run,
2 the report was produced but an arm did not complete.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.soc_comparison import (  # noqa: E402
    SocComparisonError,
    execute_soc_campaign_arms,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, type=Path,
                        help="campaign config JSON (composition_request + component_profiles)")
    parser.add_argument("--output", required=True, type=Path,
                        help="new output directory; the report is written here")
    parser.add_argument("--timeout-seconds", type=float, default=60.0,
                        help="per-sample RTL simulator deadline")
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"config-unreadable: {error}", file=sys.stderr)
        return 1
    if not isinstance(config, dict):
        print("config-invalid: mapping-required", file=sys.stderr)
        return 1
    try:
        document = execute_soc_campaign_arms(config, args.output, root=ROOT,
                                             timeout_seconds=args.timeout_seconds)
    except SocComparisonError as error:
        print(f"arms-failed: {error}", file=sys.stderr)
        return 1
    summary = {
        "schema_version": document["schema_version"],
        "config_id": document["config_id"],
        "drive_profile": document["drive_profile"],
        "shared": document["shared"],
        "arms": {
            arm: {
                "status": report["status"],
                "accepted_entries": report["input_projection"]["accepted_entries"],
                "rejected_entries": report["input_projection"]["rejected_entries"],
                "anomaly_entries": report["input_projection"]["anomaly_entries"],
                "repair_counts": report["input_projection"]["repair_counts"],
                "coverage_bits_hit": report["rtl_execution"]["coverage_bits_hit"],
                "corpus_entries": report["corpus"]["entries"],
                "replay": report["replay"]["status"],
            }
            for arm, report in ((name, json.loads(
                (Path(args.output) / path).read_text(encoding="utf-8")))
                for name, path in document["arm_reports"].items())
        },
        "comparison_status": document["comparison"]["comparison"]["status"],
        "not_verified": document["not_verified"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    incomplete = [arm for arm, report in summary["arms"].items()
                  if report["status"] != "completed"]
    return 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
