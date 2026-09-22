#!/usr/bin/env python3
"""Build the descriptive three-arm SoC campaign comparison report."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.integration.soc_comparison import compare_soc_campaign_arms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direct", required=True, type=Path,
                        help="direct-input campaign report.json")
    parser.add_argument("--constrained", required=True, type=Path,
                        help="constrained-baseline campaign report.json")
    parser.add_argument("--repair", required=True, type=Path,
                        help="dependency-repair campaign report.json")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    document = compare_soc_campaign_arms({
        "direct_input": args.direct,
        "constrained_baseline": args.constrained,
        "dependency_repair": args.repair,
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, ensure_ascii=True, sort_keys=True,
                                      indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
