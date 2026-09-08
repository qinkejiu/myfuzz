#!/usr/bin/env python3
"""Run three source-backed CPU/peripheral RFuzz campaigns and rebuild replays."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from myfuzz.integration.real_cpu_campaign import run_campaigns

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--seed", type=int, default=20260908)
    args = parser.parse_args()
    print(json.dumps(run_campaigns(ROOT, args.output, args.config, args.client,
                                   seconds=args.seconds, seed=args.seed), indent=2))
