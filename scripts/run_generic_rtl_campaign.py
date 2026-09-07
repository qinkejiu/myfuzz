#!/usr/bin/env python3
"""Randomly select native protocol fixtures and supervise real RTL execution."""
import argparse
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from myfuzz.integration.generic_rtl_campaign import run_demo_campaign

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args()
    result = run_demo_campaign(args.output.resolve(), seed=secrets.randbits(31) if args.seed is None else args.seed, seconds=args.seconds, count=args.count)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result.get("status") == "finished" else 2)
