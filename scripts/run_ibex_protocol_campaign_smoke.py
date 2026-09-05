#!/usr/bin/env python3
"""Emit deterministic, bounded campaign metrics for local supervisor evidence."""

from __future__ import annotations

import argparse
import json
import time


_METRICS = (
    {"transactions": 1, "protocol": "tl-ul", "component": "ram"},
    {"transactions": 1, "protocol": "apb", "component": "timer"},
    {"transactions": 1, "protocol": "apb", "component": "gpio"},
    {"transactions": 1, "protocol": "axi4-lite", "component": "uart"},
    {"transactions": 1, "protocol": "axi4-lite", "component": "spi"},
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit bounded local Ibex campaign accounting metrics."
    )
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.duration_seconds <= 0:
        raise SystemExit("--duration-seconds must be positive")
    if args.seed < 0 or args.seed > 0xFFFF_FFFF:
        raise SystemExit("--seed must be between 0 and 4294967295")

    for index, metric in enumerate(_METRICS):
        document = dict(metric)
        if index == len(_METRICS) - 1:
            document["coverage"] = f"local.ibex.protocol.seed-{args.seed:08x}"
        print(json.dumps(document, sort_keys=True, separators=(",", ":")), flush=True)

    # Keep the child alive long enough for the same RSS/checkpoint supervisor
    # used by a real campaign to observe it.  The metric set itself is fixed;
    # the seed only names the deterministic local coverage point.
    # Leave headroom for the parent supervisor's polling deadline so a short
    # smoke exits cleanly rather than being classified as a timeout.
    deadline = time.monotonic() + max(0.05, float(args.duration_seconds) - 0.25)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 0
        time.sleep(min(0.1, remaining))


if __name__ == "__main__":
    raise SystemExit(main())
