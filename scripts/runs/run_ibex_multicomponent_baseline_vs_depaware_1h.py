#!/usr/bin/env python3
"""Run Ibex multi-component baseline vs dependency-aware projection for 1h."""

from __future__ import annotations

import argparse
from pathlib import Path

import run_ibex_baseline_vs_lightweight_plus_1000s as base


base.SCHEMES = [
    {
        "scheme": "baseline_direct_slice",
        "label": "baseline_direct_slice",
        "config": "configs/designs/ibex_multicomponent_ip/baseline_direct_slice/config.coverage_width.json",
        "reuse_out_dir": "runs/designs/ibex_multicomponent_ip_baseline_direct_slice",
        "description": (
            "Ibex + common IP baseline. The same 512 RFuzz input bits are fixed-sliced "
            "directly into the wrapper without dependency projection."
        ),
    },
    {
        "scheme": "depaware_projection",
        "label": "depaware_projection",
        "config": "configs/designs/ibex_multicomponent_ip/depaware_projection/config.coverage_width.json",
        "reuse_out_dir": "runs/designs/ibex_multicomponent_ip_depaware_projection",
        "description": (
            "Ibex + common IP dependency-aware projection. The same 512 RFuzz input bits "
            "are projected through explicit CPU/bus/IP dependency rules before driving the wrapper."
        ),
    },
]


def main() -> int:
    defaults = {
        "--seconds": "3600",
        "--sample-interval": "100",
        "--label": "ibex_multicomponent_baseline_vs_depaware_1h",
        "--exclude-top-bits": "71",
        "--exclude-module-label": "ibex_multicomponent_ip_top",
        "--max-runs": "1000000000",
        "--seed-cycles": "5",
        "--max-cycles": "200",
        "--crash-restarts": "3",
        "--nice": "5",
    }
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    known, remaining = parser.parse_known_args()

    argv: list[str] = ["--repo", str(known.repo)]
    supplied = set()
    for index, item in enumerate(remaining):
        if item.startswith("--"):
            supplied.add(item.split("=", 1)[0])
    for key, value in defaults.items():
        if key not in supplied:
            argv.extend([key, value])
    argv.extend(remaining)

    import sys

    old_argv = sys.argv
    try:
        sys.argv = [old_argv[0], *argv]
        return base.main()
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    raise SystemExit(main())
