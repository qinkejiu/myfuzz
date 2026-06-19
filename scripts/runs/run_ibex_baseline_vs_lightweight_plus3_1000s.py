#!/usr/bin/env python3
"""Run Ibex baseline vs the input-bit constrained lightweight-plus3 harness."""

from __future__ import annotations

import run_ibex_baseline_vs_lightweight_plus_1000s as base


base.SCHEMES = [
    {
        "scheme": "scheme1",
        "label": "scheme1_baseline",
        "config": "configs/designs/ibex/config.json",
        "reuse_out_dir": "runs/designs/ibex",
        "description": "Top-level ibex_core baseline.",
    },
    {
        "scheme": "scheme4p3",
        "label": "scheme4_plus3",
        "config": "configs/designs/ibex_lightweight_plus3/config.json",
        "reuse_out_dir": "runs/designs/ibex_lightweight_plus3",
        "description": (
            "Top-level ibex_core harness where the same 395 RFuzz input bits are "
            "projected into scenario, short-program, bus-latency, data, IRQ, debug, "
            "and error constraints."
        ),
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
