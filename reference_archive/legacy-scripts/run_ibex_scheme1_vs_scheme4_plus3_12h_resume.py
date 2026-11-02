#!/usr/bin/env python3
"""Run Ibex scheme1 vs scheme4_plus3 with resumable slice-based accounting."""

from __future__ import annotations

import sys

import run_ibex_scheme1_vs_scheme4_plus2_10h_resume as base


base.SCHEMES = [
    {
        "scheme": "scheme1",
        "label": "scheme1_baseline",
        "config": "configs/designs/ibex/config.json",
        "reuse_out_dir": "runs/designs/ibex",
        "description": "Top-level ibex_core baseline with fully random top-level inputs.",
    },
    {
        "scheme": "scheme4p3",
        "label": "scheme4_plus3",
        "config": "configs/designs/ibex_lightweight_plus3/config.json",
        "reuse_out_dir": "runs/designs/ibex_lightweight_plus3",
        "description": (
            "Top-level ibex_core scheme4_plus3. The same 395 RFuzz input bits are "
            "projected into scenario, short-program, register-bias, memory, bus-latency, "
            "IRQ, debug, and error constraints."
        ),
    },
]


def main() -> int:
    if "--label" not in sys.argv:
        sys.argv.extend(["--label", "ibex_scheme1_vs_scheme4_plus3_resume"])
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
