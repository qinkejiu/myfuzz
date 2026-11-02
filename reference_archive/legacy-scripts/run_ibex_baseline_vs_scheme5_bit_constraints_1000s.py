#!/usr/bin/env python3
"""Run Ibex baseline vs scheme5 bit-only lightweight constraints."""

from __future__ import annotations

import run_ibex_baseline_vs_lightweight_plus_1000s as base


base.SCHEMES = [
    {
        "scheme": "scheme1",
        "label": "scheme1_baseline",
        "config": "configs/designs/ibex/config.json",
        "reuse_out_dir": "runs/designs/ibex",
        "description": "Top-level ibex_core baseline with direct RFuzz input mapping.",
    },
    {
        "scheme": "scheme5",
        "label": "scheme5_bit_constraints",
        "config": "configs/designs/ibex_scheme5_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme5_bit_constraints",
        "description": (
            "Top-level ibex_core with the same 395 RFuzz input bits, transformed "
            "only by lightweight combinational constraints such as rvalid=>gnt, "
            "err=>rvalid, boot alignment, fetch-enable projection, and IRQ/debug "
            "mutual exclusion."
        ),
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
