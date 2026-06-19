#!/usr/bin/env python3
"""Run Ibex baseline vs scheme5 and scheme6 bit-only constraints."""

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
            "only by stronger combinational constraints such as 256-byte boot "
            "alignment, 32-bit instruction low-bit bias, rvalid=>gnt, low-rate "
            "IRQ/debug/error, and fast IRQ onehot projection."
        ),
    },
    {
        "scheme": "scheme6",
        "label": "scheme6_relaxed_bit_constraints",
        "config": "configs/designs/ibex_scheme6_relaxed_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_relaxed_bit_constraints",
        "description": (
            "Top-level ibex_core with the same 395 RFuzz input bits and relaxed "
            "combinational constraints: 4-byte boot alignment, fetch-enable "
            "projection, rvalid=>gnt, valid-gated errors, and higher-rate raw "
            "IRQ/debug diversity without instruction templates or models."
        ),
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
