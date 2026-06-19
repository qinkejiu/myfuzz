#!/usr/bin/env python3
"""Run Ibex baseline, scheme5/6, and strict bit-only ablation variants."""

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
        "description": "Strict bit-only stronger constraints from scheme5.",
    },
    {
        "scheme": "scheme6",
        "label": "scheme6_relaxed_bit_constraints",
        "config": "configs/designs/ibex_scheme6_relaxed_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_relaxed_bit_constraints",
        "description": "Strict bit-only relaxed constraints from scheme6.",
    },
    {
        "scheme": "scheme6_fetch",
        "label": "scheme6_fetch_only",
        "config": "configs/designs/ibex_scheme6_fetch_only_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_fetch_only_bit_constraints",
        "description": "Ablation: only fetch_enable nonzero projection.",
    },
    {
        "scheme": "scheme6_hs",
        "label": "scheme6_handshake_only",
        "config": "configs/designs/ibex_scheme6_handshake_only_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_handshake_only_bit_constraints",
        "description": "Ablation: only instruction/data rvalid implies grant.",
    },
    {
        "scheme": "scheme6_fetch_hs",
        "label": "scheme6_fetch_handshake",
        "config": "configs/designs/ibex_scheme6_fetch_handshake_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_fetch_handshake_bit_constraints",
        "description": "Ablation: fetch_enable projection plus rvalid implies grant.",
    },
    {
        "scheme": "scheme6_minlegal",
        "label": "scheme6_minlegal",
        "config": "configs/designs/ibex_scheme6_minlegal_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_minlegal_bit_constraints",
        "description": "Ablation: boot align, fetch projection, rvalid=>gnt, error=>valid.",
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
