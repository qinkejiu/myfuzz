#!/usr/bin/env python3
"""Run Ibex baseline and strict bit-only opcode/low-bit projection sweeps."""

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
        "scheme": "scheme6_opcode_mixed12",
        "label": "scheme6_opcode_mixed12",
        "config": "configs/designs/ibex_scheme6_opcode_mixed12_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_mixed12_bit_constraints",
        "description": "Strict bit-only: legal opcode projection enabled by three raw bits, about 12.5 percent of samples.",
    },
    {
        "scheme": "scheme6_opcode_mixed25",
        "label": "scheme6_opcode_mixed25",
        "config": "configs/designs/ibex_scheme6_opcode_mixed25_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_mixed25_bit_constraints",
        "description": "Strict bit-only: legal opcode projection enabled by two raw bits, about 25 percent of samples.",
    },
    {
        "scheme": "scheme6_opcode_mixed50",
        "label": "scheme6_opcode_mixed",
        "config": "configs/designs/ibex_scheme6_opcode_mixed_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_mixed_bit_constraints",
        "description": "Strict bit-only: legal opcode projection enabled by one raw bit, about 50 percent of samples.",
    },
    {
        "scheme": "scheme6_opcode_mixed75",
        "label": "scheme6_opcode_mixed75",
        "config": "configs/designs/ibex_scheme6_opcode_mixed75_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_mixed75_bit_constraints",
        "description": "Strict bit-only: legal opcode projection enabled by either of two raw bits, about 75 percent of samples.",
    },
    {
        "scheme": "scheme6_low2_mixed25",
        "label": "scheme6_low2_mixed25",
        "config": "configs/designs/ibex_scheme6_low2_mixed25_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_low2_mixed25_bit_constraints",
        "description": "Strict bit-only: force instruction low bits to 2'b11 in about 25 percent of samples.",
    },
    {
        "scheme": "scheme6_low2_mixed50",
        "label": "scheme6_low2_mixed50",
        "config": "configs/designs/ibex_scheme6_low2_mixed50_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_low2_mixed50_bit_constraints",
        "description": "Strict bit-only: force instruction low bits to 2'b11 in about 50 percent of samples.",
    },
    {
        "scheme": "scheme6_low2_opcode_mixed25",
        "label": "scheme6_low2_opcode_mixed25",
        "config": "configs/designs/ibex_scheme6_low2_opcode_mixed25_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_low2_opcode_mixed25_bit_constraints",
        "description": "Strict bit-only: combine 25 percent low-bit projection and 25 percent legal opcode projection.",
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
