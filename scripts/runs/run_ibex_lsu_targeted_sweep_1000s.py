#!/usr/bin/env python3
"""Run Ibex baseline and strict bit-only LSU-targeted projection sweeps."""

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
        "scheme": "scheme6_opcode_mixed50",
        "label": "scheme6_opcode_mixed",
        "config": "configs/designs/ibex_scheme6_opcode_mixed_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_mixed_bit_constraints",
        "description": "Reference strict bit-only opcode mixed variant from the previous sweep.",
    },
    {
        "scheme": "scheme6_ls_opcode_mixed50",
        "label": "scheme6_ls_opcode_mixed50",
        "config": "configs/designs/ibex_scheme6_ls_opcode_mixed50_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_ls_opcode_mixed50_bit_constraints",
        "description": "Strict bit-only: 50 percent samples project only opcode to LOAD/STORE classes.",
    },
    {
        "scheme": "scheme6_ls_opcode_mixed75",
        "label": "scheme6_ls_opcode_mixed75",
        "config": "configs/designs/ibex_scheme6_ls_opcode_mixed75_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_ls_opcode_mixed75_bit_constraints",
        "description": "Strict bit-only: 75 percent samples project only opcode to LOAD/STORE classes.",
    },
    {
        "scheme": "scheme6_ls_word_mixed50",
        "label": "scheme6_ls_word_mixed50",
        "config": "configs/designs/ibex_scheme6_ls_word_mixed50_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_ls_word_mixed50_bit_constraints",
        "description": "Strict bit-only: 50 percent samples project LOAD/STORE opcode and word-size funct3.",
    },
    {
        "scheme": "scheme6_ls_misalign_mixed50",
        "label": "scheme6_ls_misalign_mixed50",
        "config": "configs/designs/ibex_scheme6_ls_misalign_mixed50_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_ls_misalign_mixed50_bit_constraints",
        "description": "Strict bit-only: 50 percent samples bias LOAD/STORE word addresses toward misalignment.",
    },
    {
        "scheme": "scheme6_ls_misalign_mixed75",
        "label": "scheme6_ls_misalign_mixed75",
        "config": "configs/designs/ibex_scheme6_ls_misalign_mixed75_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_ls_misalign_mixed75_bit_constraints",
        "description": "Strict bit-only: 75 percent samples bias LOAD/STORE word addresses toward misalignment.",
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
