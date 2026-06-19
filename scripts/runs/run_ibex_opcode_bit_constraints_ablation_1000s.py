#!/usr/bin/env python3
"""Run Ibex baseline and opcode-level strict bit-only ablation variants."""

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
        "scheme": "scheme6_minlegal",
        "label": "scheme6_minlegal",
        "config": "configs/designs/ibex_scheme6_minlegal_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_minlegal_bit_constraints",
        "description": "Ablation: boot align, fetch projection, rvalid=>gnt, error=>valid.",
    },
    {
        "scheme": "scheme6_opcode",
        "label": "scheme6_opcode_only",
        "config": "configs/designs/ibex_scheme6_opcode_only_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_only_bit_constraints",
        "description": "Ablation: only instruction opcode bits are projected into common legal RV32 opcode classes.",
    },
    {
        "scheme": "scheme6_opcode_mixed",
        "label": "scheme6_opcode_mixed",
        "config": "configs/designs/ibex_scheme6_opcode_mixed_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_mixed_bit_constraints",
        "description": "Ablation: one raw bit chooses raw opcode or legal opcode projection.",
    },
    {
        "scheme": "scheme6_opcode_minlegal",
        "label": "scheme6_opcode_minlegal",
        "config": "configs/designs/ibex_scheme6_opcode_minlegal_bit_constraints/config.json",
        "reuse_out_dir": "runs/designs/ibex_scheme6_opcode_minlegal_bit_constraints",
        "description": "Ablation: legal opcode projection plus minimal boot/fetch/handshake/error-valid projections.",
    },
]


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
