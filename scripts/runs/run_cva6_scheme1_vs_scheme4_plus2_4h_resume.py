#!/usr/bin/env python3
"""Run CVA6 scheme1 vs the plus2 scheme4 harness with resumable sampling."""

from __future__ import annotations

import run_cva6_scheme1_vs_scheme4_10h_resume as base


base.SCHEMES = [
    {
        "scheme": "scheme1",
        "label": "scheme1_baseline",
        "config": "configs/designs/cva6/config.json",
        "reuse_out_dir": "runs/designs/cva6",
        "description": "Top-level CVA6 baseline with fully random top-level inputs.",
    },
    {
        "scheme": "scheme4",
        "label": "scheme4_lightweight_plus2",
        "config": "configs/designs/cva6_lightweight_plus2/config.json",
        "reuse_out_dir": "runs/designs/cva6_lightweight_plus2",
        "description": (
            "Top-level CVA6 with input-bit projected legal instruction stream, "
            "structured NoC/AXI latency, CV-X-IF, interrupt/debug pulses, and low-rate errors."
        ),
    },
]


if __name__ == "__main__":
    raise SystemExit(base.main())
