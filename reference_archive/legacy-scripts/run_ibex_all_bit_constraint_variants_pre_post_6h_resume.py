#!/usr/bin/env python3
"""Run Ibex baseline and all scheme5/6 bit-constraint variants for 6h.

For every non-baseline variant this runner creates two rows:

* *_pre: the existing bit-only harness where RFuzz mutates raw input bits and
  the harness projects them into corrected DUT inputs.
* *_post: a direct-signal control where RFuzz mutates the DUT input vector
  after correction, so no variant-specific projection is applied.
"""

from __future__ import annotations

import json
from pathlib import Path

import run_ibex_scheme1_vs_scheme4_plus2_10h_resume as base


ROOT = Path(__file__).resolve().parents[2]
POST_CONFIG = "configs/designs/ibex_post_correction_direct/config.json"
POST_REUSE_OUT_DIR = "runs/designs/ibex"

VARIANTS = [
    ("scheme5", "configs/designs/ibex_scheme5_bit_constraints/config.json"),
    ("scheme6_relaxed", "configs/designs/ibex_scheme6_relaxed_bit_constraints/config.json"),
    ("scheme6_fetch_only", "configs/designs/ibex_scheme6_fetch_only_bit_constraints/config.json"),
    ("scheme6_handshake_only", "configs/designs/ibex_scheme6_handshake_only_bit_constraints/config.json"),
    ("scheme6_fetch_handshake", "configs/designs/ibex_scheme6_fetch_handshake_bit_constraints/config.json"),
    ("scheme6_minlegal", "configs/designs/ibex_scheme6_minlegal_bit_constraints/config.json"),
    ("scheme6_opcode_only", "configs/designs/ibex_scheme6_opcode_only_bit_constraints/config.json"),
    ("scheme6_opcode_mixed", "configs/designs/ibex_scheme6_opcode_mixed_bit_constraints/config.json"),
    ("scheme6_opcode_mixed12", "configs/designs/ibex_scheme6_opcode_mixed12_bit_constraints/config.json"),
    ("scheme6_opcode_mixed25", "configs/designs/ibex_scheme6_opcode_mixed25_bit_constraints/config.json"),
    ("scheme6_opcode_mixed75", "configs/designs/ibex_scheme6_opcode_mixed75_bit_constraints/config.json"),
    ("scheme6_opcode_minlegal", "configs/designs/ibex_scheme6_opcode_minlegal_bit_constraints/config.json"),
    ("scheme6_low2_mixed25", "configs/designs/ibex_scheme6_low2_mixed25_bit_constraints/config.json"),
    ("scheme6_low2_mixed50", "configs/designs/ibex_scheme6_low2_mixed50_bit_constraints/config.json"),
    ("scheme6_low2_opcode_mixed25", "configs/designs/ibex_scheme6_low2_opcode_mixed25_bit_constraints/config.json"),
    ("scheme6_ls_opcode_mixed50", "configs/designs/ibex_scheme6_ls_opcode_mixed50_bit_constraints/config.json"),
    ("scheme6_ls_opcode_mixed75", "configs/designs/ibex_scheme6_ls_opcode_mixed75_bit_constraints/config.json"),
    ("scheme6_ls_word_mixed50", "configs/designs/ibex_scheme6_ls_word_mixed50_bit_constraints/config.json"),
    ("scheme6_ls_misalign_mixed50", "configs/designs/ibex_scheme6_ls_misalign_mixed50_bit_constraints/config.json"),
    ("scheme6_ls_misalign_mixed75", "configs/designs/ibex_scheme6_ls_misalign_mixed75_bit_constraints/config.json"),
]


def out_dir_for(config: str) -> str:
    data = json.loads((ROOT / config).read_text())
    return str(data["out_dir"])


def make_schemes() -> list[dict]:
    schemes: list[dict] = [
        {
            "scheme": "scheme1_baseline",
            "label": "scheme1_baseline",
            "config": "configs/designs/ibex/config.json",
            "reuse_out_dir": "runs/designs/ibex",
            "description": (
                "Baseline: top-level ibex_core with direct RFuzz input mapping. "
                "This is the single no-correction reference and is not duplicated."
            ),
        }
    ]

    for name, config in VARIANTS:
        schemes.append({
            "scheme": f"{name}_pre",
            "label": f"{name}_pre",
            "config": config,
            "reuse_out_dir": out_dir_for(config),
            "description": (
                f"{name} pre-correction mutation: RFuzz mutates raw 395-bit input, "
                "then the variant harness projects/corrects those bits before driving ibex_core."
            ),
        })
        schemes.append({
            "scheme": f"{name}_post",
            "label": f"{name}_post",
            "config": POST_CONFIG,
            "reuse_out_dir": POST_REUSE_OUT_DIR,
            "description": (
                f"{name} post-correction direct-signal control: RFuzz mutates the 395-bit DUT "
                "input vector directly, representing mutation after the variant's correction layer."
            ),
        })
    return schemes


base.SCHEMES = make_schemes()
_base_choose_cpu_sets = base.choose_cpu_sets


def choose_cpu_sets(count: int, requested: str | None) -> list[str | None]:
    if requested:
        return _base_choose_cpu_sets(count, requested)
    try:
        allowed = sorted(__import__("os").sched_getaffinity(0))  # type: ignore[attr-defined]
    except AttributeError:
        allowed = list(range(__import__("os").cpu_count() or 0))
    if not allowed:
        return [None] * count
    return [str(allowed[index % len(allowed)]) for index in range(count)]


base.choose_cpu_sets = choose_cpu_sets


def main() -> int:
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
