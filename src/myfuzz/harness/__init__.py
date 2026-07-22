"""Generic structural verification harness ABI and projections."""

from __future__ import annotations

from .abi import RawBitAbi, RawBitUse, RawDestination, build_raw_abi
from .depaware import build_depaware
from .direct import HarnessArtifact, build_direct, coverage_id


_MODES = {"flat_direct", "candidate_direct", "candidate_depaware"}


def raw_width(manifest: object) -> int:
    return build_raw_abi(manifest).raw_width


def coverage_universe(manifest: object) -> str:
    return coverage_id(manifest)


def build_harness(manifest: object, mode: str) -> HarnessArtifact:
    if mode not in _MODES:
        raise ValueError(f"unknown harness mode: {mode}")
    if mode == "candidate_depaware":
        return build_depaware(manifest)
    return build_direct(manifest, mode)


__all__ = [
    "HarnessArtifact",
    "RawBitAbi",
    "RawBitUse",
    "RawDestination",
    "build_harness",
    "raw_width",
    "coverage_universe",
]
