"""Generic structural verification harness ABI and projections."""

from __future__ import annotations

from collections.abc import Mapping

from .abi import RawBitAbi, RawBitUse, RawDestination, build_raw_abi
from .compiler import HarnessBundle, compile_harness_bundle, write_harness_bundle
from .depaware import build_depaware
from .direct import HarnessArtifact, build_direct, coverage_id
from .projection import (
    CanonicalByteEnable,
    ProjectionAction,
    ProjectionPlan,
    ProjectionResult,
    ProjectionState,
    build_projection_plan,
    project_sample,
)
from .static_policy import (
    StaticAction,
    StaticPolicyParameters,
    StaticPolicyPlan,
    compile_static_policy,
    validate_static_declarations,
)
from .static_projection import build_static_harness


_MODES = {"flat_direct", "candidate_direct", "candidate_depaware", "candidate_static"}


def raw_width(manifest: object) -> int:
    return build_raw_abi(manifest).raw_width


def coverage_universe(manifest: object) -> str:
    return coverage_id(manifest)


def build_harness(
    manifest: object,
    mode: str,
    *,
    static_declarations: Mapping[str, object] | None = None,
    static_parameters: StaticPolicyParameters | None = None,
) -> HarnessArtifact:
    if mode not in _MODES:
        raise ValueError(f"unknown harness mode: {mode}")
    if mode == "candidate_static":
        if static_declarations is None or static_parameters is None:
            raise ValueError("candidate_static requires static declarations and parameters")
        plan = compile_static_policy(
            build_raw_abi(manifest), static_declarations, static_parameters
        )
        return build_static_harness(manifest, plan)
    if static_declarations is not None or static_parameters is not None:
        raise ValueError("static inputs require candidate_static mode")
    if mode == "candidate_depaware":
        return build_depaware(manifest)
    return build_direct(manifest, mode)


__all__ = [
    "HarnessArtifact",
    "HarnessBundle",
    "CanonicalByteEnable",
    "ProjectionAction",
    "ProjectionPlan",
    "ProjectionResult",
    "ProjectionState",
    "RawBitAbi",
    "RawBitUse",
    "RawDestination",
    "StaticAction",
    "StaticPolicyParameters",
    "StaticPolicyPlan",
    "build_harness",
    "build_projection_plan",
    "compile_harness_bundle",
    "compile_static_policy",
    "write_harness_bundle",
    "raw_width",
    "project_sample",
    "validate_static_declarations",
    "coverage_universe",
]
