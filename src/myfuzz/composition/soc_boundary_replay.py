"""Stable boundary-replay facade for composed SoC evidence.

The detailed evidence implementation lives in :mod:`soc_failure_evidence`.
This module is intentionally small: callers get one named entry point for the
step-9 boundary replay, while identity checks, event-plan completeness and
field-by-field divergence remain owned by the existing implementation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .soc_failure_evidence import (
    EvidencePackage,
    ReplayResult,
    SocFailureEvidenceError,
    read_evidence_package,
    replay_package,
)

BOUNDARY_REPLAY_SCHEMA = "soc_boundary_replay.v1"


def replay_boundary(package: EvidencePackage | str | Path, build: Any, *,
                    timeout_seconds: int = 600) -> ReplayResult:
    """Replay a saved boundary package against its declared build.

    ``package`` may be an in-memory :class:`EvidencePackage` or a directory
    containing ``evidence_package.json``.  The underlying replay refuses stale
    identities and incomplete event plans; this facade does not weaken either
    condition.
    """
    if isinstance(package, (str, Path)):
        package = read_evidence_package(package)
    if not isinstance(package, EvidencePackage):
        raise SocFailureEvidenceError("evidence-package-required")
    return replay_package(package, build, timeout_seconds=timeout_seconds)


def replay_boundary_document(package: EvidencePackage | str | Path, build: Any, *,
                             timeout_seconds: int = 600) -> dict[str, object]:
    """Return a versioned JSON document for a boundary replay."""
    result = replay_boundary(package, build, timeout_seconds=timeout_seconds)
    document = result.document()
    document["schema_version"] = BOUNDARY_REPLAY_SCHEMA
    return document


__all__ = [
    "BOUNDARY_REPLAY_SCHEMA",
    "replay_boundary",
    "replay_boundary_document",
]
