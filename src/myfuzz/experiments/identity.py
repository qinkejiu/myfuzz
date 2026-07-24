"""Canonical candidate identities shared by planning and reporting."""

from __future__ import annotations

from collections.abc import Mapping

from myfuzz.contracts import content_hash


_HARNESS_GROUPS = ("flat-direct", "candidate-direct", "candidate-depaware")


def _harness_semantics(manifest: Mapping[str, object]) -> dict[str, dict[str, object]]:
    harnesses = manifest.get("harnesses")
    records = harnesses if isinstance(harnesses, Mapping) else {}
    result: dict[str, dict[str, object]] = {}
    for harness in _HARNESS_GROUPS:
        value = records.get(harness)
        record = value if isinstance(value, Mapping) else {}
        result[harness] = {
            "content_hash": record.get("content_hash"),
            "abi_hash": record.get("abi_hash"),
            "projection_plan_hash": record.get("projection_plan_hash"),
        }
    return result


def candidate_semantic_hash(manifest: Mapping[str, object]) -> str:
    """Hash runnable candidate semantics, excluding transport/document hashes."""
    top = manifest.get("top")
    top_content_hash = top.get("content_hash") if isinstance(top, Mapping) else None
    return content_hash(
        {
            "candidate_id": manifest.get("candidate_id"),
            "top_content_hash": top_content_hash,
            "build_cache_key": manifest.get("build_cache_key"),
            "harnesses": _harness_semantics(manifest),
        }
    )


__all__ = ["candidate_semantic_hash"]
