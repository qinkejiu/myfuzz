"""Candidate manifest construction at the composition/emitter boundary."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath

from myfuzz.contracts import content_hash

from .ir import composition_ir
from .metadata import sanitize_metadata
from .search import CompositionCandidate


def _field(value: object, key: str, default: object = None) -> object:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _basename(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "generated_top.sv"
    return PurePosixPath(value.replace("\\", "/")).name


def candidate_manifest(candidate: CompositionCandidate, emitted: object) -> dict[str, object]:
    """Join a candidate with deterministic emitter output metadata."""
    ir_document = composition_ir(candidate)
    source_text = _field(emitted, "source_text", "")
    if not isinstance(source_text, str):
        raise ValueError("emitted.source_text:type")
    sanitize_metadata(source_text, context="emitted.source_text")
    module = _field(emitted, "module", _field(emitted, "module_name", "candidate_top_" + candidate.graph_hash[7:15]))
    source = _basename(_field(emitted, "source", _field(emitted, "source_path", "generated_top.sv")))
    source_hash = content_hash({"source_text": source_text})
    top_port_abi = _field(emitted, "top_port_abi", [])
    if not isinstance(top_port_abi, list):
        top_port_abi = list(top_port_abi) if isinstance(top_port_abi, tuple) else []
    diagnostics = _field(emitted, "diagnostics", {"errors": [], "warnings": []})
    validation = _field(emitted, "validation", {"parse": "passed", "link": "passed", "width": "passed", "compile": "pending", "smoke": "pending"})
    build_cache_key = content_hash(
        {
            "composition_ir_hash": content_hash(ir_document),
            "graph_hash": candidate.graph_hash,
            "top_content_hash": source_hash,
        }
    )
    document = {
        "schema_version": "candidate_manifest.v1",
        "lifecycle": "top_validated",
        "candidate_id": candidate.candidate_id,
        "composition_ir_hash": content_hash(ir_document),
        "top": {"module": module, "source": source, "content_hash": source_hash},
        "harnesses": {"flat-direct": [], "candidate-direct": [], "candidate-depaware": []},
        "top_port_abi": sorted(top_port_abi, key=lambda item: int(_field(item, "port_id", 0))),
        "address_map": ir_document["address_regions"],
        "raw_bit_mappings": {"flat-direct": [], "candidate-direct": [], "candidate-depaware": []},
        "validation": validation,
        "coverage_universe": [],
        "source_map": [],
        "build_cache_key": build_cache_key,
        "resources": {"peak_rss_bytes": None},
        "diagnostics": diagnostics,
        "evidence": ir_document["evidence"],
        "assumptions": ir_document["assumptions"],
    }
    return sanitize_metadata(document, context="emitted.metadata")  # type: ignore[return-value]


__all__ = ["candidate_manifest"]
