"""Candidate manifest construction at the composition/emitter boundary."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath

from .ir import composition_ir
from .metadata import sanitize_metadata, semantic_content_hash, semantic_source_hash
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
    module = _field(emitted, "module", _field(emitted, "module_name", "candidate_top_" + candidate.graph_hash[7:15]))
    source = _basename(_field(emitted, "source", _field(emitted, "source_path", "generated_top.sv")))
    source_hash = semantic_source_hash(source_text, context="emitted.source_text")
    top_port_abi = _field(emitted, "top_port_abi", [])
    if not isinstance(top_port_abi, list):
        top_port_abi = list(top_port_abi) if isinstance(top_port_abi, tuple) else []
    diagnostics = _field(emitted, "diagnostics", {"errors": [], "warnings": []})
    validation = _field(emitted, "validation", {"parse": "passed", "link": "passed", "width": "passed", "compile": "pending", "smoke": "pending"})
    dut_input_hash = _field(emitted, "dut_input_hash", candidate.parent_input_hash)
    if not isinstance(dut_input_hash, str) or not dut_input_hash.startswith("sha256:") or len(dut_input_hash) != 71:
        raise ValueError("emitted.dut_input_hash:invalid-hash")
    lifecycle = _field(emitted, "lifecycle", "top_validated")
    coverage_universe = _field(emitted, "coverage_universe", [])
    ir_hash = semantic_content_hash(ir_document, context="composition.ir")
    tool_versions = _field(emitted, "tool_versions", {})
    schema_versions = _field(
        emitted,
        "schema_versions",
        {
            "candidate_manifest": "candidate_manifest.v1",
            "composition_ir": str(ir_document["schema_version"]),
        },
    )
    instrumentation = _field(emitted, "instrumentation", {})
    compile_args = _field(emitted, "compile_args", [])
    for field, value in (
        ("tool_versions", tool_versions),
        ("schema_versions", schema_versions),
        ("instrumentation", instrumentation),
    ):
        if not isinstance(value, Mapping):
            raise ValueError(f"emitted.{field}:type")
    if not isinstance(compile_args, (list, tuple)) or any(
        not isinstance(value, str) for value in compile_args
    ):
        raise ValueError("emitted.compile_args:type")
    build_cache_inputs = sanitize_metadata(
        {
            "tool_versions": tool_versions,
            "schema_versions": schema_versions,
            "instrumentation": instrumentation,
            "compile_args": list(compile_args),
        },
        context="candidate_manifest.cache_inputs",
    )
    build_cache_key = semantic_content_hash(
        {
            "composition_ir_hash": ir_hash,
            "graph_hash": candidate.graph_hash,
            "top_content_hash": source_hash,
            "dut_input_hash": dut_input_hash,
            "build_environment": build_cache_inputs,
        },
        context="candidate_manifest.cache_key",
    )
    document = {
        "schema_version": "candidate_manifest.v1",
        "lifecycle": lifecycle,
        "candidate_id": candidate.candidate_id,
        "dut_input_hash": dut_input_hash,
        "composition_ir_hash": ir_hash,
        "top": {"module": module, "source": source, "content_hash": source_hash},
        "harnesses": {"flat-direct": [], "candidate-direct": [], "candidate-depaware": []},
        "top_port_abi": sorted(top_port_abi, key=lambda item: int(_field(item, "port_id", 0))),
        "address_map": ir_document["address_regions"],
        "raw_bit_mappings": {"flat-direct": [], "candidate-direct": [], "candidate-depaware": []},
        "validation": validation,
        "coverage_universe": coverage_universe,
        "source_map": [],
        "build_cache_key": build_cache_key,
        "build_cache_inputs": build_cache_inputs,
        "resources": {"peak_rss_bytes": None},
        "diagnostics": diagnostics,
        "evidence": ir_document["evidence"],
        "assumptions": ir_document["assumptions"],
        "rejected_alternatives": ir_document["rejected_alternatives"],
    }
    for key in (
        "combinational_design",
        "endpoint_bindings",
        "external_ports",
        "fields",
        "flat_baseline",
        "hdl_facts",
    ):
        value = _field(emitted, key)
        if value is not None:
            document[key] = value
    return sanitize_metadata(document, context="emitted.metadata")  # type: ignore[return-value]


__all__ = ["candidate_manifest"]
