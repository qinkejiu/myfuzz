"""Detached, hash-checked joins between composition and harness manifests."""

from __future__ import annotations

from collections.abc import Mapping
import copy
import json
from pathlib import Path

from myfuzz.contracts import ContractError, content_hash, validate_contract


_REQUIRED_GROUPS = frozenset(("flat-direct", "candidate-direct", "candidate-depaware"))
_COPIED_FRAGMENT_FIELDS = frozenset(
    (
        "dependency_graph",
        "coverage_universe_hash",
        "coverage_metadata_hash",
        "protocol_ids",
        "protocols",
        "files",
    )
)
_READY_VALUES = frozenset(("ready", "passed"))


def _error(path: str, reason: str) -> None:
    raise ContractError("candidate_manifest.v1", path, reason)


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error(path, "type")
    return value


def load_and_validate(path: Path, schema_id: str) -> dict[str, object]:
    """Read, validate, and detach one versioned JSON document."""
    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib.Path")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(schema_id, "document", "invalid-json") from error
    validate_contract(document, schema_id)
    return copy.deepcopy(document)


def _runtime_ready(runtime: Mapping[str, object]) -> bool:
    if runtime.get("status") not in _READY_VALUES:
        return False
    validation = runtime.get("validation")
    if validation is None:
        return True
    if not isinstance(validation, Mapping):
        return False
    return validation.get("compile") in _READY_VALUES and validation.get("smoke") in _READY_VALUES


def merge_candidate_manifest(
    composition_manifest: Mapping[str, object],
    harness_fragment: Mapping[str, object],
) -> dict[str, object]:
    """Join only validated, explicitly B-owned fields into a detached manifest."""
    base = _mapping(copy.deepcopy(dict(composition_manifest)), "document")
    fragment = _mapping(harness_fragment, "harness_fragment")
    validate_contract(base, "candidate_manifest.v1")
    if base.get("lifecycle") != "top_validated":
        _error("lifecycle", "expected-top-validated")

    groups = fragment.get("harnesses")
    if not isinstance(groups, Mapping) or set(groups) != _REQUIRED_GROUPS:
        _error("harnesses", "missing-required-group")
    if any(not isinstance(groups[group], list) or not groups[group] for group in _REQUIRED_GROUPS):
        _error("harnesses", "incomplete-required-group")

    candidate_id = fragment.get("candidate_id", base.get("candidate_id"))
    if candidate_id != base.get("candidate_id"):
        _error("candidate_id", "mismatch")
    composition_hash = fragment.get("composition_ir_hash")
    if composition_hash is not None and composition_hash != base.get("composition_ir_hash"):
        _error("composition_ir_hash", "mismatch")
    input_hash = fragment.get("input_manifest_hash")
    if input_hash is not None and input_hash != content_hash(base):
        _error("input_manifest_hash", "mismatch")

    mappings = fragment.get("raw_bit_mappings")
    if not isinstance(mappings, Mapping) or set(mappings) != _REQUIRED_GROUPS:
        _error("raw_bit_mappings", "missing-required-group")
    runtime = _mapping(fragment.get("runtime", {}), "runtime")

    candidate = copy.deepcopy(dict(base))
    candidate["harnesses"] = copy.deepcopy(dict(groups))
    candidate["raw_bit_mappings"] = copy.deepcopy(dict(mappings))
    candidate["runtime"] = copy.deepcopy(dict(runtime))
    for field in _COPIED_FRAGMENT_FIELDS:
        if field in fragment:
            candidate[field] = copy.deepcopy(fragment[field])
    candidate["lifecycle"] = "runtime_ready" if _runtime_ready(runtime) else "top_validated"
    validate_contract(candidate, "candidate_manifest.v1")
    return candidate


def manifest_content_hash(document: Mapping[str, object]) -> str:
    """Validate and hash the final persisted candidate manifest."""
    detached = copy.deepcopy(dict(_mapping(document, "document")))
    validate_contract(detached, "candidate_manifest.v1")
    return content_hash(detached)
