#!/usr/bin/env python3
"""Top-K composition orchestration and generated-top validation."""

from __future__ import annotations

import json
import ctypes
import errno
import hashlib
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
import re
import shutil
import tempfile

from myfuzz.composition import (
    candidate_manifest,
    compose_topk,
    composition_ir,
    load_declarations,
    normalize_facts,
)
from myfuzz.contracts import content_hash, validate_contract
from myfuzz.scripts.frontend_api import FrontendLibrary, default_frontend_library


_REPO_ROOT = Path(__file__).resolve().parents[3]
_SAFE_CANDIDATE_DIRECTORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_CONTENT_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"{label}:read:{error.strerror}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"{label}:json:{error.msg}") from error


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path}:type")
    return value


def _string_sequence(value: object, path: str, *, nonempty: bool) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{path}:type")
    result = tuple(value)
    if nonempty and not result:
        raise ValueError(f"{path}:empty")
    for index, item in enumerate(result):
        if not isinstance(item, str) or not item or "\0" in item:
            raise ValueError(f"{path}[{index}]:type")
    return result


def _protocols(config: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    raw = config.get("protocols")
    if isinstance(raw, Mapping):
        values: Sequence[object]
        if "protocol_id" in raw:
            values = (raw,)
        else:
            values = tuple(raw[key] for key in sorted(raw, key=str))
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        values = raw
    else:
        raise ValueError("protocols:type")

    result: list[Mapping[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for index, value in enumerate(values):
        document = _mapping(value, f"protocols[{index}]")
        validate_contract(document, "protocol.v1")
        protocol_id = document.get("protocol_id")
        if not isinstance(protocol_id, str) or not protocol_id:
            raise ValueError(f"protocols[{index}].protocol_id:type")
        version = document.get("plugin_version", document.get("version"))
        if not isinstance(version, str) or not version:
            raise ValueError(f"protocols[{index}].plugin_version:type")
        key = (protocol_id, version)
        if key in seen:
            raise ValueError(f"protocols[{index}].protocol_id:duplicate")
        seen.add(key)
        result.append(document)
    if not result:
        raise ValueError("protocols:empty")
    return tuple(
        sorted(
            result,
            key=lambda item: (
                str(item["protocol_id"]),
                str(item.get("plugin_version", item.get("version"))),
            ),
        )
    )


def _source_inputs(
    config_path: Path,
    config: Mapping[str, object],
) -> tuple[Path, tuple[str, ...], tuple[str, ...]]:
    root_value = config.get("source_root", ".")
    if not isinstance(root_value, str) or not root_value or "\0" in root_value:
        raise ValueError("source_root:type")
    source_root = Path(root_value)
    if not source_root.is_absolute():
        source_root = config_path.parent / source_root
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise ValueError("source_root:not-directory")

    configured_sources = _string_sequence(config.get("sources"), "sources", nonempty=True)
    sources: list[str] = []
    for index, value in enumerate(configured_sources):
        source = Path(value)
        if not source.is_absolute():
            source = source_root / source
        source = source.resolve()
        if not source.is_file():
            raise ValueError(f"sources[{index}]:not-file")
        sources.append(source.as_posix())
    verilator_args = _string_sequence(
        config.get("verilator_args", []),
        "verilator_args",
        nonempty=False,
    )
    return source_root, tuple(sources), verilator_args


def _diagnostics(document: Mapping[str, object], path: str) -> Mapping[str, object]:
    diagnostics = _mapping(document.get("diagnostics"), f"{path}.diagnostics")
    for group in ("errors", "warnings"):
        value = diagnostics.get(group)
        if not isinstance(value, list):
            raise ValueError(f"{path}.diagnostics.{group}:type")
    unsupported = diagnostics.get("unsupported", [])
    if not isinstance(unsupported, list):
        raise ValueError(f"{path}.diagnostics.unsupported:type")
    return diagnostics


def _require_clean_facts(document: Mapping[str, object], path: str) -> None:
    diagnostics = _diagnostics(document, path)
    if diagnostics["errors"]:
        raise ValueError(f"{path}.diagnostics.errors:not-empty")
    if diagnostics.get("unsupported"):
        raise ValueError(f"{path}.diagnostics.unsupported:not-empty")


def _source_symbols(document: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    raw = document.get("source_symbols")
    if not isinstance(raw, list):
        raise ValueError("frontend.source_symbols:type")
    symbols: list[Mapping[str, object]] = []
    for index, value in enumerate(raw):
        symbol = _mapping(value, f"frontend.source_symbols[{index}]")
        entity_id = symbol.get("entity_id")
        kind = symbol.get("kind")
        name = symbol.get("name")
        original_name = symbol.get("original_name")
        if not isinstance(entity_id, int) or isinstance(entity_id, bool) or entity_id <= 0:
            raise ValueError(f"frontend.source_symbols[{index}].entity_id:invalid")
        if not isinstance(kind, str) or not kind:
            raise ValueError(f"frontend.source_symbols[{index}].kind:type")
        if not isinstance(name, str) or not name:
            raise ValueError(f"frontend.source_symbols[{index}].name:type")
        if not isinstance(original_name, str) or not original_name:
            raise ValueError(f"frontend.source_symbols[{index}].original_name:type")
        symbols.append(symbol)
    return tuple(sorted(symbols, key=lambda item: (str(item["kind"]), int(item["entity_id"]))))


def _build_is_valid(result: Mapping[str, object]) -> bool:
    diagnostics = _diagnostics(result, "builder")
    validation = _mapping(result.get("validation"), "builder.validation")
    return (
        not diagnostics["errors"]
        and all(validation.get(name) is True for name in ("dtype", "link", "pin", "width"))
        and validation.get("unknown_width_ports") == []
        and isinstance(result.get("source_text"), str)
        and bool(result["source_text"])
    )


def _tool_input_hash(document: Mapping[str, object], path: str) -> str:
    tool = _mapping(document.get("tool"), f"{path}.tool")
    value = tool.get("input_hash")
    if not isinstance(value, str) or _CONTENT_HASH.fullmatch(value) is None:
        raise ValueError(f"{path}.tool.input_hash:invalid")
    return value


def _symbol_index(
    document: Mapping[str, object],
) -> dict[tuple[str, int], Mapping[str, object]]:
    result: dict[tuple[str, int], Mapping[str, object]] = {}
    for symbol in _source_symbols(document):
        key = (str(symbol["kind"]), int(symbol["entity_id"]))
        if key in result:
            raise ValueError(f"frontend.source_symbols:{key[0]}:{key[1]}:duplicate")
        result[key] = symbol
    return result


def _named_module(
    document: Mapping[str, object],
    name: str,
) -> Mapping[str, object] | None:
    modules = {
        int(item["id"]): item
        for item in document.get("modules", [])
        if isinstance(item, Mapping)
        and isinstance(item.get("id"), int)
        and not isinstance(item.get("id"), bool)
    }
    symbols = _symbol_index(document)
    matches = [
        modules[entity_id]
        for (kind, entity_id), symbol in symbols.items()
        if kind == "module"
        and entity_id in modules
        and (symbol.get("name") == name or symbol.get("original_name") == name)
    ]
    if len(matches) > 1:
        raise ValueError(f"reparse.module:{name}:duplicate")
    return matches[0] if matches else None


def _actual_top_port_abi(
    document: Mapping[str, object],
    ir_document: Mapping[str, object],
) -> tuple[list[dict[str, object]] | None, int | None, dict[str, object]]:
    expected: list[dict[str, object]] = []
    expected_by_name: dict[str, Mapping[str, object]] = {}
    for value in ir_document["external_ports"]:
        port = _mapping(value, "composition_ir.external_ports[]")
        port_id = int(port["port_id"])
        emitted_name = f"external_{port_id}"
        expected.append(
            {
                "port_id": port_id,
                "emitted_name": emitted_name,
                "direction": port["direction"],
                "width": port["width"],
            }
        )
        expected_by_name[emitted_name] = port

    top = _named_module(document, "composition_top")
    if top is None:
        return None, None, {
            "reason": "composition-top-not-found",
            "expected": sorted(expected, key=lambda item: int(item["port_id"])),
            "actual": [],
        }

    top_id = int(top["id"])
    top_port_ids = top.get("ports")
    if not isinstance(top_port_ids, list):
        raise ValueError("reparse.top.ports:type")
    facts_by_id = {
        int(value["id"]): _mapping(value, "reparse.ports[]")
        for value in document.get("ports", [])
        if isinstance(value, Mapping)
        and isinstance(value.get("id"), int)
        and not isinstance(value.get("id"), bool)
    }
    symbols = _symbol_index(document)
    actual: list[dict[str, object]] = []
    actual_by_name: dict[str, Mapping[str, object]] = {}
    issues: list[dict[str, object]] = []
    for raw_port_id in top_port_ids:
        if not isinstance(raw_port_id, int) or isinstance(raw_port_id, bool):
            issues.append({"reason": "invalid-actual-port-id", "value": raw_port_id})
            continue
        fact = facts_by_id.get(raw_port_id)
        symbol = symbols.get(("port", raw_port_id))
        if fact is None or symbol is None:
            issues.append({"reason": "missing-actual-port-record", "actual_port_id": raw_port_id})
            continue
        emitted_name = symbol.get("name")
        if not isinstance(emitted_name, str) or not emitted_name:
            issues.append({"reason": "missing-emitted-name", "actual_port_id": raw_port_id})
            continue
        record = {
            "actual_port_id": raw_port_id,
            "emitted_name": emitted_name,
            "direction": fact.get("direction"),
            "width": fact.get("width"),
            "signed": fact.get("signed"),
            "declared_role": fact.get("declared_role"),
        }
        actual.append(record)
        if emitted_name in actual_by_name:
            issues.append({"reason": "duplicate-emitted-name", "emitted_name": emitted_name})
        actual_by_name[emitted_name] = record

    expected_names = set(expected_by_name)
    actual_names = set(actual_by_name)
    for name in sorted(expected_names - actual_names):
        issues.append({"reason": "missing-port", "emitted_name": name})
    for name in sorted(actual_names - expected_names):
        issues.append({"reason": "unexpected-port", "emitted_name": name})
    for name in sorted(expected_names & actual_names):
        intended = expected_by_name[name]
        parsed = actual_by_name[name]
        for field in ("direction", "width", "signed"):
            if parsed.get(field) != intended.get(field):
                issues.append(
                    {
                        "reason": f"{field}-mismatch",
                        "emitted_name": name,
                        "expected": intended.get(field),
                        "actual": parsed.get(field),
                    }
                )

    diagnostics = {
        "expected": sorted(expected, key=lambda item: int(item["port_id"])),
        "actual": sorted(actual, key=lambda item: str(item["emitted_name"])),
        "issues": issues,
    }
    if issues:
        return None, top_id, diagnostics

    control_by_port: dict[int, Mapping[str, object]] = {}
    for section in ("clock_domains", "reset_domains"):
        for value in ir_document.get(section, []):
            control = _mapping(value, f"composition_ir.{section}[]")
            control_by_port[int(control["port_id"])] = control

    abi: list[dict[str, object]] = []
    for name in sorted(expected_by_name, key=lambda value: int(value.removeprefix("external_"))):
        intended = expected_by_name[name]
        parsed = actual_by_name[name]
        port_id = int(intended["port_id"])
        role = str(intended["semantic_role"])
        fuzzable = intended["direction"] in ("input", "inout") and role not in ("clock", "reset")
        record: dict[str, object] = {
            "port_id": port_id,
            "actual_port_id": int(parsed["actual_port_id"]),
            "component_id": intended.get("component_id"),
            "emitted_name": name,
            "direction": parsed["direction"],
            "width": parsed["width"],
            "signed": parsed["signed"],
            "semantic_role": role,
            "fuzzable": fuzzable,
            "fuzz_disposition": "fuzz" if fuzzable else "control" if role in ("clock", "reset") else "observe",
        }
        control = control_by_port.get(port_id)
        if control is not None:
            active_level = 1 if control.get("active_level") == "high" else 0
            record["active_level"] = active_level
            record["synchronous"] = bool(control.get("synchronous"))
            if role == "reset":
                record["reset_value"] = active_level
                record["io_meta_reset"] = False
        abi.append(record)
    return sorted(abi, key=lambda item: int(item["port_id"])), top_id, diagnostics


def _abi_facts_conflicts(
    document: Mapping[str, object],
    abi: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    facts = {
        int(value["id"]): value
        for value in document.get("ports", [])
        if isinstance(value, Mapping)
        and isinstance(value.get("id"), int)
        and not isinstance(value.get("id"), bool)
    }
    conflicts: list[dict[str, object]] = []
    for port in abi:
        logical_port_id = int(port["port_id"])
        actual_port_id = int(port["actual_port_id"])
        fact = facts.get(actual_port_id)
        if fact is None:
            conflicts.append(
                {
                    "reason": "actual-port-id-absent-from-facts",
                    "port_id": logical_port_id,
                    "actual_port_id": actual_port_id,
                }
            )
            continue
        expected_fields = {
            "direction": port.get("direction"),
            "width": port.get("width"),
            "signed": port.get("signed"),
            "declared_role": port.get("semantic_role"),
        }
        for field, expected in expected_fields.items():
            if fact.get(field) != expected:
                conflicts.append(
                    {
                        "reason": f"logical-port-{field}-conflict",
                        "port_id": logical_port_id,
                        "actual_port_id": actual_port_id,
                        "expected": expected,
                        "actual": fact.get(field),
                    }
                )
    return conflicts


def _facts_with_declared_roles(
    document: Mapping[str, object],
    abi: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    roles = {
        int(value["actual_port_id"]): (
            int(value["port_id"]),
            str(value["semantic_role"]),
        )
        for value in abi
    }
    result = dict(document)
    ports: list[dict[str, object]] = []
    seen: set[int] = set()
    for value in document.get("ports", []):
        port = dict(_mapping(value, "reparse.ports[]"))
        port_id = int(port["id"])
        role_binding = roles.get(port_id)
        if role_binding is not None:
            logical_port_id, role = role_binding
            frontend_role = port.get("declared_role")
            if frontend_role not in ("uninterpreted_external", role):
                raise ValueError(
                    f"reparse.ports:{port_id}:declared-role-conflict:"
                    f"frontend={frontend_role}:declaration={role}"
                )
            port["frontend_declared_role"] = frontend_role
            port["declared_role"] = role
            port["declared_role_evidence_id"] = content_hash(
                {
                    "kind": "validated-composition-declaration",
                    "port_id": logical_port_id,
                    "actual_port_id": port_id,
                    "semantic_role": role,
                }
            )
            seen.add(port_id)
        ports.append(port)
    missing = sorted(set(roles) - seen)
    if missing:
        raise ValueError(
            "reparse.ports:declared-role-targets-missing:"
            + ",".join(str(port_id) for port_id in missing)
        )
    result["ports"] = ports
    result["declared_role_provenance"] = "composition_ir.external_ports"
    validate_contract(result, "hdl_facts.v2")
    return result


def _abi_with_validation_evidence(
    document: Mapping[str, object],
    abi: Sequence[Mapping[str, object]],
    top_module_id: int,
) -> list[dict[str, object]]:
    facts = {
        int(value["id"]): value
        for value in document.get("ports", [])
        if isinstance(value, Mapping)
        and isinstance(value.get("id"), int)
        and not isinstance(value.get("id"), bool)
    }
    result: list[dict[str, object]] = []
    for value in abi:
        port = dict(value)
        logical_port_id = int(port["port_id"])
        actual_port_id = int(port["actual_port_id"])
        fact = facts.get(actual_port_id)
        if fact is None:
            raise ValueError(
                f"top_port_abi:{logical_port_id}:actual-port-id-missing:{actual_port_id}"
            )
        port["validation_evidence_id"] = content_hash(
            {
                "top_module_id": top_module_id,
                "logical_port_id": logical_port_id,
                "actual": {
                    "actual_port_id": actual_port_id,
                    "emitted_name": port["emitted_name"],
                    "direction": fact.get("direction"),
                    "width": fact.get("width"),
                    "signed": fact.get("signed"),
                    "declared_role": fact.get("declared_role"),
                },
            }
        )
        result.append(port)
    return sorted(result, key=lambda item: int(item["port_id"]))


def _portable_value(value: object, replacements: Sequence[tuple[str, str]]) -> object:
    if isinstance(value, Mapping):
        return {str(key): _portable_value(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_portable_value(item, replacements) for item in value]
    if isinstance(value, str):
        result = value
        for source, replacement in replacements:
            if source:
                result = result.replace(source, replacement)
        return result
    return value


def _portable_facts(
    document: Mapping[str, object],
    source_root: Path,
    generated_top: Path | None = None,
    *,
    generated_source_name: str = "generated_top.sv",
) -> Mapping[str, object]:
    replacements: list[tuple[str, str]] = []
    if generated_top is not None:
        replacements.append((generated_top.resolve().as_posix(), generated_source_name))
    replacements.append((source_root.resolve().as_posix() + "/", ""))
    result = _portable_value(document, replacements)
    return _mapping(result, "portable_facts")


def _coverage_universe(
    document: Mapping[str, object],
    source_root: Path,
    artifact_kind: str,
) -> list[dict[str, object]]:
    records: dict[str, tuple[Mapping[str, object], str]] = {}
    for value in document.get("source_locations", []):
        if not isinstance(value, Mapping):
            continue
        file_value = value.get("file", "unknown")
        file_label = Path(str(file_value).replace("\\", "/")).name
        if isinstance(file_value, str):
            candidate = Path(file_value)
            if candidate.is_absolute():
                try:
                    file_label = candidate.resolve().relative_to(source_root.resolve()).as_posix()
                except ValueError:
                    file_label = candidate.name
            elif file_value:
                file_label = file_value.replace("\\", "/")
        semantic = {
            "kind": value.get("kind"),
            "file": file_label,
            "line": value.get("line"),
            "column": value.get("column"),
        }
        stable_source_id = content_hash(semantic)
        records.setdefault(stable_source_id, (value, file_label))
    if not records:
        stable_source_id = content_hash(
            {"input_hash": _tool_input_hash(document, artifact_kind)}
        )
        records[stable_source_id] = (
            {"entity_id": 1, "line": 1, "column": 0},
            "unknown.sv",
        )

    result: list[dict[str, object]] = []
    for point_id, (stable_source_id, (value, file_label)) in enumerate(
        sorted(records.items()), 1
    ):
        file_hash = hashlib.sha256(file_label.encode("utf-8")).hexdigest()
        result.append(
            {
                "point_id": point_id,
                "stable_source_id": stable_source_id,
                "component_id": max(1, int(value.get("entity_id", 1))),
                "component_role": artifact_kind,
                "source": {
                    "file_id": max(1, int(file_hash[:8], 16)),
                    "line": max(1, int(value.get("line", 1))),
                    "column": max(0, int(value.get("column", 0))),
                },
                "provenance": "frontend-structural-location",
            }
        )
    return result


def _flat_composition_ir(
    document: Mapping[str, object],
    declarations: object,
    dut_input_hash: str,
) -> dict[str, object]:
    facts_by_id = {
        int(value["id"]): value
        for value in document.get("ports", [])
        if isinstance(value, Mapping)
        and isinstance(value.get("id"), int)
        and not isinstance(value.get("id"), bool)
    }
    components = sorted(getattr(declarations, "components"), key=lambda item: item.id)
    component_records = [
        {"id": component.id, "module_id": component.module_id, "role": component.role}
        for component in components
    ]
    external_ports: list[dict[str, object]] = []
    for component in components:
        for declaration in component.ports:
            port_id = int(declaration.port_id)
            fact = facts_by_id.get(port_id)
            if fact is None:
                raise ValueError(f"flat_baseline.port:{port_id}:fact-missing")
            external_ports.append(
                {
                    "port_id": port_id,
                    "component_id": component.id,
                    "direction": fact["direction"],
                    "width": fact["width"],
                    "signed": fact["signed"],
                    "semantic_role": declaration.role,
                }
            )

    graph_hash = content_hash(
        {
            "mode": "flat-direct",
            "dut_input_hash": dut_input_hash,
            "components": component_records,
            "external_ports": external_ports,
        }
    )
    return {
        "schema_version": "composition_ir.v1",
        "candidate_id": "flat-baseline-" + graph_hash[7:23],
        "parent_input_hash": dut_input_hash,
        "graph_hash": graph_hash,
        "components": component_records,
        "instances": [
            {
                "id": component.id,
                "component_id": component.id,
                "module_id": component.module_id,
                "role": component.role,
            }
            for component in components
        ],
        "nets": [],
        "endpoint_bindings": [
            {
                "endpoint_id": binding.id,
                "component_id": component.id,
                "protocol_id": binding.protocol_id,
                "version": binding.version,
                "side": binding.side,
                "parameters": dict(binding.parameters),
                "fields": [
                    {
                        "field_role": field.field_role,
                        "port_id": field.port_id,
                        "direction": facts_by_id[field.port_id]["direction"],
                        "width": facts_by_id[field.port_id]["width"],
                        "signed": facts_by_id[field.port_id]["signed"],
                    }
                    for field in binding.fields
                ],
            }
            for component in components
            for binding in component.protocol_bindings
        ],
        "adapters": [],
        "address_regions": [],
        "clock_domains": [
            {
                "component_id": component.id,
                "port_id": item.port_id,
                "domain_id": item.domain_id,
                "active_level": item.active_level,
                "synchronous": item.synchronous,
            }
            for component in components
            for item in component.clock_reset
            if item.kind == "clock"
        ],
        "reset_domains": [
            {
                "component_id": component.id,
                "port_id": item.port_id,
                "domain_id": item.domain_id,
                "active_level": item.active_level,
                "synchronous": item.synchronous,
            }
            for component in components
            for item in component.clock_reset
            if item.kind == "reset"
        ],
        "external_ports": sorted(external_ports, key=lambda item: int(item["port_id"])),
        "unresolved_optional_endpoints": [],
        "evidence": [],
        "assumptions": [],
        "rejected_alternatives": [],
        "score_vector": [],
        "diagnostics": {"errors": [], "warnings": []},
    }


def _source_composition(
    source_root: Path,
    sources: Sequence[str],
) -> list[dict[str, str]]:
    source_composition: list[dict[str, str]] = []
    for source_value in sources:
        source = Path(source_value)
        try:
            label = source.resolve().relative_to(source_root.resolve()).as_posix()
        except ValueError:
            label = source.name
        digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
        source_composition.append({"source": label, "content_hash": digest})
    source_composition.sort(key=lambda item: item["source"])
    if not source_composition:
        raise ValueError("flat_baseline.sources:empty")
    return source_composition


def _flat_baseline(
    frontend: FrontendLibrary,
    ir_document: Mapping[str, object],
    source_symbols: Sequence[Mapping[str, object]],
    source_root: Path,
    sources: Sequence[str],
    verilator_args: Sequence[str],
    dut_input_hash: str,
    working_root: Path,
) -> tuple[dict[str, object], str]:
    build_result = _mapping(frontend.composition(ir_document, source_symbols), "flat_builder")
    if not _build_is_valid(build_result):
        raise ValueError(
            "flat_baseline.builder:invalid:"
            + json.dumps(_diagnostics(build_result, "flat_builder"), sort_keys=True)
        )
    source_text = str(build_result["source_text"])
    flat_build_dir = working_root / ".flat-baseline"
    flat_build_dir.mkdir()
    flat_top = flat_build_dir / "flat_top.sv"
    flat_top.write_text(source_text, encoding="utf-8")
    reparsed = _mapping(
        frontend.facts(
            [
                "--lint-only",
                "-Wno-fatal",
                *verilator_args,
                *sources,
                flat_top.resolve().as_posix(),
                "--top-module",
                "composition_top",
            ],
            source_root,
        ),
        "flat_reparse",
    )
    validate_contract(reparsed, "hdl_facts.v2")
    _require_clean_facts(reparsed, "flat_reparse")
    reparsed = _portable_facts(
        reparsed,
        source_root,
        flat_top,
        generated_source_name="flat_top.sv",
    )
    top_port_abi, top_module_id, abi_diagnostics = _actual_top_port_abi(
        reparsed,
        ir_document,
    )
    if top_port_abi is None or top_module_id is None:
        raise ValueError(
            "flat_baseline.top_abi:invalid:"
            + json.dumps(abi_diagnostics, sort_keys=True)
        )
    reparsed = _facts_with_declared_roles(reparsed, top_port_abi)
    conflicts = _abi_facts_conflicts(reparsed, top_port_abi)
    if conflicts:
        raise ValueError(
            "flat_baseline.top_abi:facts-conflict:"
            + json.dumps(conflicts, sort_keys=True)
        )
    top_port_abi = _abi_with_validation_evidence(reparsed, top_port_abi, top_module_id)
    source_composition = _source_composition(source_root, sources)
    flat_source = {
        "source": "flat_top.sv",
        "content_hash": "sha256:" + hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
    }
    source_composition.append(flat_source)
    source_composition.sort(key=lambda item: item["source"])
    coverage = _coverage_universe(reparsed, source_root, "flat-baseline")
    diagnostics = {
        "errors": [],
        "warnings": [
            *_diagnostics(build_result, "flat_builder")["warnings"],
            *_diagnostics(reparsed, "flat_reparse")["warnings"],
        ],
        "unsupported": [],
    }
    return {
        "schema_version": "flat_baseline.v1",
        "baseline_id": str(ir_document["candidate_id"]),
        "dut_input_hash": dut_input_hash,
        "combinational_design": not any(
            port["semantic_role"] in ("clock", "reset") for port in top_port_abi
        ),
        "top": {
            "module": "composition_top",
            "source": flat_source["source"],
            "content_hash": flat_source["content_hash"],
        },
        "source_composition": source_composition,
        "top_port_abi": sorted(top_port_abi, key=lambda item: int(item["port_id"])),
        "coverage_universe": coverage,
        "coverage_universe_id": content_hash({"coverage_universe": coverage}),
        "diagnostics": diagnostics,
    }, source_text


def _publish_directory_no_replace(staging: Path, destination: Path) -> None:
    """Atomically publish a directory and fail if the destination already exists."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOTSUP, "atomic no-replace directory publication is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(staging),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (errno.EEXIST, errno.ENOTEMPTY):
        raise FileExistsError(error_number, "output directory already exists", destination)
    raise OSError(error_number, os.strerror(error_number), destination)


def _write_json(path: Path, document: object) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_composition_facts(
    config_path: Path,
    output_path: Path,
    *,
    frontend_library: Path | None = None,
) -> dict[str, object]:
    """Parse the exact declared composition sources and persist clean HDL facts."""
    config_path = Path(config_path).resolve()
    output_path = Path(output_path).absolute()
    config = _mapping(_read_json(config_path, "config"), "config")
    source_root, sources, verilator_args = _source_inputs(config_path, config)
    library_path = Path(frontend_library or default_frontend_library(_REPO_ROOT)).resolve()
    if not library_path.is_file():
        raise FileNotFoundError(
            f"myfuzz frontend library not built: {library_path}. "
            "Build it with src/myfuzz/frontend/scripts/build_frontend.sh"
        )
    os.environ.setdefault(
        "MYFUZZ_FRONTEND_VERILATOR_ROOT",
        (_REPO_ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator").as_posix(),
    )
    facts = _mapping(
        FrontendLibrary(library_path).facts(
            ["--lint-only", *verilator_args, *sources],
            source_root,
        ),
        "frontend",
    )
    validate_contract(facts, "hdl_facts.v2")
    _require_clean_facts(facts, "frontend")
    document = dict(facts)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(output_path, document)
    return document


def generate_compositions(
    config_path: Path,
    frontend_path: Path,
    top_k: int,
    out_dir: Path,
    *,
    frontend_library: Path | None = None,
) -> dict[str, object]:
    """Generate and atomically publish all valid candidates from a bounded Top-K search."""
    config_path = Path(config_path).resolve()
    frontend_path = Path(frontend_path).resolve()
    out_dir = Path(out_dir).absolute()
    if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k <= 0:
        raise ValueError("top_k:positive-integer-required")
    if top_k > 100:
        raise ValueError("top_k:maximum-100")
    if out_dir.exists():
        raise FileExistsError(f"output directory already exists: {out_dir}")

    config = _mapping(_read_json(config_path, "config"), "config")
    instrumentation = _mapping(config.get("instrumentation", {}), "instrumentation")
    declarations = load_declarations(config_path)
    protocols = _protocols(config)
    source_root, sources, verilator_args = _source_inputs(config_path, config)
    supplied_facts = _mapping(_read_json(frontend_path, "frontend"), "frontend")
    validate_contract(supplied_facts, "hdl_facts.v2")
    _require_clean_facts(supplied_facts, "frontend")
    library_path = Path(frontend_library or default_frontend_library(_REPO_ROOT)).resolve()
    if not library_path.is_file():
        raise FileNotFoundError(
            f"myfuzz frontend library not built: {library_path}. "
            "Build it with src/myfuzz/frontend/scripts/build_frontend.sh"
        )
    os.environ.setdefault(
        "MYFUZZ_FRONTEND_VERILATOR_ROOT",
        (_REPO_ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator").as_posix(),
    )
    frontend = FrontendLibrary(library_path)
    current_facts = _mapping(
        frontend.facts(
            ["--lint-only", *verilator_args, *sources],
            source_root,
        ),
        "current_frontend",
    )
    validate_contract(current_facts, "hdl_facts.v2")
    _require_clean_facts(current_facts, "current_frontend")
    supplied_input_hash = _tool_input_hash(supplied_facts, "frontend")
    dut_input_hash = _tool_input_hash(current_facts, "current_frontend")
    if supplied_input_hash != dut_input_hash:
        raise ValueError(
            "frontend.tool.input_hash:mismatch:"
            f"supplied={supplied_input_hash}:current={dut_input_hash}"
        )
    facts = normalize_facts(current_facts)
    source_symbols = _source_symbols(current_facts)
    tool = _mapping(current_facts.get("tool"), "current_frontend.tool")
    tool_versions = {
        str(key): value
        for key, value in tool.items()
        if key != "input_hash"
    }
    schema_versions = {
        "candidate_manifest": "candidate_manifest.v1",
        "composition_build_result": "composition_build_result.v1",
        "composition_ir": "composition_ir.v1",
        "hdl_facts": str(current_facts["schema_version"]),
    }
    compile_args = [
        "--lint-only",
        "-Wno-fatal",
        *verilator_args,
        "--top-module",
        "composition_top",
    ]
    flat_ir_document = _flat_composition_ir(current_facts, declarations, dut_input_hash)
    validate_contract(flat_ir_document, "composition_ir.v1")

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".myfuzz-composition-", dir=out_dir.parent) as tmp:
        staging_root = Path(tmp) / "output"
        staging_root.mkdir()
        flat_baseline, flat_source_text = _flat_baseline(
            frontend,
            flat_ir_document,
            source_symbols,
            source_root,
            sources,
            verilator_args,
            dut_input_hash,
            Path(tmp),
        )
        published: list[dict[str, object]] = []
        rejected: list[dict[str, object]] = []
        attempted_graph_hashes: set[str] = set()
        while len(published) < top_k:
            remaining = top_k - len(published)
            batch = tuple(
                compose_topk(
                    facts,
                    declarations,
                    protocols,
                    remaining,
                    excluded_graph_hashes=attempted_graph_hashes,
                )
            )
            batch = tuple(
                candidate
                for candidate in batch
                if candidate.graph_hash not in attempted_graph_hashes
            )
            if not batch:
                break
            for candidate in batch:
                attempted_graph_hashes.add(candidate.graph_hash)
                candidate_name = candidate.candidate_id
                if _SAFE_CANDIDATE_DIRECTORY.fullmatch(candidate_name) is None:
                    raise ValueError("candidate_id:unsafe-directory")
                ir_document = composition_ir(candidate)
                validate_contract(ir_document, "composition_ir.v1")
                adapter_conflicts = [
                    adapter
                    for adapter in ir_document["adapters"]
                    if isinstance(adapter, Mapping)
                    and adapter.get("shape_status") == "irreducible"
                ]
                if adapter_conflicts:
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "handoff",
                            "diagnostics": {
                                "reason": "irreducible-adapter-shape",
                                "adapters": adapter_conflicts,
                            },
                        }
                    )
                    continue

                try:
                    build_result = _mapping(
                        frontend.composition(ir_document, source_symbols),
                        "builder",
                    )
                    builder_diagnostics = _diagnostics(build_result, "builder")
                    builder_validation = _mapping(
                        build_result.get("validation"),
                        "builder.validation",
                    )
                except Exception as error:
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "builder",
                            "diagnostics": {
                                "exception": str(error),
                                "errors": [],
                                "warnings": [],
                                "unsupported": [],
                            },
                        }
                    )
                    continue
                if not _build_is_valid(build_result):
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "builder",
                            "diagnostics": builder_diagnostics,
                            "validation": dict(builder_validation),
                        }
                    )
                    continue

                source_text = str(build_result["source_text"])
                candidate_dir = staging_root / candidate_name
                candidate_dir.mkdir()
                generated_top = candidate_dir / "generated_top.sv"
                generated_top.write_text(source_text, encoding="utf-8")
                (candidate_dir / "flat_top.sv").write_text(
                    flat_source_text,
                    encoding="utf-8",
                )
                reparse_args = [
                    "--lint-only",
                    "-Wno-fatal",
                    *verilator_args,
                    *sources,
                    generated_top.resolve().as_posix(),
                    "--top-module",
                    "composition_top",
                ]
                raw_reparsed: Mapping[str, object] | None = None
                try:
                    raw_reparsed = _mapping(frontend.facts(reparse_args, source_root), "reparse")
                    validate_contract(raw_reparsed, "hdl_facts.v2")
                    _require_clean_facts(raw_reparsed, "reparse")
                    reparsed = _portable_facts(raw_reparsed, source_root, generated_top)
                except Exception as error:
                    reparse_diagnostics: object = {
                        "errors": [],
                        "warnings": [],
                        "unsupported": [],
                        "exception": str(error),
                    }
                    if raw_reparsed is not None:
                        try:
                            reparse_diagnostics = {
                                **dict(_diagnostics(raw_reparsed, "reparse")),
                                "exception": str(error),
                            }
                        except Exception:
                            pass
                    reparse_diagnostics = _portable_value(
                        reparse_diagnostics,
                        (
                            (generated_top.resolve().as_posix(), "generated_top.sv"),
                            (source_root.resolve().as_posix() + "/", ""),
                        ),
                    )
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "reparse",
                            "diagnostics": reparse_diagnostics,
                        }
                    )
                    continue

                try:
                    top_port_abi, top_module_id, abi_diagnostics = _actual_top_port_abi(
                        reparsed,
                        ir_document,
                    )
                except Exception as error:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "top-abi",
                            "diagnostics": {"exception": str(error)},
                        }
                    )
                    continue
                if top_port_abi is None or top_module_id is None:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "top-abi",
                            "diagnostics": abi_diagnostics,
                        }
                    )
                    continue
                try:
                    reparsed = _facts_with_declared_roles(reparsed, top_port_abi)
                    handoff_conflicts = _abi_facts_conflicts(reparsed, top_port_abi)
                    top_port_abi = _abi_with_validation_evidence(
                        reparsed,
                        top_port_abi,
                        top_module_id,
                    )
                except Exception as error:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "role-validation",
                            "diagnostics": {"exception": str(error)},
                        }
                    )
                    continue
                if handoff_conflicts:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "handoff",
                            "diagnostics": {
                                "reason": "logical-abi-facts-conflict",
                                "conflicts": handoff_conflicts,
                            },
                        }
                    )
                    continue

                try:
                    reparse_diagnostics = _diagnostics(reparsed, "reparse")
                    facts_descriptor = {
                        "source": "hdl_facts.json",
                        "content_hash": content_hash(reparsed),
                        "input_hash": _tool_input_hash(reparsed, "reparse"),
                        "top_module_id": top_module_id,
                    }
                except Exception as error:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "post-reparse",
                            "diagnostics": {"exception": str(error)},
                        }
                    )
                    continue
                try:
                    coverage_universe = _coverage_universe(
                        reparsed,
                        source_root,
                        "candidate",
                    )
                except Exception as error:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "coverage",
                            "diagnostics": {"exception": str(error)},
                        }
                    )
                    continue
                manifest_diagnostics = {
                    "errors": [],
                    "warnings": [
                        *builder_diagnostics["warnings"],
                        *reparse_diagnostics["warnings"],
                    ],
                    "unsupported": [],
                }
                try:
                    manifest = candidate_manifest(
                        candidate,
                        {
                            "source_text": source_text,
                            "module": "composition_top",
                            "source": "generated_top.sv",
                            "dut_input_hash": dut_input_hash,
                            "lifecycle": "top_validated",
                            "top_port_abi": top_port_abi,
                            "combinational_design": not any(
                                port["semantic_role"] in ("clock", "reset")
                                for port in top_port_abi
                            ),
                            "endpoint_bindings": ir_document["endpoint_bindings"],
                            "external_ports": ir_document["external_ports"],
                            "flat_baseline": flat_baseline,
                            "hdl_facts": facts_descriptor,
                            "coverage_universe": coverage_universe,
                            "tool_versions": tool_versions,
                            "schema_versions": schema_versions,
                            "instrumentation": instrumentation,
                            "compile_args": compile_args,
                            "diagnostics": manifest_diagnostics,
                            "validation": {
                                "status": "valid",
                                "parse": "passed",
                                "elaboration": "passed",
                                "link": "passed",
                                "width": "passed",
                                "compile": "pending",
                                "smoke": "pending",
                                "evidence": {
                                    "builder": dict(builder_validation),
                                    "reparse": {
                                        "hdl_facts_input_hash": facts_descriptor["input_hash"],
                                        "hdl_facts_content_hash": facts_descriptor["content_hash"],
                                        "top_module_id": top_module_id,
                                        "top_port_abi": abi_diagnostics["actual"],
                                    },
                                },
                            },
                        },
                    )
                    validate_contract(manifest, "candidate_manifest.v1")
                except Exception as error:
                    shutil.rmtree(candidate_dir)
                    rejected.append(
                        {
                            "candidate_id": candidate_name,
                            "graph_hash": candidate.graph_hash,
                            "stage": "manifest",
                            "diagnostics": {"exception": str(error)},
                        }
                    )
                    continue
                diagnostics_document = {
                    "builder": builder_diagnostics,
                    "builder_validation": dict(builder_validation),
                    "reparse": reparse_diagnostics,
                    "top_abi": abi_diagnostics,
                }
                _write_json(candidate_dir / "composition_ir.json", ir_document)
                _write_json(candidate_dir / "candidate_manifest.json", manifest)
                _write_json(candidate_dir / "hdl_facts.json", reparsed)
                _write_json(candidate_dir / "flat_baseline.json", flat_baseline)
                _write_json(candidate_dir / "diagnostics.json", diagnostics_document)
                (candidate_dir / "graph_hash.txt").write_text(
                    candidate.graph_hash + "\n",
                    encoding="ascii",
                )
                published.append(
                    {
                        "candidate_id": candidate_name,
                        "directory": candidate_name,
                        "graph_hash": candidate.graph_hash,
                        "composition_ir_hash": manifest["composition_ir_hash"],
                        "manifest_hash": content_hash(manifest),
                        "hdl_facts_hash": facts_descriptor["content_hash"],
                    }
                )
                if len(published) == top_k:
                    break

        complete = len(published) == top_k
        summary: dict[str, object] = {
            "schema_version": "composition_generation_summary.v1",
            "requested_top_k": top_k,
            "candidate_count": len(published),
            "attempted_candidate_count": len(attempted_graph_hashes),
            "complete": complete,
            "status": "complete" if complete else "incomplete",
            "candidates": published,
            "rejected_candidates": rejected,
        }
        _write_json(staging_root / "generation_summary.json", summary)
        _publish_directory_no_replace(staging_root, out_dir)
    return summary


__all__ = ["generate_compositions", "write_composition_facts"]
