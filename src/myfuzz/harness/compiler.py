"""Strict compatibility compiler for complete harness runtime bundles."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
import json
import os
from pathlib import Path
import tempfile

from myfuzz.contracts import canonical_bytes, content_hash, validate_contract
from myfuzz.dependency.csr import CsrGraph, to_csr
from myfuzz.dependency.dynamic import ActiveDependencyView
from myfuzz.dependency.graph import DependencyNode
from myfuzz.dependency.static import build_static_graph
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.compiler import compile_protocol
from myfuzz.protocols.model import CompiledProtocol, ProtocolPlugin

from .abi import RawBitAbi
from .depaware import build_depaware
from .direct import HarnessArtifact, build_direct
from .projection import ProjectionPlan, build_projection_plan


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{label} must be an array")
    return value


def _identifier(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer ID")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _diagnostics_clean(document: Mapping[str, object], label: str) -> None:
    diagnostics = _object(document.get("diagnostics"), f"{label}.diagnostics")
    errors = _array(diagnostics.get("errors"), f"{label}.diagnostics.errors")
    if errors:
        raise ValueError(f"{label}.diagnostics contains errors")
    if "unsupported" in diagnostics:
        unsupported = _array(
            diagnostics.get("unsupported"),
            f"{label}.diagnostics.unsupported",
        )
        if unsupported:
            raise ValueError(f"{label}.diagnostics contains unsupported constructs")


def _validate_runtime_evidence(
    facts: Mapping[str, object],
    composition: Mapping[str, object],
    manifest: Mapping[str, object],
) -> int:
    _diagnostics_clean(facts, "hdl_facts")
    _diagnostics_clean(composition, "composition_ir")
    _diagnostics_clean(manifest, "candidate_manifest")
    if manifest.get("lifecycle") != "top_validated":
        raise ValueError("candidate_manifest.lifecycle must be top_validated")
    validation = _object(manifest.get("validation"), "candidate_manifest.validation")
    if validation.get("status") != "valid":
        raise ValueError("candidate_manifest.validation.status must be valid")
    for phase in ("parse", "link", "width"):
        if validation.get(phase) != "passed":
            raise ValueError(f"candidate_manifest.validation.{phase} must be passed")
    if validation.get("elaboration") != "passed":
        raise ValueError("candidate_manifest.validation.elaboration must be passed")
    for phase in ("compile", "smoke"):
        if validation.get(phase) not in {"pending", "passed"}:
            raise ValueError(
                f"candidate_manifest.validation.{phase} must be pending or passed"
            )

    descriptor = _object(manifest.get("hdl_facts"), "candidate_manifest.hdl_facts")
    _string(descriptor.get("source"), "candidate_manifest.hdl_facts.source")
    expected_content_hash = content_hash(facts)
    if descriptor.get("content_hash") != expected_content_hash:
        raise ValueError("candidate_manifest.hdl_facts.content_hash is stale")
    tool = _object(facts.get("tool"), "hdl_facts.tool")
    input_hash = _string(tool.get("input_hash"), "hdl_facts.tool.input_hash")
    if descriptor.get("input_hash") != input_hash:
        raise ValueError("candidate_manifest.hdl_facts.input_hash is stale")
    top_module_id = _identifier(
        descriptor.get("top_module_id"),
        "candidate_manifest.hdl_facts.top_module_id",
    )

    evidence = _object(validation.get("evidence"), "candidate_manifest.validation.evidence")
    reparse = _object(evidence.get("reparse"), "candidate_manifest.validation.evidence.reparse")
    expected_reparse = {
        "hdl_facts_content_hash": expected_content_hash,
        "hdl_facts_input_hash": input_hash,
        "top_module_id": top_module_id,
    }
    for key, expected in expected_reparse.items():
        if reparse.get(key) != expected:
            raise ValueError(
                f"candidate_manifest.validation.evidence.reparse.{key} is stale"
            )
    return top_module_id


def _facts_ports(hdl_facts: Mapping[str, object]) -> dict[int, Mapping[str, object]]:
    result: dict[int, Mapping[str, object]] = {}
    for index, value in enumerate(_array(hdl_facts.get("ports"), "hdl_facts.ports")):
        port = _object(value, f"hdl_facts.ports[{index}]")
        port_id = _identifier(port.get("id"), f"hdl_facts.ports[{index}].id")
        if port_id in result:
            raise ValueError(f"duplicate HDL fact port ID: {port_id}")
        result[port_id] = port
    return result


def _abi_records(
    values: object,
    label: str,
    *,
    id_key: str,
) -> dict[int, Mapping[str, object]]:
    result: dict[int, Mapping[str, object]] = {}
    for index, value in enumerate(_array(values, label)):
        port = _object(value, f"{label}[{index}]")
        port_id = _identifier(port.get(id_key), f"{label}[{index}].{id_key}")
        if port_id in result:
            raise ValueError(f"{label} contains duplicate ABI port ID: {port_id}")
        direction = port.get("direction")
        if direction not in {"input", "output", "inout"}:
            raise ValueError(f"{label}[{index}].direction is invalid")
        width = port.get("width")
        if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
            raise ValueError(f"{label}[{index}].width is invalid")
        result[port_id] = port
    return result


def _abi_semantic_role(
    port: Mapping[str, object],
    key: str,
    label: str,
) -> str:
    role = port.get(key)
    if not isinstance(role, str) or not role:
        raise ValueError(f"ABI semantic_role is missing from {label}")
    return role


def _active_level(value: object, label: str) -> int:
    if value == "high":
        return 1
    if value == "low":
        return 0
    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"ABI control active_level is invalid for {label}")
    return int(value)


def _composition_controls(
    composition: Mapping[str, object],
) -> dict[int, tuple[str, int, int, int, bool]]:
    controls: dict[int, tuple[str, int, int, int, bool]] = {}
    for section, role in (("clock_domains", "clock"), ("reset_domains", "reset")):
        for index, value in enumerate(
            _array(composition.get(section), f"composition_ir.{section}")
        ):
            label = f"composition_ir.{section}[{index}]"
            record = _object(value, label)
            port_id = _identifier(record.get("port_id"), f"{label}.port_id")
            if port_id in controls:
                raise ValueError(f"ABI control port ID {port_id} has duplicate domains")
            component_id = _identifier(
                record.get("component_id"),
                f"{label}.component_id",
            )
            domain_id = _identifier(record.get("domain_id"), f"{label}.domain_id")
            synchronous = record.get("synchronous")
            if not isinstance(synchronous, bool):
                raise ValueError(f"ABI control synchronous is invalid for port ID {port_id}")
            controls[port_id] = (
                role,
                component_id,
                domain_id,
                _active_level(record.get("active_level"), f"port ID {port_id}"),
                synchronous,
            )
    return controls


def _validate_control_facts(
    facts: Mapping[str, object],
    controls: Mapping[int, tuple[str, int, int, int, bool]],
    actual_to_logical: Mapping[int, int],
) -> None:
    for index, value in enumerate(
        _array(facts.get("clock_reset_checks"), "hdl_facts.clock_reset_checks")
    ):
        label = f"hdl_facts.clock_reset_checks[{index}]"
        record = _object(value, label)
        if record.get("structurally_validated") is not True:
            continue
        port_id = record.get("port_id")
        if isinstance(port_id, bool) or not isinstance(port_id, int):
            raise ValueError(f"ABI control fact has invalid port ID at {label}")
        logical_port_id = actual_to_logical.get(port_id)
        if logical_port_id is None:
            continue
        expected = controls.get(logical_port_id)
        if expected is None:
            continue
        role, component_id, domain_id, active_level, synchronous = expected
        if (
            record.get("kind") != role
            or record.get("component_id") != component_id
            or record.get("domain_id") != domain_id
        ):
            raise ValueError(
                f"ABI control fact mismatch for port ID {logical_port_id}"
            )
        if "active_level" in record and _active_level(
            record.get("active_level"),
            f"fact port ID {port_id}",
        ) != active_level:
            raise ValueError(
                f"ABI control active_level mismatch for port ID {logical_port_id}"
            )
        if "synchronous" in record and record.get("synchronous") is not synchronous:
            raise ValueError(
                f"ABI control synchronous mismatch for port ID {logical_port_id}"
            )


def _top_module_abi(
    facts: Mapping[str, object],
    manifest: Mapping[str, object],
    top_module_id: int,
) -> tuple[int, set[int], dict[int, str]]:
    modules: dict[int, Mapping[str, object]] = {}
    for index, value in enumerate(_array(facts.get("modules"), "hdl_facts.modules")):
        label = f"hdl_facts.modules[{index}]"
        module = _object(value, label)
        module_id = _identifier(module.get("id"), f"{label}.id")
        if module_id in modules:
            raise ValueError(f"duplicate HDL fact module ID: {module_id}")
        modules[module_id] = module

    top = _object(manifest.get("top"), "candidate_manifest.top")
    top_name = _string(top.get("module"), "candidate_manifest.top.module")
    top_module_names: list[str] = []
    port_names: dict[int, str] = {}
    duplicate_port_symbols: set[int] = set()
    for index, value in enumerate(
        _array(facts.get("source_symbols"), "hdl_facts.source_symbols")
    ):
        label = f"hdl_facts.source_symbols[{index}]"
        record = _object(value, label)
        kind = record.get("kind")
        if kind not in {"module", "port"}:
            continue
        entity_id = _identifier(record.get("entity_id"), f"{label}.entity_id")
        name = _string(record.get("name"), f"{label}.name")
        if kind == "module" and entity_id == top_module_id:
            top_module_names.append(name)
        elif kind == "port":
            if entity_id in port_names:
                duplicate_port_symbols.add(entity_id)
            else:
                port_names[entity_id] = name

    if len(top_module_names) != 1:
        raise ValueError(
            f"candidate_manifest.hdl_facts.top_module_id {top_module_id} "
            "must have exactly one module source symbol"
        )
    if top_module_names[0] != top_name:
        raise ValueError("candidate top module name does not match numeric top_module_id")
    top_module = modules.get(top_module_id)
    if top_module is None or top_module.get("top") is not True:
        raise ValueError(f"candidate top module {top_name!r} is not the validated top module")
    top_port_ids = {
        _identifier(item, f"hdl_facts top module ports[{index}]")
        for index, item in enumerate(
            _array(top_module.get("ports"), "hdl_facts top module ports")
        )
    }
    if duplicate_port_symbols & top_port_ids:
        duplicate = min(duplicate_port_symbols & top_port_ids)
        raise ValueError(f"actual_port_id {duplicate} has duplicate port source symbols")
    return top_module_id, top_port_ids, port_names


def _validation_evidence_id(
    top_module_id: int,
    logical_port_id: int,
    manifest_port: Mapping[str, object],
    fact: Mapping[str, object],
) -> str:
    """Match A's canonical evidence over the final, enriched HDL fact record."""
    actual_port_id = _identifier(
        manifest_port.get("actual_port_id"),
        f"candidate_manifest port ID {logical_port_id}.actual_port_id",
    )
    return content_hash(
        {
            "top_module_id": top_module_id,
            "logical_port_id": logical_port_id,
            "actual": {
                "actual_port_id": actual_port_id,
                "emitted_name": manifest_port.get("emitted_name"),
                "direction": fact.get("direction"),
                "width": fact.get("width"),
                "signed": fact.get("signed"),
                "declared_role": fact.get("declared_role"),
            },
        }
    )


def _validate_candidate_abi(
    facts: Mapping[str, object],
    composition: Mapping[str, object],
    manifest: Mapping[str, object],
    top_module_id: int,
) -> dict[int, int]:
    fact_abi = _facts_ports(facts)
    composition_abi = _abi_records(
        composition.get("external_ports"),
        "composition_ir.external_ports",
        id_key="port_id",
    )
    manifest_abi = _abi_records(
        manifest.get("top_port_abi"),
        "candidate_manifest.top_port_abi",
        id_key="port_id",
    )
    if set(composition_abi) != set(manifest_abi):
        raise ValueError("ABI port IDs differ between composition_ir and candidate_manifest")
    top_module_id, top_port_ids, port_names = _top_module_abi(
        facts,
        manifest,
        top_module_id,
    )
    controls = _composition_controls(composition)
    actual_to_logical: dict[int, int] = {}
    for logical_port_id, manifest_port in manifest_abi.items():
        actual_port_id = _identifier(
            manifest_port.get("actual_port_id"),
            f"candidate_manifest port ID {logical_port_id}.actual_port_id",
        )
        if actual_port_id in actual_to_logical:
            raise ValueError(f"duplicate actual_port_id: {actual_port_id}")
        fact = fact_abi.get(actual_port_id)
        if fact is None:
            raise ValueError(
                f"actual_port_id {actual_port_id} for logical port ID "
                f"{logical_port_id} is absent from hdl_facts"
            )
        if (
            fact.get("module_id") != top_module_id
            or actual_port_id not in top_port_ids
        ):
            raise ValueError(
                f"actual_port_id {actual_port_id} is not a port of the top module"
            )
        emitted_name = _string(
            manifest_port.get("emitted_name"),
            f"candidate_manifest port ID {logical_port_id}.emitted_name",
        )
        if port_names.get(actual_port_id) != emitted_name:
            raise ValueError(
                f"emitted_name mismatch for logical port ID {logical_port_id}"
            )
        actual_to_logical[actual_port_id] = logical_port_id

    unexpected_actual_ports = sorted(top_port_ids - set(actual_to_logical))
    if unexpected_actual_ports:
        raise ValueError(
            "unexpected actual top port IDs: "
            + ", ".join(str(port_id) for port_id in unexpected_actual_ports)
        )

    _validate_control_facts(facts, controls, actual_to_logical)
    for port_id, declared in composition_abi.items():
        manifest_port = manifest_abi[port_id]
        actual_port_id = _identifier(
            manifest_port.get("actual_port_id"),
            f"candidate_manifest port ID {port_id}.actual_port_id",
        )
        fact = fact_abi[actual_port_id]
        if "component_id" not in manifest_port or (
            manifest_port.get("component_id") != declared.get("component_id")
        ):
            raise ValueError(f"ABI component mismatch for port ID {port_id}")
        fact_geometry = (fact.get("direction"), fact.get("width"))
        declared_geometry = (declared.get("direction"), declared.get("width"))
        manifest_geometry = (
            manifest_port.get("direction"),
            manifest_port.get("width"),
        )
        if fact_geometry != declared_geometry or manifest_geometry != declared_geometry:
            raise ValueError(f"ABI direction/width mismatch for port ID {port_id}")
        signed_values = (
            fact.get("signed"),
            declared.get("signed"),
            manifest_port.get("signed"),
        )
        if any(not isinstance(value, bool) for value in signed_values):
            raise ValueError(f"ABI signed value is missing for port ID {port_id}")
        if len(set(signed_values)) != 1:
            raise ValueError(f"ABI signed mismatch for port ID {port_id}")
        roles = (
            _abi_semantic_role(
                fact,
                "declared_role",
                f"hdl_facts actual port ID {actual_port_id}",
            ),
            _abi_semantic_role(
                declared,
                "semantic_role",
                f"composition_ir port ID {port_id}",
            ),
            _abi_semantic_role(
                manifest_port,
                "semantic_role",
                f"candidate_manifest port ID {port_id}",
            ),
        )
        if len(set(roles)) != 1:
            raise ValueError(f"ABI semantic_role mismatch for port ID {port_id}")
        role = roles[0]

        expected_evidence_id = _validation_evidence_id(
            top_module_id,
            port_id,
            manifest_port,
            fact,
        )
        if manifest_port.get("validation_evidence_id") != expected_evidence_id:
            raise ValueError(
                f"validation_evidence_id mismatch for port ID {port_id}"
            )

        control = controls.get(port_id)
        if role in {"clock", "reset"}:
            if control is None or control[0] != role:
                raise ValueError(f"ABI control declaration is missing for port ID {port_id}")
            if declared.get("direction") != "input" or declared.get("width") != 1:
                raise ValueError(f"ABI control geometry is invalid for port ID {port_id}")
            _, component_id, _, active_level, synchronous = control
            if "component_id" in declared and declared.get("component_id") != component_id:
                raise ValueError(f"ABI control component mismatch for port ID {port_id}")
            if _active_level(
                manifest_port.get("active_level"),
                f"manifest port ID {port_id}",
            ) != active_level:
                raise ValueError(f"ABI control active_level mismatch for port ID {port_id}")
            if manifest_port.get("synchronous") is not synchronous:
                raise ValueError(f"ABI control synchronous mismatch for port ID {port_id}")
            if role == "reset" and manifest_port.get("reset_value") != active_level:
                raise ValueError(f"ABI control reset_value mismatch for port ID {port_id}")
        elif control is not None:
            raise ValueError(f"ABI control role mismatch for port ID {port_id}")

        fuzzable = manifest_port.get("fuzzable")
        if not isinstance(fuzzable, bool):
            raise ValueError(f"ABI fuzz disposition is missing for port ID {port_id}")
        fuzz_capable = declared.get("direction") in {"input", "inout"} and role not in {
            "clock",
            "reset",
        }
        bound_value = manifest_port.get(
            "constant_value",
            manifest_port.get("reset_value"),
        )
        if fuzzable and not fuzz_capable:
            raise ValueError(f"ABI fuzz disposition mismatch for port ID {port_id}")
        if not fuzzable and fuzz_capable and bound_value is None:
            raise ValueError(f"ABI fuzz disposition mismatch for port ID {port_id}")
        expected_disposition = (
            "fuzz"
            if fuzzable
            else "control"
            if role in {"clock", "reset"}
            else "observe"
        )
        if manifest_port.get("fuzz_disposition") != expected_disposition:
            raise ValueError(f"ABI fuzz disposition mismatch for port ID {port_id}")
    undeclared_controls = sorted(set(controls) - set(composition_abi))
    if undeclared_controls:
        raise ValueError(
            "ABI control domain references non-external port IDs: "
            + ", ".join(str(port_id) for port_id in undeclared_controls)
        )
    return actual_to_logical


def _composition_logical_port_ids(composition: Mapping[str, object]) -> set[int]:
    logical_ids = set(
        _abi_records(
            composition.get("external_ports"),
            "composition_ir.external_ports",
            id_key="port_id",
        )
    )
    for binding_index, binding_value in enumerate(
        _array(composition.get("endpoint_bindings"), "composition_ir.endpoint_bindings")
    ):
        binding = _object(
            binding_value,
            f"composition_ir.endpoint_bindings[{binding_index}]",
        )
        for field_index, field_value in enumerate(
            _array(
                binding.get("fields"),
                f"composition_ir.endpoint_bindings[{binding_index}].fields",
            )
        ):
            field = _object(
                field_value,
                f"composition_ir.endpoint_bindings[{binding_index}].fields[{field_index}]",
            )
            logical_ids.add(
                _identifier(
                    field.get("port_id"),
                    f"composition_ir.endpoint_bindings[{binding_index}].fields[{field_index}].port_id",
                )
            )
    for section in ("clock_domains", "reset_domains"):
        for index, value in enumerate(_array(composition.get(section), f"composition_ir.{section}")):
            record = _object(value, f"composition_ir.{section}[{index}]")
            logical_ids.add(
                _identifier(record.get("port_id"), f"composition_ir.{section}[{index}].port_id")
            )
    for index, value in enumerate(
        _array(
            composition.get("external_endpoint_port_ids", ()),
            "composition_ir.external_endpoint_port_ids",
        )
    ):
        logical_ids.add(
            _identifier(value, f"composition_ir.external_endpoint_port_ids[{index}]")
        )
    for index, value in enumerate(_array(composition.get("adapters"), "composition_ir.adapters")):
        adapter = _object(value, f"composition_ir.adapters[{index}]")
        for key in ("source_port_id", "target_port_id"):
            logical_ids.add(
                _identifier(adapter.get(key), f"composition_ir.adapters[{index}].{key}")
            )
    return logical_ids


def _complete_port_id_map(
    facts: Mapping[str, object],
    composition: Mapping[str, object],
    top_actual_to_logical: Mapping[int, int],
) -> dict[int, int]:
    logical_ids = _composition_logical_port_ids(composition)
    result = dict(top_actual_to_logical)
    for actual_port_id in sorted(_facts_ports(facts)):
        if actual_port_id in result:
            continue
        if actual_port_id not in logical_ids:
            raise ValueError(f"unmapped actual port ID: {actual_port_id}")
        result[actual_port_id] = actual_port_id
    return result


def _compiled_protocols(
    hdl_facts: Mapping[str, object],
    composition_ir: Mapping[str, object],
    protocols: Mapping[str, ProtocolPlugin],
    *,
    port_id_map: Mapping[int, int] | None = None,
) -> tuple[CompiledProtocol, ...]:
    plugins = _protocol_plugins(protocols)
    fact_ports = _facts_ports(hdl_facts)
    facts_by_logical_port: dict[int, list[Mapping[str, object]]] = {}
    for actual_port_id, fact in fact_ports.items():
        logical_port_id = (
            actual_port_id
            if port_id_map is None
            else port_id_map.get(actual_port_id, actual_port_id)
        )
        facts_by_logical_port.setdefault(logical_port_id, []).append(fact)
    catalog = ProtocolCatalog(tuple(plugins.values()))
    external_ports = _abi_records(
        composition_ir.get("external_ports", ()),
        "composition_ir.external_ports",
        id_key="port_id",
    )
    compiled: list[tuple[int, CompiledProtocol]] = []
    bindings = _array(
        composition_ir.get("endpoint_bindings"),
        "composition_ir.endpoint_bindings",
    )
    for index, value in enumerate(bindings):
        label = f"composition_ir.endpoint_bindings[{index}]"
        binding = _object(value, label)
        endpoint_id = _identifier(binding.get("endpoint_id"), f"{label}.endpoint_id")
        protocol_id = _string(binding.get("protocol_id"), f"{label}.protocol_id")
        version = _string(binding.get("version"), f"{label}.version")
        side = binding.get("side")
        if side not in {"initiator", "target"}:
            raise ValueError(f"{label}.side must be initiator or target")
        plugin = plugins.get((protocol_id, version))
        if plugin is None:
            raise ValueError(
                f"missing explicitly declared protocol version: {protocol_id}@{version}"
            )

        declared_fields = {field.field_id: field for field in plugin.fields}
        field_ports: dict[str, str] = {}
        width_facts: dict[str, int] = {}
        bound_ports: set[int] = set()
        for field_index, field_value in enumerate(_array(binding.get("fields"), f"{label}.fields")):
            field_label = f"{label}.fields[{field_index}]"
            field = _object(field_value, field_label)
            field_id = _string(field.get("field_role"), f"{field_label}.field_role")
            if field_id not in declared_fields:
                raise ValueError(f"unknown protocol field: {field_id}")
            if field_id in field_ports:
                raise ValueError(f"duplicate protocol field binding: {field_id}")
            port_id = _identifier(field.get("port_id"), f"{field_label}.port_id")
            if port_id in bound_ports:
                raise ValueError(f"duplicate protocol port binding: {port_id}")
            direction = field.get("direction")
            if direction not in {"input", "output", "inout"}:
                raise ValueError(f"{field_label}.direction is invalid")
            width = field.get("width")
            if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
                raise ValueError(f"{field_label}.width is invalid")
            signed = field.get("signed")
            if not isinstance(signed, bool):
                raise ValueError(f"{field_label}.signed must be boolean")

            specification = declared_fields[field_id]
            if specification.direction == "host_to_device":
                expected_direction = "output" if side == "initiator" else "input"
            elif specification.direction == "device_to_host":
                expected_direction = "input" if side == "initiator" else "output"
            else:
                raise ValueError(
                    f"unsupported protocol field direction: {specification.direction}"
                )
            if direction != expected_direction:
                raise ValueError(
                    f"protocol direction mismatch for field {field_id}: "
                    f"expected {expected_direction}, binding {direction}"
                )

            matching_facts = facts_by_logical_port.get(port_id, ())
            if not matching_facts:
                raise ValueError(f"protocol port ID {port_id} has no matching HDL fact")
            for fact in matching_facts:
                if fact.get("direction") != direction:
                    raise ValueError(
                        f"protocol direction mismatch for HDL fact port ID {port_id}"
                    )
                if fact.get("width") != width:
                    raise ValueError(f"protocol width mismatch for HDL fact port ID {port_id}")
                if fact.get("signed") is not signed:
                    raise ValueError(f"protocol signed mismatch for HDL fact port ID {port_id}")

            external_port = external_ports.get(port_id)
            if external_port is not None:
                if external_port.get("direction") != direction:
                    raise ValueError(
                        f"protocol direction mismatch for port ID {port_id}"
                    )
                if external_port.get("width") != width:
                    raise ValueError(f"protocol width mismatch for port ID {port_id}")
                if external_port.get("signed") is not signed:
                    raise ValueError(f"protocol signed mismatch for port ID {port_id}")
            bound_ports.add(port_id)
            field_ports[field_id] = str(port_id)
            width_facts[str(port_id)] = width

        missing = sorted(
            field.field_id
            for field in plugin.fields
            if field.required and field.field_id not in field_ports
        )
        if missing:
            raise ValueError(f"missing required protocol fields: {', '.join(missing)}")
        parameters = _object(binding.get("parameters"), f"{label}.parameters")
        compiled_protocol = compile_protocol(
            {
                "binding_id": str(endpoint_id),
                "protocol_id": protocol_id,
                "version": version,
                "ports": field_ports,
                "parameters": parameters,
            },
            {"port_widths": width_facts},
            catalog,
        )
        compiled.append((endpoint_id, compiled_protocol))
    return tuple(item for _, item in sorted(compiled, key=lambda item: item[0]))


def _protocol_plugins(
    protocols: Mapping[str, ProtocolPlugin],
) -> dict[tuple[str, str], ProtocolPlugin]:
    if not isinstance(protocols, Mapping):
        raise ValueError("protocols must be a mapping of explicit protocol versions")
    result: dict[tuple[str, str], ProtocolPlugin] = {}
    for key, plugin in protocols.items():
        if not isinstance(key, str) or not key:
            raise ValueError("protocol mapping keys must be non-empty strings")
        if not isinstance(plugin, ProtocolPlugin):
            raise ValueError(f"protocol mapping value is invalid for key: {key}")
        identity = (plugin.protocol_id, plugin.version)
        if identity in result:
            raise ValueError(
                f"duplicate explicitly declared protocol version: {identity[0]}@{identity[1]}"
            )
        result[identity] = plugin
    return result


def _port_id_array(
    value: object,
    label: str,
    port_id_map: Mapping[int, int] | None = None,
) -> set[str]:
    result: set[str] = set()
    for index, item in enumerate(_array(value, label)):
        port_id = _identifier(item, f"{label}[{index}]")
        if port_id_map is not None:
            try:
                port_id = port_id_map[port_id]
            except KeyError as error:
                raise ValueError(f"unmapped actual port ID: {port_id}") from error
        result.add(str(port_id))
    return result


def _mapped_edge_port_id(
    value: int | str,
    port_id_map: Mapping[int, int] | None,
) -> str:
    if port_id_map is None:
        return str(value)
    if isinstance(value, int):
        try:
            return str(port_id_map[value])
        except KeyError as error:
            raise ValueError(f"unmapped actual port ID: {value}") from error
    try:
        numeric_value = int(value)
    except ValueError:
        raise ValueError(f"unmapped actual port ID: {value}")
    if numeric_value <= 0 or str(numeric_value) != value:
        return value
    try:
        return str(port_id_map[numeric_value])
    except KeyError as error:
        raise ValueError(f"unmapped actual port ID: {numeric_value}") from error


def _edge_records(
    document: Mapping[str, object],
    key: str,
    label: str,
    *,
    adapter: bool = False,
    port_id_map: Mapping[int, int] | None = None,
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for index, value in enumerate(_array(document.get(key, ()), f"{label}.{key}")):
        edge = _object(value, f"{label}.{key}[{index}]")
        source = edge.get("source_port_id", edge.get("source_id"))
        target = edge.get("target_port_id", edge.get("target_id"))
        if isinstance(source, bool) or not isinstance(source, (int, str)):
            raise ValueError(f"{label}.{key}[{index}] has invalid source port ID")
        if isinstance(target, bool) or not isinstance(target, (int, str)):
            raise ValueError(f"{label}.{key}[{index}] has invalid target port ID")
        source_id = _mapped_edge_port_id(source, port_id_map)
        target_id = _mapped_edge_port_id(target, port_id_map)
        evidence = edge.get("evidence_id")
        if not isinstance(evidence, str) or not evidence:
            evidence = content_hash(
                {
                    "kind": key,
                    "source_port_id": source_id,
                    "target_port_id": target_id,
                }
            )
        record = {
            "source_port_id": source_id,
            "target_port_id": target_id,
            "evidence_id": evidence,
        }
        if adapter:
            record["adapter_id"] = _string(
                edge.get("adapter_id"),
                f"{label}.{key}[{index}].adapter_id",
            )
        result.append(record)
    return result


def _graph_facts(
    hdl_facts: Mapping[str, object],
    composition_ir: Mapping[str, object],
    actual_to_logical: Mapping[int, int],
) -> dict[str, object]:
    clock_ids: set[str] = set()
    reset_ids: set[str] = set()
    for port_id, port in _facts_ports(hdl_facts).items():
        try:
            logical_port_id = actual_to_logical[port_id]
        except KeyError as error:
            raise ValueError(f"unmapped actual port ID: {port_id}") from error
        role = port.get("declared_role")
        if role == "clock":
            clock_ids.add(str(logical_port_id))
        elif role == "reset":
            reset_ids.add(str(logical_port_id))
    for index, value in enumerate(
        _array(composition_ir.get("external_ports"), "composition_ir.external_ports")
    ):
        port = _object(value, f"composition_ir.external_ports[{index}]")
        port_id = str(
            _identifier(
                port.get("port_id"),
                f"composition_ir.external_ports[{index}].port_id",
            )
        )
        if port.get("semantic_role") == "clock":
            clock_ids.add(port_id)
        elif port.get("semantic_role") == "reset":
            reset_ids.add(port_id)
    external = _port_id_array(
        hdl_facts.get("external_endpoint_port_ids", ()),
        "hdl_facts.external_endpoint_port_ids",
        actual_to_logical,
    ) | _port_id_array(
        composition_ir.get("external_endpoint_port_ids", ()),
        "composition_ir.external_endpoint_port_ids",
    )
    adapter_edges = _edge_records(
        hdl_facts,
        "adapter_edges",
        "hdl_facts",
        adapter=True,
        port_id_map=actual_to_logical,
    ) + _edge_records(
        composition_ir,
        "adapters",
        "composition_ir",
        adapter=True,
    )
    return {
        "clock_port_ids": sorted(clock_ids),
        "reset_port_ids": sorted(reset_ids),
        "external_endpoint_port_ids": sorted(external),
        "dataflow_edges": _edge_records(
            hdl_facts,
            "dataflow_edges",
            "hdl_facts",
            port_id_map=actual_to_logical,
        ),
        "control_edges": _edge_records(
            hdl_facts,
            "control_edges",
            "hdl_facts",
            port_id_map=actual_to_logical,
        ),
        "adapter_edges": adapter_edges,
    }


def _node_document(node: DependencyNode) -> dict[str, object]:
    return {"kind": node.kind, "components": list(node.components)}


def _graph_document(graph: CsrGraph) -> dict[str, object]:
    return {
        "schema_version": "dependency_graph.v1",
        "node_ids": [_node_document(node) for node in graph.node_ids],
        "group_ids": [_node_document(node) for node in graph.group_ids],
        "indptr": list(graph.indptr),
        "indices": list(graph.indices),
        "edge_kinds": list(graph.edge_kinds),
        "evidence_ids": list(graph.evidence_ids),
        "external_endpoint_port_ids": list(graph.external_endpoint_port_ids),
        "adapter_edges": [
            {
                "source_port_id": source,
                "target_port_id": target,
                "adapter_id": adapter_id,
                "evidence_id": evidence_id,
            }
            for source, target, adapter_id, evidence_id in graph.adapter_edges
        ],
        "diagnostics": list(graph.diagnostics),
    }


def _manifest_with_dependency_groups(
    candidate_manifest: Mapping[str, object],
    graph: CsrGraph,
    compiled_protocols: tuple[CompiledProtocol, ...],
) -> dict[str, object]:
    result = dict(candidate_manifest)
    groups = tuple(graph.group_ids)
    result["dependency_groups"] = [_node_document(group) for group in groups]
    group_set = set(groups)
    groups_by_port: dict[str, list[DependencyNode]] = {}
    for protocol in compiled_protocols:
        for field in protocol.fields:
            if field.direction != "host_to_device":
                continue
            group = DependencyNode("field_group", (protocol.binding_id, field.field_id))
            if group in group_set:
                groups_by_port.setdefault(field.port_id, []).append(group)

    ports: list[dict[str, object]] = []
    for index, value in enumerate(
        _array(candidate_manifest.get("top_port_abi"), "candidate_manifest.top_port_abi")
    ):
        port = dict(_object(value, f"candidate_manifest.top_port_abi[{index}]"))
        matches = groups_by_port.get(str(port.get("port_id")), ())
        if len(matches) == 1:
            port["dependency_group"] = _node_document(matches[0])
        ports.append(port)
    result["top_port_abi"] = ports
    return result


def _coverage_hash(value: object, label: str) -> str:
    points = _array(value, label)
    return content_hash({"coverage_universe": sorted(points, key=canonical_bytes)})


def _flat_manifest(candidate_manifest: Mapping[str, object]) -> dict[str, object]:
    baseline = _object(
        candidate_manifest.get("flat_baseline"),
        "candidate_manifest.flat_baseline",
    )
    baseline_id = _string(
        baseline.get("baseline_id"),
        "candidate_manifest.flat_baseline.baseline_id",
    )
    if baseline_id == candidate_manifest.get("candidate_id"):
        raise ValueError("flat_baseline must use a standalone baseline identity")
    combinational = baseline.get("combinational_design")
    if not isinstance(combinational, bool):
        raise ValueError("candidate_manifest.flat_baseline.combinational_design must be boolean")
    top = _object(baseline.get("top"), "candidate_manifest.flat_baseline.top")
    _string(top.get("module"), "candidate_manifest.flat_baseline.top.module")
    source = _string(top.get("source"), "candidate_manifest.flat_baseline.top.source")
    top_hash = _string(
        top.get("content_hash"),
        "candidate_manifest.flat_baseline.top.content_hash",
    )
    source_composition = _array(
        baseline.get("source_composition"),
        "candidate_manifest.flat_baseline.source_composition",
    )
    sources: set[tuple[str, str]] = set()
    for index, value in enumerate(source_composition):
        record = _object(
            value,
            f"candidate_manifest.flat_baseline.source_composition[{index}]",
        )
        sources.add(
            (
                _string(record.get("source"), "flat baseline source"),
                _string(record.get("content_hash"), "flat baseline source content_hash"),
            )
        )
    if (source, top_hash) not in sources:
        raise ValueError("flat_baseline source composition does not contain its declared top")
    candidate_top = _object(candidate_manifest.get("top"), "candidate_manifest.top")
    if top_hash == candidate_top.get("content_hash"):
        raise ValueError("flat_baseline must be a standalone baseline top/source composition")
    coverage_universe = _array(
        baseline.get("coverage_universe"),
        "candidate_manifest.flat_baseline.coverage_universe",
    )
    baseline_coverage_hash = _coverage_hash(
        coverage_universe,
        "candidate_manifest.flat_baseline.coverage_universe",
    )
    candidate_coverage_hash = _coverage_hash(
        candidate_manifest.get("coverage_universe"),
        "candidate_manifest.coverage_universe",
    )
    if baseline_coverage_hash == candidate_coverage_hash:
        raise ValueError("flat_baseline must use a distinct coverage universe")
    top_port_abi = _array(
        baseline.get("top_port_abi"),
        "candidate_manifest.flat_baseline.top_port_abi",
    )
    result: dict[str, object] = {
        "schema_version": "candidate_manifest.v1",
        "candidate_id": baseline_id,
        "combinational_design": combinational,
        "top": dict(top),
        "top_port_abi": [dict(_object(item, "flat baseline ABI port")) for item in top_port_abi],
        "coverage_universe": list(coverage_universe),
        "coverage_universe_id": baseline_coverage_hash,
    }
    return result


def _projection_plan(
    direct_abi: RawBitAbi,
    compiled_protocols: tuple[CompiledProtocol, ...],
    protocols: Mapping[str, ProtocolPlugin],
    graph: CsrGraph,
    active_view: ActiveDependencyView | None,
) -> ProjectionPlan:
    if active_view is not None and active_view.static_graph != graph:
        raise ValueError("active dependency view does not belong to the compiled static graph")
    destination_by_port = {
        str(destination.port_id): destination.destination_id
        for destination in direct_abi.destinations
    }
    node_index = {node: index for index, node in enumerate(graph.node_ids)}
    action_candidates: list[
        tuple[tuple[str, int, str, str], dict[str, object]]
    ] = []
    active_destinations = {
        destination.destination_id: True for destination in direct_abi.destinations
    }
    plugins = _protocol_plugins(protocols)
    for compiled in compiled_protocols:
        plugin = plugins[(compiled.protocol_id, compiled.version)]
        rule_bounds = {
            rule.antecedent_field_id: rule.max_cycles
            for rule in plugin.temporal_rules
        }
        targeted_fields: set[str] = set()
        for specification in plugin.projection_actions:
            for field_id in specification.field_ids:
                try:
                    field = compiled.field_for(field_id)
                except KeyError:
                    continue
                if field.direction != "host_to_device" or field.port_id not in destination_by_port:
                    continue
                destination_id = destination_by_port[field.port_id]
                group = DependencyNode("field_group", (compiled.binding_id, field.field_id))
                port = DependencyNode("port", (field.port_id,))
                active = True
                if active_view is not None:
                    active = active_view.is_active(node_index[group], node_index[port])
                active_destinations[destination_id] &= active
                max_cycles = specification.max_cycles
                if specification.kind in {"gate", "delay_select"} and field_id in rule_bounds:
                    max_cycles = min(max_cycles or rule_bounds[field_id], rule_bounds[field_id])
                action_candidates.append(
                    (
                        (compiled.binding_id, specification.action_id, field_id, "action"),
                        {
                            "destination_id": destination_id,
                            "kind": specification.kind,
                            "category": specification.category,
                            "max_cycles": max_cycles,
                            "active": active,
                        },
                    )
                )
                targeted_fields.add(field_id)
        for rule in plugin.temporal_rules:
            if rule.antecedent_field_id in targeted_fields:
                continue
            try:
                field = compiled.field_for(rule.antecedent_field_id)
            except KeyError:
                continue
            if field.direction != "host_to_device" or field.port_id not in destination_by_port:
                continue
            destination_id = destination_by_port[field.port_id]
            group = DependencyNode("field_group", (compiled.binding_id, field.field_id))
            port = DependencyNode("port", (field.port_id,))
            active = True
            if active_view is not None:
                active = active_view.is_active(node_index[group], node_index[port])
            active_destinations[destination_id] &= active
            action_candidates.append(
                (
                    (compiled.binding_id, rule.rule_id, field.field_id, "rule"),
                    {
                        "destination_id": destination_id,
                        "kind": "gate",
                        "category": "progress",
                        "max_cycles": rule.max_cycles,
                        "active": active,
                    },
                )
            )
    records: list[dict[str, object]] = []
    for action_id, (_, record) in enumerate(sorted(action_candidates, key=lambda item: item[0])):
        records.append({"action_id": action_id, **record})
    field_order = tuple(
        sorted(
            active_destinations,
            key=lambda destination_id: (
                not active_destinations[destination_id],
                destination_id,
            ),
        )
    )
    return build_projection_plan(direct_abi, records, field_order=field_order)


@dataclass(frozen=True, slots=True)
class HarnessBundle:
    flat_direct: HarnessArtifact
    candidate_direct: HarnessArtifact
    candidate_depaware: HarnessArtifact
    dependency_graph: CsrGraph
    coverage_universe_hash: str
    coverage_metadata_hash: str
    dependency_graph_hash: str
    protocol_ids: tuple[str, ...]
    protocol_versions: tuple[tuple[str, str], ...]
    candidate_id: str
    composition_ir_hash: str = field(compare=False)
    input_manifest_hash: str = field(compare=False)
    build_cache_key: str

    def manifest_fragment(self) -> dict[str, object]:
        artifacts = (
            ("flat-direct", self.flat_direct),
            ("candidate-direct", self.candidate_direct),
            ("candidate-depaware", self.candidate_depaware),
        )
        graph_document = _graph_document(self.dependency_graph)
        harnesses = {name: artifact.manifest_fragment() for name, artifact in artifacts}
        return {
            "candidate_id": self.candidate_id,
            "composition_ir_hash": self.composition_ir_hash,
            "input_manifest_hash": self.input_manifest_hash,
            "harnesses": harnesses,
            "raw_bit_mappings": {
                name: harnesses[name]["mapping"] for name, _ in artifacts
            },
            "dependency_graph": {
                "content_hash": self.dependency_graph_hash,
                "node_count": len(self.dependency_graph.node_ids),
                "group_count": len(self.dependency_graph.group_ids),
                "edge_count": len(self.dependency_graph.indices),
                "document": graph_document,
            },
            "coverage_universe_hash": self.coverage_universe_hash,
            "coverage_metadata_hash": self.coverage_metadata_hash,
            "protocol_ids": list(self.protocol_ids),
            "protocols": [
                {"protocol_id": protocol_id, "version": version}
                for protocol_id, version in self.protocol_versions
            ],
            "runtime": {
                "status": "pending",
                "input_lifecycle": "top_validated",
                "build_cache_key": self.build_cache_key,
                "peak_rss_bytes": None,
                "validation": {
                    "status": "pending",
                    "contracts": "passed",
                    "candidate_abi": "passed",
                    "protocols": "passed",
                    "dependency_graph": "passed",
                    "harnesses": "passed",
                    "compile": "pending",
                    "smoke": "pending",
                },
            },
        }


def _atomic_write(path: Path, text: str) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def write_harness_bundle(bundle: HarnessBundle, output_dir: Path) -> dict[str, Path]:
    """Atomically materialize the five canonical bundle files."""
    if not isinstance(bundle, HarnessBundle):
        raise TypeError("bundle must be a HarnessBundle")
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    output_dir.mkdir(parents=True, exist_ok=True)
    sources = {
        "flat-direct.sv": bundle.flat_direct.source_text,
        "candidate-direct.sv": bundle.candidate_direct.source_text,
        "candidate-depaware.sv": bundle.candidate_depaware.source_text,
    }
    graph_document = _graph_document(bundle.dependency_graph)
    fragment = bundle.manifest_fragment()
    for name in ("flat-direct", "candidate-direct", "candidate-depaware"):
        fragment["harnesses"][name]["source"] = f"{name}.sv"
    fragment["dependency_graph"]["source"] = "dependency_graph.v1.json"
    fragment["files"] = {
        "flat-direct": "flat-direct.sv",
        "candidate-direct": "candidate-direct.sv",
        "candidate-depaware": "candidate-depaware.sv",
        "dependency_graph": "dependency_graph.v1.json",
        "manifest_fragment": "harness_manifest_fragment.json",
    }
    json_documents = {
        "dependency_graph.v1.json": graph_document,
        "harness_manifest_fragment.json": fragment,
    }
    for filename, source in sources.items():
        _atomic_write(output_dir / filename, source)
    for filename, document in json_documents.items():
        text = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        _atomic_write(output_dir / filename, text)
    filenames = tuple((*sources, *json_documents))
    return {filename: output_dir / filename for filename in filenames}


def compile_harness_bundle(
    hdl_facts: object,
    composition_ir: object,
    candidate_manifest: object,
    protocols: Mapping[str, ProtocolPlugin],
    *,
    active_view: ActiveDependencyView | None = None,
) -> HarnessBundle:
    """Compile three distinct harness modes after strict runtime compatibility checks."""
    validate_contract(hdl_facts, "hdl_facts.v2")
    validate_contract(composition_ir, "composition_ir.v1")
    validate_contract(candidate_manifest, "candidate_manifest.v1")
    facts = _object(hdl_facts, "hdl_facts")
    composition = _object(composition_ir, "composition_ir")
    manifest = _object(candidate_manifest, "candidate_manifest")
    input_manifest_hash = content_hash(candidate_manifest)
    top_module_id = _validate_runtime_evidence(facts, composition, manifest)
    if manifest.get("candidate_id") != composition.get("candidate_id"):
        raise ValueError("candidate_id does not match composition_ir")
    if manifest.get("composition_ir_hash") != content_hash(composition_ir):
        raise ValueError("candidate_manifest.composition_ir_hash does not match composition_ir")
    actual_to_logical = _validate_candidate_abi(
        facts,
        composition,
        manifest,
        top_module_id,
    )

    port_id_map = _complete_port_id_map(facts, composition, actual_to_logical)
    compiled = _compiled_protocols(
        facts,
        composition,
        protocols,
        port_id_map=port_id_map,
    )
    graph_facts = _graph_facts(facts, composition, port_id_map)
    plain_graph = to_csr(build_static_graph(graph_facts, compiled))
    adapter_edges = tuple(
        sorted(
            (
                edge["source_port_id"],
                edge["target_port_id"],
                edge["adapter_id"],
                edge["evidence_id"],
            )
            for edge in graph_facts["adapter_edges"]
        )
    )
    graph = replace(
        plain_graph,
        external_endpoint_port_ids=tuple(graph_facts["external_endpoint_port_ids"]),
        adapter_edges=adapter_edges,
    )
    dependency_graph_hash = content_hash(_graph_document(graph))

    candidate_coverage_hash = _coverage_hash(
        manifest.get("coverage_universe"),
        "candidate_manifest.coverage_universe",
    )
    harness_manifest = _manifest_with_dependency_groups(manifest, graph, compiled)
    harness_manifest["coverage_universe_id"] = candidate_coverage_hash
    baseline_manifest = _flat_manifest(manifest)
    flat_direct = build_direct(baseline_manifest, "flat_direct")
    candidate_direct = build_direct(harness_manifest, "candidate_direct")
    plan = _projection_plan(
        candidate_direct.abi,
        compiled,
        protocols,
        graph,
        active_view,
    )
    candidate_depaware = build_depaware(harness_manifest, plan)
    if not (
        candidate_direct.raw_width == candidate_depaware.raw_width
        and candidate_direct.top_content_hash == candidate_depaware.top_content_hash
        and candidate_direct.coverage_universe_id
        == candidate_depaware.coverage_universe_id
    ):
        raise ValueError("candidate harness identity is not shared across the comparison pair")
    return HarnessBundle(
        flat_direct=flat_direct,
        candidate_direct=candidate_direct,
        candidate_depaware=candidate_depaware,
        dependency_graph=graph,
        coverage_universe_hash=candidate_coverage_hash,
        coverage_metadata_hash=candidate_coverage_hash,
        dependency_graph_hash=dependency_graph_hash,
        protocol_ids=tuple(sorted({protocol.protocol_id for protocol in compiled})),
        protocol_versions=tuple(
            sorted({(protocol.protocol_id, protocol.version) for protocol in compiled})
        ),
        candidate_id=_string(manifest.get("candidate_id"), "candidate_manifest.candidate_id"),
        composition_ir_hash=_string(
            manifest.get("composition_ir_hash"),
            "candidate_manifest.composition_ir_hash",
        ),
        input_manifest_hash=input_manifest_hash,
        build_cache_key=_string(
            manifest.get("build_cache_key"),
            "candidate_manifest.build_cache_key",
        ),
    )
