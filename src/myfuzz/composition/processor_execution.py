"""Deterministic processor adapter execution records."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass

from myfuzz.contracts import content_hash
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import ProtocolDefinitionError
from myfuzz.protocols.widths import ProtocolWidthError, compile_width_expression

from .endpoint_capabilities import EndpointFieldFact
from .ids import canonical_id
from .input_layout import InputLayout, LayoutField
from .processor_adapters import ProcessorAdapterError, resolve_processor_adapter
from .processor_boundary import ProcessorBoundary, ProcessorMemoryBinding


class ProcessorExecutionError(ValueError):
    """Raised when processor execution wiring is incomplete or ambiguous."""


@dataclass(frozen=True, slots=True)
class ProcessorExecutionRoute:
    route_id: int
    endpoint_id: str
    function: str
    source_protocol: tuple[str, str]
    target_protocol: tuple[str, str]
    adapter_id: str
    rtl_module: str
    rtl_source: str
    parameters: tuple[tuple[str, int], ...]
    widths: tuple[tuple[str, int], ...]
    field_connections: tuple[Mapping[str, object], ...]
    backend_contract: Mapping[str, object]
    extension_policies: tuple[Mapping[str, object], ...]
    reset_contract: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ProcessorExecutionPlan:
    routes: tuple[ProcessorExecutionRoute, ...]
    adapter_sources: tuple[str, ...]
    execution_hash: str


_WIDTH_ROLES = {
    "address": frozenset({"addr", "awaddr", "araddr", "a_address"}),
    "data": frozenset({"wdata", "rdata", "a_data", "d_data"}),
    "id": frozenset({"awid", "bid", "arid", "rid"}),
    "source": frozenset({"a_source", "d_source"}),
    "user": frozenset({"awuser", "wuser", "buser", "aruser", "ruser"}),
}

_BACKEND_ADAPTER_PORTS = {
    "req_valid": "req_valid_o",
    "req_ready": "req_ready_i",
    "write": "req_write_o",
    "addr": "req_addr_o",
    "wdata": "req_wdata_o",
    "be": "req_be_o",
    "rsp_valid": "rsp_valid_i",
    "rsp_ready": "rsp_ready_o",
    "rdata": "rsp_rdata_i",
    "error": "rsp_error_i",
}


def _expression_names(expression: str) -> frozenset[str]:
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, TypeError) as error:
        raise ProcessorExecutionError("width-expression") from error
    return frozenset(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))


def _validated_fields(
    memory: ProcessorMemoryBinding, catalog: ProtocolCatalog,
) -> tuple[tuple[EndpointFieldFact, ...], dict[str, int]]:
    try:
        plugin = catalog.require(*memory.protocol)
    except ProtocolDefinitionError as error:
        raise ProcessorExecutionError(
            f"unknown-protocol:{memory.protocol[0]}@{memory.protocol[1]}"
        ) from error
    by_role: dict[str, EndpointFieldFact] = {}
    for field in memory.fields:
        if field.role in by_role:
            raise ProcessorExecutionError(f"duplicate-field:{memory.endpoint_id}:{field.role}")
        by_role[field.role] = field
    parameters: dict[str, int] = {}
    for spec in plugin.fields:
        field = by_role.get(spec.field_id)
        if field is None:
            if spec.required or spec.runtime_required:
                raise ProcessorExecutionError(
                    f"missing-field:{memory.endpoint_id}:{spec.field_id}"
                )
            continue
        expected_direction = "output" if spec.direction == "host_to_device" else "input"
        if field.direction != expected_direction:
            raise ProcessorExecutionError(
                f"field-direction:{memory.endpoint_id}:{spec.field_id}"
            )
        names = _expression_names(spec.width_expression)
        if len(names) == 1 and spec.width_expression.strip() in names:
            name = next(iter(names))
            previous = parameters.setdefault(name, field.width)
            if previous != field.width:
                raise ProcessorExecutionError(
                    f"width-mismatch:{memory.endpoint_id}:{spec.field_id}"
                )
    for spec in plugin.fields:
        field = by_role.get(spec.field_id)
        if field is None:
            continue
        try:
            expected = compile_width_expression(spec.width_expression, parameters)
        except ProtocolWidthError as error:
            raise ProcessorExecutionError(
                f"width-mismatch:{memory.endpoint_id}:{spec.field_id}"
            ) from error
        if field.width != expected:
            raise ProcessorExecutionError(
                f"width-mismatch:{memory.endpoint_id}:{spec.field_id}"
            )
    return tuple(by_role[role] for role in sorted(by_role)), parameters


def _derived_widths(memory: ProcessorMemoryBinding) -> dict[str, int]:
    widths: dict[str, int] = {}
    for name, roles in _WIDTH_ROLES.items():
        values = {field.width for field in memory.fields if field.role in roles}
        if len(values) > 1:
            raise ProcessorExecutionError(f"width-mismatch:{memory.endpoint_id}:{name}")
        if values:
            widths[name] = next(iter(values))
    for required in ("address", "data"):
        if required not in widths:
            raise ProcessorExecutionError(f"missing-field:{memory.endpoint_id}:{required}-width")
    if memory.protocol == ("axi4", "1"):
        for required in ("id", "user"):
            if required not in widths:
                raise ProcessorExecutionError(f"missing-field:{memory.endpoint_id}:{required}-width")
    if memory.protocol == ("tl-ul", "1") and "source" not in widths:
        raise ProcessorExecutionError(f"missing-field:{memory.endpoint_id}:source-width")
    return widths


def _physical(field: EndpointFieldFact) -> dict[str, object]:
    if not field.member_path:
        if any(value is not None for value in (field.raw_lo, field.raw_hi, field.container_width)):
            raise ProcessorExecutionError(f"incomplete-packed-input:{field.port}")
        return {"port": field.port}
    if any(type(value) is not int for value in (field.raw_lo, field.raw_hi, field.container_width)):
        raise ProcessorExecutionError(f"incomplete-packed-input:{field.port}")
    assert field.raw_lo is not None and field.raw_hi is not None
    assert field.container_width is not None
    if (
        field.raw_lo < 0 or field.raw_hi < field.raw_lo
        or field.raw_hi >= field.container_width
        or field.raw_hi - field.raw_lo + 1 != field.width
    ):
        raise ProcessorExecutionError(f"incomplete-packed-input:{field.port}")
    return {
        "container_port": field.port,
        "member_path": list(field.member_path),
        "part_select": f"[{field.raw_hi}:{field.raw_lo}]",
        "raw_lo": field.raw_lo,
        "raw_hi": field.raw_hi,
        "container_width": field.container_width,
    }


def _range(field: EndpointFieldFact | LayoutField) -> tuple[str, int | None, int | None]:
    member_path = getattr(field, "member_path", ())
    if not member_path:
        return field.port, None, None
    lo = getattr(field, "raw_lo", None)
    hi = getattr(field, "raw_hi", None)
    if isinstance(field, LayoutField):
        lo, hi = field.port_raw_lo, field.port_raw_hi
    return field.port, lo, hi


def _overlap(
    left: tuple[str, int | None, int | None],
    right: tuple[str, int | None, int | None],
) -> bool:
    if left[0] != right[0]:
        return False
    if left[1] is None or right[1] is None:
        return True
    assert left[2] is not None and right[2] is not None
    return max(left[1], right[1]) <= min(left[2], right[2])


def _validate_input_ownership(
    boundary: ProcessorBoundary, input_layout: InputLayout | None,
) -> None:
    driven = [
        field for memory in boundary.memories for field in memory.fields
        if field.direction == "input"
    ]
    for index, field in enumerate(driven):
        physical = _range(field)
        if any(_overlap(physical, _range(other)) for other in driven[:index]):
            raise ProcessorExecutionError(f"duplicate-input-driver:{field.port}")
        if input_layout is not None and any(
            _overlap(physical, _range(layout_field)) for layout_field in input_layout.fields
        ):
            raise ProcessorExecutionError(f"duplicate-input-driver:{field.port}")


def _validate_packed_inputs(boundary: ProcessorBoundary) -> None:
    declared = {(item.endpoint_id, item.port): item for item in boundary.packed_input_containers}
    observed: set[tuple[str, str]] = set()
    for memory in boundary.memories:
        by_port: dict[str, list[EndpointFieldFact]] = {}
        for field in memory.fields:
            if field.direction == "input" and field.member_path:
                by_port.setdefault(field.port, []).append(field)
        for port, fields in by_port.items():
            key = (memory.endpoint_id, port)
            observed.add(key)
            widths = {field.container_width for field in fields}
            if len(widths) != 1 or None in widths:
                raise ProcessorExecutionError(f"incomplete-packed-input:{port}")
            width = next(iter(widths))
            cursor = 0
            for field in sorted(fields, key=lambda item: (item.raw_lo, item.raw_hi)):
                _physical(field)
                if field.raw_lo != cursor:
                    raise ProcessorExecutionError(f"incomplete-packed-input:{port}")
                assert field.raw_hi is not None
                cursor = field.raw_hi + 1
            container = declared.get(key)
            if container is None or cursor != width or container.width != width or container.covered_bits != width:
                raise ProcessorExecutionError(f"incomplete-packed-input:{port}")
    if set(declared) != observed:
        port = next(iter(sorted(set(declared) - observed)), ("", "unknown"))[1]
        raise ProcessorExecutionError(f"incomplete-packed-input:{port}")


def _backend_contract(
    catalog: ProtocolCatalog, widths: Mapping[str, int],
) -> dict[str, object]:
    protocol = ("processor-memory-beat", "1")
    try:
        plugin = catalog.require(*protocol)
    except ProtocolDefinitionError as error:
        raise ProcessorExecutionError("backend-contract:processor-memory-beat@1") from error
    parameters = {"address_width": widths["address"], "data_width": widths["data"]}
    fields = []
    for spec in plugin.fields:
        try:
            width = compile_width_expression(spec.width_expression, parameters)
        except ProtocolWidthError as error:
            raise ProcessorExecutionError(f"backend-contract:{spec.field_id}") from error
        fields.append({
            "field_id": spec.field_id,
            "direction": "output" if spec.direction == "host_to_device" else "input",
            "width": width,
            "adapter_port": _BACKEND_ADAPTER_PORTS[spec.field_id],
        })
    return {
        "mode": "single_outstanding_request_response",
        "protocol": list(protocol),
        "fields": fields,
        "capabilities": dict(plugin.capability_limits),
    }


def _extension_document(policy: object) -> dict[str, object]:
    return {
        name: value
        for name in (
            "role", "direction", "action", "width", "width_group",
            "width_of", "width_divisor",
        )
        if (value := getattr(policy, name)) is not None
    }


def _route(
    memory: ProcessorMemoryBinding, catalog: ProtocolCatalog,
) -> ProcessorExecutionRoute:
    _validated_fields(memory, catalog)
    try:
        adapter = resolve_processor_adapter(memory)
    except ProcessorAdapterError as error:
        raise ProcessorExecutionError(str(error)) from error
    widths = _derived_widths(memory)
    parameters = {"ADDRESS_WIDTH": widths["address"], "DATA_WIDTH": widths["data"]}
    if "id" in widths:
        parameters["ID_WIDTH"] = widths["id"]
    if "user" in widths:
        parameters["USER_WIDTH"] = widths["user"]
    parameters.update(adapter.parameter_values)
    source_ports = {
        role: port for role, port, _direction in adapter.source_ports
    }
    connections = tuple({
        "field_id": field.role,
        "direction": field.direction,
        "width": field.width,
        "signed": field.signed,
        "adapter_port": source_ports[field.role],
        "physical": _physical(field),
    } for field in sorted(memory.fields, key=lambda item: item.role))
    route_key = f"{memory.function}:{memory.protocol[0]}@{memory.protocol[1]}"
    return ProcessorExecutionRoute(
        canonical_id("processor-memory-route", route_key), memory.endpoint_id,
        memory.function, adapter.source_protocol, adapter.target_protocol,
        adapter.adapter_id, adapter.rtl_module, adapter.rtl_source,
        tuple(sorted(parameters.items())), tuple(sorted(widths.items())),
        connections, _backend_contract(catalog, widths),
        tuple(_extension_document(item) for item in adapter.extension_policies),
        {"polarity": adapter.reset_polarity, "synchrony": adapter.reset_synchrony},
    )


def _document(routes: tuple[ProcessorExecutionRoute, ...]) -> dict[str, object]:
    return {
        "schema_version": "processor_execution.v1",
        "adapter_sources": sorted({route.rtl_source for route in routes}),
        "routes": [{
            "route_id": route.route_id,
            "function": route.function,
            "source_protocol": list(route.source_protocol),
            "target_protocol": list(route.target_protocol),
            "adapter_id": route.adapter_id,
            "rtl_module": route.rtl_module,
            "rtl_source": route.rtl_source,
            "parameters": dict(route.parameters),
            "widths": dict(route.widths),
            "field_connections": list(route.field_connections),
            "extension_policies": list(route.extension_policies),
            "reset_contract": dict(route.reset_contract),
            "backend_contract": dict(route.backend_contract),
        } for route in routes],
    }


def build_processor_execution(
    boundary: ProcessorBoundary, *, protocol_catalog: ProtocolCatalog,
    input_layout: InputLayout | None = None,
) -> ProcessorExecutionPlan:
    """Build a complete path-free execution record before RTL rendering."""
    if not isinstance(boundary, ProcessorBoundary):
        raise ProcessorExecutionError("boundary:type")
    functions = [memory.function for memory in boundary.memories]
    valid = functions in (["memory_master"], ["processor_memory_master"]) or sorted(functions) == [
        "data_memory_master", "instruction_memory_master",
    ]
    if not valid:
        raise ProcessorExecutionError("ambiguous-memory")
    _validate_packed_inputs(boundary)
    _validate_input_ownership(boundary, input_layout)
    routes = tuple(sorted(
        (_route(memory, protocol_catalog) for memory in boundary.memories),
        key=lambda item: (item.function, item.route_id),
    ))
    document = _document(routes)
    return ProcessorExecutionPlan(
        routes, tuple(document["adapter_sources"]),
        content_hash(document),
    )


def processor_execution_document(plan: ProcessorExecutionPlan) -> dict[str, object]:
    """Return the canonical execution record included in composition IR."""
    if not isinstance(plan, ProcessorExecutionPlan):
        raise ProcessorExecutionError("plan:type")
    document = _document(plan.routes)
    document["execution_hash"] = plan.execution_hash
    return document


__all__ = [
    "ProcessorExecutionError",
    "ProcessorExecutionPlan",
    "ProcessorExecutionRoute",
    "build_processor_execution",
    "processor_execution_document",
]
