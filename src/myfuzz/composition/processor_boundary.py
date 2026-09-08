"""CPU-name-independent execution boundary derived from endpoint capabilities."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import FieldSpec, ProtocolDefinitionError
from myfuzz.protocols.widths import ProtocolWidthError, compile_width_expression

from .endpoint_capabilities import EndpointCapability, EndpointFieldFact


class ProcessorBoundaryError(ValueError):
    """Raised when endpoint facts cannot form one processor test boundary."""


@dataclass(frozen=True, slots=True)
class ProcessorMemoryBinding:
    endpoint_id: str
    function: str
    protocol: tuple[str, str]
    fields: tuple[EndpointFieldFact, ...]
    extension_fields: tuple[EndpointFieldFact, ...]


@dataclass(frozen=True, slots=True)
class RequestClassification:
    mode: str
    endpoint_id: str | None
    field_role: str | None
    field: EndpointFieldFact | None
    instruction_value: int
    data_value: int

    @property
    def port(self) -> str | None:
        return None if self.field is None else self.field.port


@dataclass(frozen=True, slots=True)
class ProcessorControlBinding:
    endpoint_id: str
    function: str
    fields: tuple[EndpointFieldFact, ...]


@dataclass(frozen=True, slots=True)
class PackedInputContainer:
    endpoint_id: str
    port: str
    width: int
    covered_bits: int


@dataclass(frozen=True, slots=True)
class ProcessorBoundary:
    clock: ProcessorControlBinding
    reset: ProcessorControlBinding
    memories: tuple[ProcessorMemoryBinding, ...]
    controls: tuple[ProcessorControlBinding, ...]
    packed_input_containers: tuple[PackedInputContainer, ...]
    classification: RequestClassification | None = None


_MEMORY_FUNCTIONS = frozenset(
    {
        "memory_master",
        "processor_memory_master",
        "instruction_memory_master",
        "data_memory_master",
    }
)
_OPTIONAL_CONTROL_FUNCTIONS = frozenset(
    {"boot_control", "interrupt_sink", "debug_transport"}
)
_CONTROL_ROLES: dict[str, frozenset[str]] = {
    "boot_control": frozenset({"boot_address", "hart_id"}),
    "interrupt_sink": frozenset({
        "software_interrupt", "timer_interrupt", "external_interrupt",
        "fast_interrupt", "non_maskable_interrupt",
    }),
    "debug_transport": frozenset({"request"}),
}


def _source_backed(endpoint: EndpointCapability) -> None:
    for field in endpoint.fields:
        if field.source is None or not field.evidence:
            raise ProcessorBoundaryError(
                f"source-evidence:{endpoint.endpoint_id}:{field.role}"
            )


def _one_control(
    endpoints: Sequence[EndpointCapability], function: str, role: str
) -> ProcessorControlBinding:
    selected = [endpoint for endpoint in endpoints if endpoint.function == function]
    if len(selected) != 1:
        reason = function if not selected else f"duplicate-{function}"
        raise ProcessorBoundaryError(reason)
    endpoint = selected[0]
    _source_backed(endpoint)
    if endpoint.protocol is not None or endpoint.side is not None:
        raise ProcessorBoundaryError(f"{function}-protocol:{endpoint.endpoint_id}")
    if len(endpoint.fields) != 1:
        raise ProcessorBoundaryError(f"{function}-field:{endpoint.endpoint_id}")
    field = endpoint.fields[0]
    if field.role != role or field.direction != "input" or field.width != 1:
        raise ProcessorBoundaryError(f"{function}-field:{endpoint.endpoint_id}")
    return ProcessorControlBinding(endpoint.endpoint_id, function, endpoint.fields)


def _validate_memory(
    endpoint: EndpointCapability, catalog: ProtocolCatalog
) -> ProcessorMemoryBinding:
    _source_backed(endpoint)
    if endpoint.side != "initiator":
        raise ProcessorBoundaryError(f"memory-side:{endpoint.endpoint_id}")
    if endpoint.protocol is None:
        raise ProcessorBoundaryError(f"memory-protocol:{endpoint.endpoint_id}")
    try:
        plugin = catalog.require(*endpoint.protocol)
    except ProtocolDefinitionError as error:
        raise ProcessorBoundaryError(
            f"unsupported-protocol:{endpoint.protocol[0]}@{endpoint.protocol[1]}"
        ) from error
    fields = {field.role: field for field in endpoint.fields}
    parameters: dict[str, int] = {}
    checked: list[tuple[FieldSpec, EndpointFieldFact]] = []
    for expected in plugin.fields:
        field = fields.get(expected.field_id)
        if field is None:
            if expected.required or expected.runtime_required:
                raise ProcessorBoundaryError(
                    f"required-field:{expected.field_id}:{endpoint.endpoint_id}"
                )
            continue
        expected_direction = (
            "output" if expected.direction == "host_to_device" else "input"
        )
        if field.direction != expected_direction:
            raise ProcessorBoundaryError(
                f"field-direction:{expected.field_id}:{endpoint.endpoint_id}"
            )
        expression = expected.width_expression.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression):
            previous = parameters.setdefault(expression, field.width)
            if previous != field.width:
                raise ProcessorBoundaryError(
                    f"field-width:{expected.field_id}:{endpoint.endpoint_id}"
                )
        checked.append((expected, field))
    for expected, field in checked:
        try:
            expected_width = compile_width_expression(
                expected.width_expression, parameters
            )
        except ProtocolWidthError as error:
            raise ProcessorBoundaryError(
                f"field-width:{expected.field_id}:{endpoint.endpoint_id}"
            ) from error
        if field.width != expected_width:
            raise ProcessorBoundaryError(
                f"field-width:{expected.field_id}:{endpoint.endpoint_id}"
            )
    protocol_roles = {field.field_id for field in plugin.fields}
    extensions = tuple(
        field for field in endpoint.fields if field.role not in protocol_roles
    )
    return ProcessorMemoryBinding(
        endpoint.endpoint_id,
        endpoint.function,
        endpoint.protocol,
        endpoint.fields,
        extensions,
    )


def _packed_input_coverage(
    endpoints: Sequence[EndpointCapability],
) -> tuple[PackedInputContainer, ...]:
    member_fields: dict[str, list[tuple[str, EndpointFieldFact]]] = {}
    whole_ports: set[str] = set()
    for endpoint in endpoints:
        for field in endpoint.fields:
            if field.direction != "input":
                continue
            if field.member_path:
                if field.source is None or not field.evidence:
                    raise ProcessorBoundaryError(
                        f"source-evidence:{endpoint.endpoint_id}:{field.role}"
                    )
                member_fields.setdefault(field.port, []).append(
                    (endpoint.endpoint_id, field)
                )
            else:
                whole_ports.add(field.port)
    mixed = sorted(whole_ports & member_fields.keys())
    if mixed:
        raise ProcessorBoundaryError(f"mixed-packed-input:{mixed[0]}")

    result: list[PackedInputContainer] = []
    for port, owned_fields in sorted(member_fields.items()):
        owners = {endpoint_id for endpoint_id, _ in owned_fields}
        if len(owners) != 1:
            raise ProcessorBoundaryError(f"split-packed-input:{port}")
        endpoint_id = next(iter(owners))
        fields = [field for _, field in owned_fields]
        widths = {field.container_width for field in fields}
        if len(widths) != 1 or None in widths:
            raise ProcessorBoundaryError(f"inconsistent-packed-container:{port}")
        width = next(iter(widths))
        assert width is not None
        ranges = sorted(
            fields,
            key=lambda field: (field.raw_lo, field.raw_hi, field.member_path),
        )
        cursor = 0
        for field in ranges:
            assert field.raw_lo is not None and field.raw_hi is not None
            if field.raw_lo < cursor:
                raise ProcessorBoundaryError(f"overlapping-packed-input:{port}")
            if field.raw_lo > cursor:
                raise ProcessorBoundaryError(
                    f"incomplete-packed-input:{port}:{cursor}/{width}"
                )
            cursor = field.raw_hi + 1
        if cursor != width:
            raise ProcessorBoundaryError(
                f"incomplete-packed-input:{port}:{cursor}/{width}"
            )
        result.append(PackedInputContainer(endpoint_id, port, width, cursor))
    return tuple(result)


def _request_classification(
    memories: tuple[ProcessorMemoryBinding, ...],
) -> RequestClassification:
    functions = {memory.function for memory in memories}
    if functions and functions <= {
        "instruction_memory_master", "data_memory_master"
    } and len(memories) <= 2:
        if any(
            field.role == "instruction_identity"
            for memory in memories for field in memory.fields
        ):
            raise ProcessorBoundaryError("classification-with-split-memory")
        return RequestClassification("split_function", None, None, None, 1, 0)
    if len(memories) != 1 or functions not in ({"memory_master"}, {"processor_memory_master"}):
        raise ProcessorBoundaryError("ambiguous-memory")
    memory = memories[0]
    identity = [
        field for field in memory.fields if field.role == "instruction_identity"
    ]
    if not identity:
        raise ProcessorBoundaryError("missing-instruction-identity")
    if len(identity) != 1:
        raise ProcessorBoundaryError("duplicate-instruction-identity")
    field = identity[0]
    if field.direction != "output":
        raise ProcessorBoundaryError("instruction-identity-direction")
    if field.width != 1:
        raise ProcessorBoundaryError("instruction-identity-width")
    return RequestClassification(
        "explicit_signal", memory.endpoint_id, field.role, field, 1, 0
    )


def build_processor_boundary(
    endpoints: Sequence[EndpointCapability], *, protocol_catalog: ProtocolCatalog
) -> ProcessorBoundary:
    """Build a generic processor boundary from source-backed semantic facts."""
    clock = _one_control(endpoints, "clock", "clock")
    reset = _one_control(endpoints, "reset", "reset")
    memory_endpoints = [
        endpoint for endpoint in endpoints if endpoint.function in _MEMORY_FUNCTIONS
    ]
    if not memory_endpoints:
        raise ProcessorBoundaryError("memory")
    functions = [endpoint.function for endpoint in memory_endpoints]
    unified_functions = {"memory_master", "processor_memory_master"}
    if sum(functions.count(function) for function in unified_functions) > 1:
        raise ProcessorBoundaryError("duplicate-memory")
    if unified_functions.intersection(functions) and len(functions) != 1:
        raise ProcessorBoundaryError("ambiguous-memory")
    for function in ("instruction_memory_master", "data_memory_master"):
        if functions.count(function) > 1:
            raise ProcessorBoundaryError(f"duplicate-{function}")
    for endpoint in memory_endpoints:
        if endpoint.function == "memory_master":
            continue
        if endpoint.clock != clock.fields[0].port:
            raise ProcessorBoundaryError(f"memory-clock:{endpoint.endpoint_id}")
        if endpoint.reset != reset.fields[0].port:
            raise ProcessorBoundaryError(f"memory-reset:{endpoint.endpoint_id}")
    memories = tuple(sorted(
        (_validate_memory(endpoint, protocol_catalog) for endpoint in memory_endpoints),
        key=lambda item: (item.function, item.endpoint_id),
    ))
    classification = _request_classification(memories)

    controls: list[ProcessorControlBinding] = []
    for function in sorted(_OPTIONAL_CONTROL_FUNCTIONS):
        selected = [endpoint for endpoint in endpoints if endpoint.function == function]
        if len(selected) > 1:
            raise ProcessorBoundaryError(f"duplicate-{function}")
        if selected:
            endpoint = selected[0]
            _source_backed(endpoint)
            if endpoint.protocol is not None or endpoint.side is not None:
                raise ProcessorBoundaryError(
                    f"control-protocol:{endpoint.endpoint_id}"
                )
            allowed_roles = _CONTROL_ROLES[function]
            if not endpoint.fields:
                raise ProcessorBoundaryError(f"control-field:{endpoint.endpoint_id}")
            for field in endpoint.fields:
                if field.role not in allowed_roles:
                    raise ProcessorBoundaryError(
                        f"control-role:{endpoint.endpoint_id}:{field.role}"
                    )
                if field.direction != "input":
                    raise ProcessorBoundaryError(
                        f"control-direction:{endpoint.endpoint_id}:{field.role}"
                    )
                if field.role in {
                    "software_interrupt", "timer_interrupt",
                    "non_maskable_interrupt", "request",
                } and field.width != 1:
                    raise ProcessorBoundaryError(
                        f"control-width:{endpoint.endpoint_id}:{field.role}"
                    )
                if field.role == "boot_address" and field.width not in {32, 64}:
                    raise ProcessorBoundaryError(
                        f"control-width:{endpoint.endpoint_id}:{field.role}"
                    )
                if field.role == "hart_id" and field.width not in {32, 64}:
                    raise ProcessorBoundaryError(
                        f"control-width:{endpoint.endpoint_id}:{field.role}"
                    )
                if field.role in {"external_interrupt", "fast_interrupt"} and field.width > 256:
                    raise ProcessorBoundaryError(
                        f"control-width:{endpoint.endpoint_id}:{field.role}"
                    )
            controls.append(ProcessorControlBinding(
                endpoint.endpoint_id, function, endpoint.fields
            ))

    return ProcessorBoundary(
        clock,
        reset,
        memories,
        tuple(controls),
        _packed_input_coverage(endpoints),
        classification,
    )


def _field_document(field: EndpointFieldFact) -> dict[str, object]:
    value: dict[str, object] = {
        "role": field.role,
        "port": field.port,
        "direction": field.direction,
        "width": field.width,
        "signed": field.signed,
    }
    if field.member_path:
        value.update(
            member_path=list(field.member_path),
            raw_lo=field.raw_lo,
            raw_hi=field.raw_hi,
            container_width=field.container_width,
        )
    return value


def processor_boundary_document(boundary: ProcessorBoundary) -> dict[str, object]:
    """Return the deterministic, path-free boundary record used by later IR."""
    def control(value: ProcessorControlBinding) -> dict[str, object]:
        return {
            "endpoint_id": value.endpoint_id,
            "function": value.function,
            "fields": [_field_document(field) for field in value.fields],
        }

    return {
        "schema_version": "processor_boundary.v1",
        "clock": control(boundary.clock),
        "reset": control(boundary.reset),
        "memories": [
            {
                "endpoint_id": memory.endpoint_id,
                "function": memory.function,
                "protocol": list(memory.protocol),
                "fields": [_field_document(field) for field in memory.fields],
                "extension_fields": [
                    {
                        **_field_document(field),
                        "adapter_status": "requires-explicit-policy",
                    }
                    for field in memory.extension_fields
                ],
            }
            for memory in boundary.memories
        ],
        "controls": [control(value) for value in boundary.controls],
        "packed_input_containers": [
            {
                "endpoint_id": item.endpoint_id,
                "port": item.port,
                "width": item.width,
                "covered_bits": item.covered_bits,
            }
            for item in boundary.packed_input_containers
        ],
        "classification": {
            "mode": boundary.classification.mode,
            "endpoint_id": boundary.classification.endpoint_id,
            "field_role": boundary.classification.field_role,
            "instruction_value": boundary.classification.instruction_value,
            "data_value": boundary.classification.data_value,
            **({"field": _field_document(boundary.classification.field)}
               if boundary.classification.field is not None else {}),
        } if boundary.classification is not None else None,
    }
