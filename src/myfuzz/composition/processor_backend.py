"""Deterministic routing plans for processor-memory-beat backends."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from myfuzz.contracts import content_hash

from .processor_execution import ProcessorExecutionPlan, processor_execution_document


class ProcessorBackendError(ValueError):
    """Raised when processor execution routes cannot share one backend."""


@dataclass(frozen=True, slots=True)
class ProcessorBackendPlan:
    execution_hash: str
    initiators: tuple[Mapping[str, object], ...]
    regions: tuple[Mapping[str, object], ...]
    routing: Mapping[str, object]
    recovery: Mapping[str, object]
    rtl_sources: tuple[str, ...]
    backend_hash: str


_ARBITER_MODULE = "processor_memory_arbiter"
_ARBITER_SOURCE = "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv"
_SPLIT_FUNCTIONS = ("data_memory_master", "instruction_memory_master")
_SINGLE_FUNCTIONS = frozenset(("memory_master", "processor_memory_master"))


def _plain_execution(execution: ProcessorExecutionPlan | Mapping[str, object]) -> Mapping[str, object]:
    if isinstance(execution, ProcessorExecutionPlan):
        return processor_execution_document(execution)
    if not isinstance(execution, Mapping):
        raise ProcessorBackendError("execution:type")
    return execution


def _positive_integer(value: object, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProcessorBackendError(reason)
    return value


def _initiators(document: Mapping[str, object]) -> tuple[tuple[Mapping[str, object], ...], int, int, int]:
    if document.get("schema_version") != "processor_execution.v1":
        raise ProcessorBackendError("execution:schema-version")
    raw_routes = document.get("routes")
    if not isinstance(raw_routes, (tuple, list)) or len(raw_routes) not in (1, 2):
        raise ProcessorBackendError("execution:routes")
    routes: list[tuple[str, int, Mapping[str, object]]] = []
    widths_seen: set[tuple[int, int]] = set()
    waits: set[int] = set()
    for raw in raw_routes:
        if not isinstance(raw, Mapping):
            raise ProcessorBackendError("execution:route")
        function, route_id = raw.get("function"), raw.get("route_id")
        if not isinstance(function, str) or isinstance(route_id, bool) or not isinstance(route_id, int):
            raise ProcessorBackendError("execution:route")
        if raw.get("target_protocol") != ["processor-memory-beat", "1"]:
            raise ProcessorBackendError("backend-contract:protocol")
        contract = raw.get("backend_contract")
        if not isinstance(contract, Mapping) or contract.get("mode") != "single_outstanding_request_response":
            raise ProcessorBackendError("backend-contract:mode")
        if contract.get("protocol") != ["processor-memory-beat", "1"]:
            raise ProcessorBackendError("backend-contract:protocol")
        capabilities = contract.get("capabilities")
        if not isinstance(capabilities, Mapping) or capabilities.get("max_outstanding") != 1:
            raise ProcessorBackendError("backend-contract:outstanding")
        waits.add(_positive_integer(capabilities.get("max_wait_cycles"), "backend-contract:timeout"))
        widths = raw.get("widths")
        if not isinstance(widths, Mapping):
            raise ProcessorBackendError("width-mismatch")
        address_width = _positive_integer(widths.get("address"), "width-mismatch")
        data_width = _positive_integer(widths.get("data"), "width-mismatch")
        if data_width % 8:
            raise ProcessorBackendError("width-mismatch")
        widths_seen.add((address_width, data_width))
        routes.append((function, route_id, raw))
    if len(widths_seen) != 1 or len(waits) != 1:
        raise ProcessorBackendError("width-mismatch")
    functions = tuple(sorted(item[0] for item in routes))
    if len(routes) == 1:
        if functions[0] not in _SINGLE_FUNCTIONS:
            raise ProcessorBackendError("execution:route-shape")
    elif functions != _SPLIT_FUNCTIONS:
        raise ProcessorBackendError("execution:route-shape")

    result: list[Mapping[str, object]] = []
    for index, (function, route_id, raw) in enumerate(sorted(routes, key=lambda item: (item[0], item[1]))):
        parameters = raw.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ProcessorBackendError("execution:parameters")
        read_only = parameters.get("READ_ONLY") == 1
        if function == "instruction_memory_master" and not read_only:
            raise ProcessorBackendError("instruction-write-policy")
        result.append({
            "index": index,
            "route_id": route_id,
            "function": function,
            "access": "read_only" if read_only else "read_write",
            "write_policy": (
                "error_without_backend_request" if read_only else "forward_byte_enable"
            ),
        })
    address_width, data_width = next(iter(widths_seen))
    return tuple(result), address_width, data_width, next(iter(waits))


def _regions(
    raw_regions: Sequence[Mapping[str, object]], address_width: int,
) -> tuple[Mapping[str, object], ...]:
    if isinstance(raw_regions, (str, bytes)) or not isinstance(raw_regions, Sequence):
        raise ProcessorBackendError("address-regions:type")
    limit = 1 << address_width
    regions: list[dict[str, object]] = []
    for index, raw in enumerate(raw_regions):
        if not isinstance(raw, Mapping):
            raise ProcessorBackendError("address-region")
        base, size, end = raw.get("base"), raw.get("size"), raw.get("end")
        if (
            isinstance(base, bool) or not isinstance(base, int) or base < 0
            or isinstance(size, bool) or not isinstance(size, int) or size <= 0
            or isinstance(end, bool) or not isinstance(end, int)
            or end != base + size or end > limit
        ):
            raise ProcessorBackendError("address-region")
        component_id = raw.get("component_id")
        if not isinstance(component_id, (str, int)) or isinstance(component_id, bool):
            raise ProcessorBackendError("address-region")
        region_width = raw.get("address_width", address_width)
        if region_width != address_width:
            raise ProcessorBackendError("width-mismatch")
        region_id = raw.get("region_id", index)
        if isinstance(region_id, bool) or not isinstance(region_id, int):
            raise ProcessorBackendError("address-region")
        regions.append({
            "region_id": region_id,
            "component_id": component_id,
            "base": base,
            "size": size,
            "end": end,
        })
    regions.sort(key=lambda item: (int(item["base"]), str(item["component_id"]), int(item["region_id"])))
    for previous, current in zip(regions, regions[1:]):
        if int(current["base"]) < int(previous["end"]):
            raise ProcessorBackendError(
                f"address-overlap:{previous['component_id']}:{current['component_id']}"
            )
    return tuple(regions)


def _document(plan: ProcessorBackendPlan, *, include_hash: bool) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "processor_backend.v1",
        "execution_hash": plan.execution_hash,
        "protocol": ["processor-memory-beat", "1"],
        "widths": {
            "address": plan.routing["address_width"],
            "data": plan.routing["data_width"],
        },
        "initiators": [dict(item) for item in plan.initiators],
        "routing": dict(plan.routing),
        "address_decode": {
            "regions": [dict(item) for item in plan.regions],
            "unmapped": {"completion": "error", "rdata": 0, "side_effect": False},
        },
        "recovery": dict(plan.recovery),
        "rtl_sources": list(plan.rtl_sources),
    }
    if include_hash:
        document["backend_hash"] = plan.backend_hash
    return document


def build_processor_backend(
    execution: ProcessorExecutionPlan | Mapping[str, object],
    address_regions: Sequence[Mapping[str, object]],
) -> ProcessorBackendPlan:
    """Build a path-free backend plan from Task 9 execution and address contracts."""
    execution_document = _plain_execution(execution)
    initiators, address_width, data_width, max_wait_cycles = _initiators(execution_document)
    regions = _regions(address_regions, address_width)
    mode = "direct" if len(initiators) == 1 else "round_robin"
    routing: dict[str, object] = {
        "mode": mode,
        "max_outstanding": 1,
        "address_width": address_width,
        "data_width": data_width,
    }
    rtl_sources: tuple[str, ...] = ()
    if mode == "round_robin":
        routing.update({"rtl_module": _ARBITER_MODULE, "fairness": "round_robin"})
        rtl_sources = (_ARBITER_SOURCE,)
    recovery = {
        "max_wait_cycles": max_wait_cycles,
        "completion": "single_error",
        "late_response": "quarantine_and_discard",
        "reset": "abort_without_completion",
    }
    execution_hash = execution_document.get("execution_hash")
    if not isinstance(execution_hash, str):
        raise ProcessorBackendError("execution:hash")
    provisional = ProcessorBackendPlan(
        execution_hash, initiators, regions, routing, recovery, rtl_sources, "",
    )
    return ProcessorBackendPlan(
        execution_hash, initiators, regions, routing, recovery, rtl_sources,
        content_hash(_document(provisional, include_hash=False)),
    )


def processor_backend_document(plan: ProcessorBackendPlan) -> dict[str, object]:
    if not isinstance(plan, ProcessorBackendPlan):
        raise ProcessorBackendError("plan:type")
    return _document(plan, include_hash=True)


__all__ = [
    "ProcessorBackendError",
    "ProcessorBackendPlan",
    "build_processor_backend",
    "processor_backend_document",
]
