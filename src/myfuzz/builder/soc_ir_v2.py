"""Build the canonical SoCIR v2 structural truth from proven planner facts."""

from __future__ import annotations

from typing import Mapping

from .backend_registry import BackendRegistry, builtin_backend_registry
from .contracts import SoCIRV2, seal_contract
from .discovery import DiscoveryResult
from .input_model import AddressAliasPolicy, InputValidationError, SystemSpec
from .planner import SystemPlan
from .profiles import InterfaceRole


def build_soc_ir_v2(
    spec: SystemSpec,
    discovery: DiscoveryResult,
    plan: SystemPlan,
    *,
    source_digests: Mapping[str, str],
    analysis_manifest_digest: str,
    backend_registry: BackendRegistry | None = None,
) -> SoCIRV2:
    if not plan.valid:
        raise InputValidationError("cannot build SoCIR v2 from invalid plan: " + "; ".join(plan.validation_issues))
    if len(spec.clock_domains) > 1:
        raise InputValidationError("SoCIR v2 first-stage capability supports exactly one clock domain")
    initiators = [interface for interface in plan.interfaces if interface.role is InterfaceRole.INITIATOR]
    if len(initiators) != 1:
        raise InputValidationError(f"SoCIR v2 first-stage capability requires one CPU master; found {len(initiators)}")
    _sha256(analysis_manifest_digest, "analysis_manifest_digest")
    discovered = {module.name: module for module in discovery.modules}
    declared = {module.name: module for module in spec.modules}
    missing = sorted(set(declared) - set(discovered))
    if missing:
        raise InputValidationError(
            "SoCIR v2 declared module(s) are absent from discovery: " + ", ".join(missing)
        )
    for name in declared:
        if name not in source_digests:
            raise InputValidationError(f"{name}: missing proven source digest")
        _sha256(source_digests[name], f"source_digests.{name}")

    logical_modules = tuple({
        "logical_id": module.name,
        "rtl_module": module.rtl_module or module.name,
        "coverage_component_id": module.component_id,
        "kind": module.kind.value,
        "source_set": module.source_set,
        "source_digest": source_digests[module.name],
        "parameters": dict(sorted(module.parameters.items())),
        "provenance": {"source": "user_manifest"},
    } for module in spec.modules)
    instances = tuple({
        "instance_id": name,
        "logical_module_id": name,
        "clock_domain": declared[name].clock_domain,
        "reset_domain": declared[name].reset_domain,
        "provenance": {"source": "elaborated_rtl", "source_file": discovered[name].source_file},
    } for name in sorted(declared))
    endpoints = tuple({
        "endpoint_id": f"{binding.module}.{binding.name}",
        "instance_id": binding.module,
        "protocol": binding.protocol,
        "role": binding.role.value,
        "profile": binding.profile,
        "signals": tuple({
            "semantic": port.semantic, "physical_port": port.port,
            "direction": port.direction.value, "width": port.width,
        } for port in binding.ports),
        "provenance": {"source": "profile_binding"},
    } for binding in plan.interfaces)
    port_bindings = tuple({
        "instance_id": binding.module, "physical_port": binding.port,
        "endpoint_id": None if binding.interface is None else f"{binding.module}.{binding.interface}",
        "semantic": binding.semantic, "direction": binding.direction.value, "width": binding.width,
        "evidence": binding.source, "reason": binding.reason,
        "confidence": binding.confidence,
    } for binding in plan.port_bindings)
    protocol_edges = tuple({
        "order": edge.order, "source": edge.source.label(), "target": edge.target.label(),
        "width": edge.width, "kind": edge.kind.value,
        "reason": edge.reason, "evidence": edge.evidence_source,
    } for edge in plan.graph.connections)
    address_views = tuple(
        _address_view(window, plan, declared[window.module])
        for window in plan.address_plan.windows
    )
    clock_domains = tuple({
        "domain_id": domain.name, "source": domain.source, "frequency_hz": domain.frequency_hz,
        "provenance": {"source": "user_manifest"},
    } for domain in spec.clock_domains)
    reset_domains = tuple({
        "domain_id": domain.name, "source": domain.source, "active_low": domain.active_low,
        "synchronous": domain.synchronous,
        "members": tuple(sorted(module.name for module in spec.modules if module.reset_domain == domain.name)),
        "provenance": {"source": "user_manifest"},
    } for domain in spec.reset_domains)
    external_boundaries = tuple({
        "boundary_id": f"{decision.module}.{decision.port}", "instance_id": decision.module,
        "port": decision.port, "direction": decision.direction.value, "width": decision.width,
        "action": decision.action.value, "reason": decision.reason,
        "provenance": {"source": decision.evidence_source},
    } for decision in plan.unknown_ports if decision.action.value in {
        "external_input", "rfuzz_drive", "constrained_random", "observe",
    })
    unknown_decisions = tuple({
        "instance_id": decision.module, "port": decision.port,
        "direction": decision.direction.value, "width": decision.width,
        "action": decision.action.value, "status": decision.status.value,
        "result": decision.resulting_action, "reason": decision.reason,
        "evidence": decision.evidence_source,
    } for decision in plan.unknown_ports)
    services = tuple({"node_id": name, "kind": "generated_service", "provenance": {"source": "planner"}}
                     for name in plan.virtual_modules)
    interrupt_edges = _interrupt_edges(plan)
    backend_evidence = _select_backends(plan, backend_registry or builtin_backend_registry())
    value = SoCIRV2(
        name=plan.name,
        logical_modules=logical_modules,
        instances=instances,
        endpoints=endpoints,
        port_bindings=port_bindings,
        protocol_edges=protocol_edges,
        address_views=address_views,
        clock_domains=clock_domains,
        reset_domains=reset_domains,
        interrupt_edges=interrupt_edges,
        external_boundaries=external_boundaries,
        service_nodes=services,
        adapters=(),
        unknown_port_decisions=unknown_decisions,
        provenance={
            "analysis_manifest_digest": analysis_manifest_digest,
            "planner": "myfuzz.protocol-driven/v2",
            "backends": backend_evidence,
        },
    )
    return seal_contract(value)  # type: ignore[return-value]


def _interrupt_edges(plan: SystemPlan) -> tuple[Mapping[str, object], ...]:
    sources = sorted(
        (binding for binding in plan.port_bindings if binding.semantic == "interrupt_source"),
        key=lambda item: (item.module, item.port),
    )
    sinks = sorted(
        (binding for binding in plan.port_bindings if binding.semantic == "interrupt_sink"),
        key=lambda item: (item.module, item.port),
    )
    for source in sources:
        if source.direction.value != "output":
            raise InputValidationError(
                f"{source.module}.{source.port}: interrupt_source must be an output"
            )
    for sink in sinks:
        if sink.direction.value != "input":
            raise InputValidationError(f"{sink.module}.{sink.port}: interrupt_sink must be an input")
    if len(sinks) > 1:
        labels = ", ".join(f"{item.module}.{item.port}" for item in sinks)
        raise InputValidationError(f"first-stage SoC supports one interrupt_sink; found {labels}")
    if sources and not sinks:
        raise InputValidationError("interrupt_source port(s) require one interrupt_sink")
    if not sinks:
        return ()
    sink = sinks[0]
    if sink.width != 32:
        raise InputValidationError(
            f"{sink.module}.{sink.port}: first-stage interrupt_sink width must be 32, got {sink.width}"
        )
    total_width = sum(source.width for source in sources)
    if total_width > 32:
        raise InputValidationError(
            f"interrupt_source aggregate width {total_width} exceeds the 32-bit mapper"
        )
    provenance = {
        "source": "authoritative_port_annotation",
        "reason": "interrupt_source/interrupt_sink semantic binding",
    }
    edges: list[Mapping[str, object]] = []
    offset = 0
    for source in sources:
        edges.append({
            "edge_id": f"irq:{offset}:{source.module}.{source.port}",
            "source": {
                "kind": "internal", "instance_id": source.module,
                "port": source.port, "width": source.width,
            },
            "sink": {"instance_id": sink.module, "port": sink.port, "width": sink.width},
            "mapper_offset": offset, "trigger": "level_high", "ack": None,
            "provenance": provenance,
        })
        offset += source.width
    edges.append({
        "edge_id": "irq:external:harness",
        "source": {
            "kind": "external", "boundary_id": "__harness.external_irq_sources", "width": 32,
        },
        "sink": {"instance_id": sink.module, "port": sink.port, "width": sink.width},
        "mapper_offset": 0, "trigger": "level_high", "ack": None,
        "provenance": {"source": "generated_harness", "reason": "bit-level IRQ injection"},
    })
    return tuple(edges)


def _address_view(window, plan: SystemPlan, module) -> Mapping[str, object]:
    local_widths = [
        binding.width for binding in plan.port_bindings
        if binding.module == window.module and _is_address_semantic(binding.semantic)
    ]
    if not local_widths:
        raise InputValidationError(f"{window.module}: addressed target has no typed address endpoint")
    if len(set(local_widths)) != 1:
        raise InputValidationError(f"{window.module}: local address width is ambiguous")
    local_width = local_widths[0]
    alias_policy = module.address.alias_policy if module.address is not None else AddressAliasPolicy.REJECT
    if window.size > 1 << local_width and alias_policy is AddressAliasPolicy.REJECT:
        raise InputValidationError(
            f"{window.module}: window size {window.size:#x} aliases {local_width}-bit local address space"
        )
    transform = "local = global - global_base"
    if alias_policy is AddressAliasPolicy.ALLOW_MIRROR:
        transform = f"local = (global - global_base) mod 2^{local_width}"
    return {
        "instance_id": window.module, "global_base": window.base, "size": window.size,
        "byte_address_unit": 1, "local_address_width": local_width,
        "transform": transform, "preserved_offset_bits": 0,
        "alignment": window.size if window.size & (window.size - 1) == 0 else 1,
        "alias_policy": alias_policy.value, "provenance": {
            "source": window.source, "reason": window.reason, "confidence": window.confidence,
        },
    }


def _is_address_semantic(semantic: str) -> bool:
    return semantic.rsplit(".", 1)[-1] in {"address", "awaddr", "araddr", "paddr"}


def _select_backends(plan: SystemPlan, registry: BackendRegistry) -> tuple[Mapping[str, object], ...]:
    protocols = {interface.protocol for interface in plan.interfaces}
    selected = []
    if "axi_lite" in protocols:
        selected.append(registry.select(protocols=("axi_lite",), required_capabilities=("decode",)))
    for apb in ("apb3", "apb4"):
        if apb in protocols:
            selected.append(registry.select(protocols=(apb,), required_capabilities=("decode",)))
            if "axi_lite" not in protocols:
                raise InputValidationError(f"{apb}: first-stage SoC requires an AXI-Lite CPU-side bridge")
            selected.append(registry.select(protocols=("axi_lite", apb), required_capabilities=("bridge",)))
    known = {"axi_lite", "apb3", "apb4", "simple_bus"}
    unsupported = protocols - known
    if unsupported:
        raise InputValidationError("unsupported protocol(s): " + ", ".join(sorted(unsupported)))
    return tuple({"backend_id": item.backend_id, "version": item.version,
                  "protocols": item.protocols, "capabilities": item.capabilities}
                 for item in selected)


def _sha256(value: str, path: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
